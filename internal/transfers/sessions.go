package transfers

// Migration session persistence: a half-configured migration survives a page
// reload without the operator re-entering the source server details, the
// credentials, or re-running discovery.
//
// The flow is: MigrationDiscover saves a session (encrypted credentials plus the
// discovery result, a 2-hour TTL); the page lists and restores it; MigrationStart
// decrypts the stored credentials SERVER-SIDE when the operator did not re-type
// them. The password NEVER travels back to the browser.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"servika/internal/httpx"
	"servika/internal/secret"
)

// sessionTTL is how long a saved migration session stays resumable.
const sessionTTL = 2 * time.Hour

// saveSession persists the source and the discovery result so a reload resumes.
// It is best-effort: a failure returns 0 and the caller still answers discovery.
// Only ONE fresh session is kept per source, so an earlier one for the same
// host and user is dropped first. Returns the session id, or 0 on any error.
func (h *Handlers) saveSession(source *RemoteSource, discoveryJSON []byte, startedBy string) int64 {
	_, _ = h.DB.Exec(`DELETE FROM migration_sessions WHERE source_host=? AND source_user=?`,
		source.Host, source.User)

	encPass, err := sealForHost(source.Password, source.Host)
	if err != nil {
		log.Printf("migration session: could not seal the password: %v", err)
		return 0
	}
	encKey, err := sealForHost(source.Key, source.Host)
	if err != nil {
		log.Printf("migration session: could not seal the key: %v", err)
		return 0
	}
	res, err := h.DB.Exec(
		`INSERT INTO migration_sessions
		   (source_type, source_host, source_port, source_user, source_password, source_key,
		    discovery_json, started_by, last_used, expires_at)
		 VALUES (?,?,?,?,?,?,?,?, NOW(), NOW() + INTERVAL ? SECOND)`,
		source.Type, source.Host, source.Port, source.User, encPass, encKey,
		string(discoveryJSON), nullIfEmpty(startedBy), int(sessionTTL.Seconds()))
	if err != nil {
		log.Printf("migration session: could not save: %v", err)
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

// sealForHost encrypts a secret bound to the source host, or returns NULL when
// the secret is empty so the stored column stays NULL (credentials_stored=false).
func sealForHost(value, host string) (sql.NullString, error) {
	if value == "" {
		return sql.NullString{}, nil
	}
	sealed, err := secret.EncryptWith(value, host)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: sealed, Valid: true}, nil
}

func nullIfEmpty(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// sessionSummary is one saved session as the list sees it. It carries NO secret:
// only whether credentials are stored, never the password or key.
type sessionSummary struct {
	ID                int64  `json:"id"`
	Type              string `json:"type"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	User              string `json:"user"`
	CredentialsStored bool   `json:"credentials_stored"`
	LastUsed          string `json:"last_used"`
}

// SessionList — GET /admin/migrations/sessions (AdminOnly). Non-expired sessions,
// no secrets returned.
func (h *Handlers) SessionList(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, source_type, source_host, source_port, source_user,
		        (source_password IS NOT NULL OR source_key IS NOT NULL),
		        COALESCE(DATE_FORMAT(last_used,'%Y-%m-%d %H:%i:%s'),'')
		   FROM migration_sessions
		  WHERE expires_at > NOW()
		  ORDER BY last_used DESC LIMIT 25`)
	if err != nil {
		log.Printf("migration sessions list: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the sessions could not be read")
		return
	}
	defer func() { _ = rows.Close() }()
	out := make([]sessionSummary, 0)
	for rows.Next() {
		var s sessionSummary
		if err := rows.Scan(&s.ID, &s.Type, &s.Host, &s.Port, &s.User,
			&s.CredentialsStored, &s.LastUsed); err != nil {
			log.Printf("migration sessions scan: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "the sessions could not be read")
			return
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		log.Printf("migration sessions rows: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the sessions could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// SessionGet — GET /admin/migrations/sessions/{id} (AdminOnly). Restores the
// form and the discovery result. It returns NO secret: only credentials_stored,
// so the page knows the operator can start without re-typing the password.
func (h *Handlers) SessionGet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid session")
		return
	}
	var (
		sType, sHost, sUser string
		sPort               int
		discovery           sql.NullString
		hasPass, hasKey     bool
	)
	err = h.DB.QueryRowContext(r.Context(),
		`SELECT source_type, source_host, source_port, source_user, discovery_json,
		        source_password IS NOT NULL, source_key IS NOT NULL
		   FROM migration_sessions WHERE id=? AND expires_at > NOW()`, id).
		Scan(&sType, &sHost, &sPort, &sUser, &discovery, &hasPass, &hasKey)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "no such session")
		return
	}
	if err != nil {
		log.Printf("migration session get: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the session could not be read")
		return
	}
	_, _ = h.DB.ExecContext(r.Context(), `UPDATE migration_sessions SET last_used=NOW() WHERE id=?`, id)

	accounts := json.RawMessage("[]")
	if discovery.Valid && discovery.String != "" {
		accounts = json.RawMessage(discovery.String)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id": id, "type": sType, "host": sHost, "port": sPort, "user": sUser,
		"credentials_stored": hasPass || hasKey,
		"accounts":           accounts,
	})
}

// SessionDelete — DELETE /admin/migrations/sessions/{id} (AdminOnly).
func (h *Handlers) SessionDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid session")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM migration_sessions WHERE id=?`, id); err != nil {
		log.Printf("migration session delete: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the session could not be deleted")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// loadSessionCredentials decrypts a session's stored password and key, bound to
// the given host. It is used at start when the operator did not re-type them.
// The host must match the session's, or the AES-GCM AAD fails and nothing is
// returned, which is the point: a blob cannot be used against another host.
func (h *Handlers) loadSessionCredentials(ctx context.Context, sessionID int64, host string) (password, key string, err error) {
	var pass, keyVal sql.NullString
	err = h.DB.QueryRowContext(ctx,
		`SELECT source_password, source_key FROM migration_sessions
		  WHERE id=? AND source_host=? AND expires_at > NOW()`, sessionID, host).
		Scan(&pass, &keyVal)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrSessionNotFound
	}
	if err != nil {
		return "", "", err
	}
	if pass.Valid {
		if password, err = secret.DecryptWith(pass.String, host); err != nil {
			return "", "", err
		}
	}
	if keyVal.Valid {
		if key, err = secret.DecryptWith(keyVal.String, host); err != nil {
			return "", "", err
		}
	}
	return password, key, nil
}

// ErrSessionNotFound is what a start gets for a session id that no longer exists,
// has expired, or does not match the host.
var ErrSessionNotFound = errors.New("the migration session was not found or has expired")
