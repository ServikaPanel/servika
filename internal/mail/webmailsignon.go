package mail

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"

	"servika/internal/config"
	"servika/internal/httpx"
	"servika/internal/logx"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

// Opening webmail from the panel without asking for the password again.
//
// This follows the phpMyAdmin signon path exactly: the panel mints a token that
// is single-use and short-lived, the token travels to the web application in a
// POST body so it never reaches browser history or a proxy log, and the
// application exchanges it over the loopback for the credential it needs. The
// credential here is Dovecot's master user, because the panel keeps only a hash
// of the mailbox password and cannot replay it.

const webmailTokenValiditySeconds = 120

// WebmailToken mints a signon token for one mailbox.
// POST /domains/{id}/mail/{mid}/webmail-token
func (h *Handlers) WebmailToken(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	// The route carries the domain in {id}, so CustomerScope has already tied it
	// to the caller. The suspension check is repeated here because a suspended
	// customer must not be able to mint a credential that outlives the block.
	if !middleware.EnforceCustomerNotSuspended(w, r, id) {
		return
	}
	if MasterPassword() == "" {
		httpx.WriteError(w, http.StatusServiceUnavailable, "webmail signon is not configured on this server")
		return
	}

	mailboxID, _ := strconv.ParseInt(chi.URLParam(r, "mid"), 10, 64)
	var email, status string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT email, status FROM mailboxes WHERE id=? AND domain_id=?`, mailboxID, id).
		Scan(&email, &status)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "mailbox not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		return
	}
	if status != "active" {
		httpx.WriteError(w, http.StatusForbidden, "that mailbox is not active")
		return
	}

	token, err := randomToken()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to create a secure signon token")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO webmail_tokens(token, domain_id, mailbox_id, email, expires_at)
		 VALUES(?,?,?,?, DATE_ADD(NOW(), INTERVAL ? SECOND))`,
		token, id, mailboxID, email, webmailTokenValiditySeconds); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		return
	}
	// Expiry is evaluated with the MySQL clock everywhere, so the cleanup here
	// uses the same clock as the insert above and the redeem below.
	_, _ = h.DB.ExecContext(r.Context(),
		`DELETE FROM webmail_tokens WHERE expires_at < NOW() OR used=1`)

	h.audit(r, "mail.webmail.signon", email, true)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"token":            token,
		"validity_seconds": webmailTokenValiditySeconds,
	})
}

// WebmailRedeem exchanges a token for the credential Roundcube logs in with.
// POST /api/v1/internal/webmail-redeem  (X-Internal-Auth header)
//
// This is reachable without a panel session because Roundcube has none. It is
// protected the same way the phpMyAdmin redeem is: a shared secret readable only
// by root and the web application, plus a token that is consumed once.
func (h *Handlers) WebmailRedeem(w http.ResponseWriter, r *http.Request) {
	if !internalCallerMatches(r) {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	master := MasterPassword()
	if master == "" {
		httpx.WriteError(w, http.StatusServiceUnavailable, "webmail signon is not configured on this server")
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		httpx.WriteError(w, http.StatusBadRequest, "token is required")
		return
	}

	email, status, message := h.redeemWebmailToken(r.Context(), req.Token)
	if status != 0 {
		httpx.WriteError(w, status, message)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"username": MasterLogin(email),
		"password": master,
	})
}

// internalCallerMatches reports whether the request carries the shared secret
// Roundcube presents.
func internalCallerMatches(r *http.Request) bool {
	expected := webmailInternalToken()
	provided := r.Header.Get("X-Internal-Auth")
	return expected != "" && provided != "" &&
		subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// redeemWebmailToken checks the token and consumes it. It returns the mailbox the
// token was minted for, or the status and message that refuse it.
func (h *Handlers) redeemWebmailToken(ctx context.Context, token string) (string, int, string) {
	var email string
	var used, expired int
	err := h.DB.QueryRowContext(ctx,
		`SELECT email, used, (expires_at < NOW()) FROM webmail_tokens WHERE token=?`, token).
		Scan(&email, &used, &expired)
	if errors.Is(err, sql.ErrNoRows) {
		return "", http.StatusNotFound, "token not found"
	}
	if err != nil {
		return "", http.StatusInternalServerError, "database operation failed"
	}
	if used == 1 || expired == 1 {
		return "", http.StatusGone, "token is no longer valid"
	}

	// Consuming and checking in one statement is what makes the token single-use:
	// two requests arriving together cannot both find it unused.
	result, err := h.DB.ExecContext(ctx,
		`UPDATE webmail_tokens SET used=1 WHERE token=? AND used=0 AND expires_at >= NOW()`, token)
	if err != nil {
		return "", http.StatusInternalServerError, "database operation failed"
	}
	if consumed, err := result.RowsAffected(); err != nil || consumed != 1 {
		return "", http.StatusGone, "token is no longer valid"
	}
	return email, 0, ""
}

// webmailInternalToken reads the shared secret Roundcube presents. The panel and
// Roundcube are the only readers; it is the same file the phpMyAdmin signon uses,
// because both are the same trust relationship: a local web application asking
// the panel to vouch for a session it started.
func webmailInternalToken() string {
	raw, err := os.ReadFile(config.PMATokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func randomToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// pruneWebmailTokens is called from the delivery-log timer so an unopened token
// does not sit in the table until the next signon happens to clean it up.
func pruneWebmailTokens(ctx context.Context, db *sql.DB) {
	if _, err := db.ExecContext(ctx,
		`DELETE FROM webmail_tokens WHERE expires_at < NOW() OR used=1`); err != nil {
		logx.Errorf("webmail token prune: %v", err)
	}
}
