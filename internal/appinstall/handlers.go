package appinstall

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// Handlers serves the catalog and the installations.
type Handlers struct {
	DB *sql.DB
}

// installBudget bounds one detached installation end to end.
const installBudget = 30 * time.Minute

// domainOf loads what an installation needs about its target domain.
func (h *Handlers) domainOf(ctx context.Context, id int64) (Request, bool) {
	var request Request
	var certPath string
	err := h.DB.QueryRowContext(ctx,
		`SELECT id, domain_name, system_user, COALESCE(web_root,''), COALESCE(cert_path,'')
		   FROM domains WHERE id=?`, id).
		Scan(&request.DomainID, &request.DomainName, &request.SystemUser, &request.WebRoot, &certPath)
	if err != nil {
		return Request{}, false
	}
	if request.WebRoot == "" {
		request.WebRoot = "/home/" + request.SystemUser + "/public_html"
	}
	request.SSL = certPath != ""
	return request, strings.HasPrefix(request.SystemUser, "c_")
}

// CatalogForDomain — GET /domains/{id}/app-installer (CustomerScope).
//
// A customer sees only what they can actually install: an entry with no
// checksum is not offered, because offering it would produce a refusal at the
// moment they press the button rather than an absence they never notice.
func (h *Handlers) CatalogForDomain(w http.ResponseWriter, r *http.Request) {
	entries, err := Catalog(r.Context(), h.DB)
	if err != nil {
		log.Printf("app catalog: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	out := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if !entry.Enabled || !sha256Pattern.MatchString(entry.SHA256) {
			continue
		}
		// The URL and the digest are operational detail, not something a
		// customer needs, and the URL names where the panel fetches from.
		entry.DownloadURL, entry.SHA256 = "", ""
		out = append(out, entry)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

const installColumns = `id, domain_id, code, name, version, subdirectory, site_url,
	db_name, db_user, state, last_error, DATE_FORMAT(created_at,'%Y-%m-%d %H:%i')`

type installRow struct {
	Install
	State     string `json:"state"`
	LastError string `json:"last_error"`
}

// Installs — GET /domains/{id}/app-installer/installs (CustomerScope).
func (h *Handlers) Installs(w http.ResponseWriter, r *http.Request) {
	domainID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || domainID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid domain")
		return
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT `+installColumns+` FROM app_installs WHERE domain_id=? ORDER BY id DESC`, domainID)
	if err != nil {
		log.Printf("app installs: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer func() { _ = rows.Close() }()

	out := make([]installRow, 0)
	for rows.Next() {
		var row installRow
		if err := rows.Scan(&row.ID, &row.DomainID, &row.Code, &row.Name, &row.Version,
			&row.Subdirectory, &row.SiteURL, &row.DBName, &row.DBUser,
			&row.State, &row.LastError, &row.CreatedAt); err != nil {
			log.Printf("app installs scan: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
			return
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		log.Printf("app installs rows: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// Create — POST /domains/{id}/app-installer/installs (CustomerScope).
//
// Begin runs synchronously so a refusal is answered as a refusal, with its
// code. The work then runs DETACHED: a Nextcloud download and unpack takes
// longer than the panel's 300-second request timeout, and the row Begin wrote
// is how the screen learns the outcome.
func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	domainID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || domainID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid domain")
		return
	}
	request, ok := h.domainOf(r.Context(), domainID)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var body struct {
		Code         string `json:"code"`
		Subdirectory string `json:"subdirectory"`
		DBSuffix     string `json:"db_suffix"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	request.Code = strings.TrimSpace(body.Code)
	request.Subdirectory = strings.ToLower(strings.TrimSpace(body.Subdirectory))
	request.DBSuffix = strings.ToLower(strings.TrimSpace(body.DBSuffix))

	id, entry, err := Begin(r.Context(), h.DB, request)
	if err != nil {
		if code := ReasonOf(err); code != "" {
			status := http.StatusBadRequest
			if code == ReasonTargetNotEmpty || code == ReasonDatabaseExists {
				status = http.StatusConflict
			}
			httpx.WriteError(w, status, code)
			return
		}
		log.Printf("app install start: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the installation could not be started")
		return
	}

	// #nosec G118 -- detaching from the request context is the point: the work outlives the request by design and the row Begin wrote is what carries the outcome.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), installBudget)
		defer cancel()
		runErr := Run(ctx, h.DB, entry, request)
		if runErr != nil {
			log.Printf("app install %d (%s): %v", id, entry.Code, runErr)
		}
		Finish(h.DB, id, runErr)
	}()

	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"id": id, "state": "installing", "site_url": siteURLFor(request),
	})
}

// Forget — DELETE /domains/{id}/app-installer/installs/{aid} (CustomerScope).
//
// It removes the RECORD and nothing else. Deleting the files would be deleting
// a live site, and deleting the database would be deleting its content; neither
// belongs behind a row in a list of what was installed. The file manager and the
// database screen already do both, deliberately and one at a time.
func (h *Handlers) Forget(w http.ResponseWriter, r *http.Request) {
	domainID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || domainID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid domain")
		return
	}
	installID, err := strconv.ParseInt(chi.URLParam(r, "aid"), 10, 64)
	if err != nil || installID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid installation")
		return
	}
	// The domain is part of the WHERE clause, so a neighbour's installation id
	// is refused rather than read and then checked.
	result, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM app_installs WHERE id=? AND domain_id=?`, installID, domainID)
	if err != nil {
		log.Printf("app install forget: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database write failed")
		return
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		httpx.WriteError(w, http.StatusNotFound, "installation not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// AdminCatalog — GET /admin/app-catalog (AdminOnly).
func (h *Handlers) AdminCatalog(w http.ResponseWriter, r *http.Request) {
	entries, err := Catalog(r.Context(), h.DB)
	if err != nil {
		log.Printf("app catalog: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, entries)
}

// AdminSave — PUT /admin/app-catalog (AdminOnly).
func (h *Handlers) AdminSave(w http.ResponseWriter, r *http.Request) {
	var entry Entry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	entry.Code = strings.ToLower(strings.TrimSpace(entry.Code))
	entry.SHA256 = strings.ToLower(strings.TrimSpace(entry.SHA256))
	entry.DownloadURL = strings.TrimSpace(entry.DownloadURL)
	entry.ArchiveName = strings.TrimSpace(entry.ArchiveName)

	// The refusal names the FIELD, because an operator entering a catalog row
	// by hand needs to know which of eight values the panel would not take.
	if field, ok := ValidEntry(entry); !ok {
		httpx.WriteError(w, http.StatusBadRequest, "app_catalog_invalid_"+field)
		return
	}
	if err := SaveEntry(r.Context(), h.DB, entry); err != nil {
		log.Printf("app catalog save: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the catalog could not be written")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, entry)
}

// AdminDelete — DELETE /admin/app-catalog/{code} (AdminOnly).
func (h *Handlers) AdminDelete(w http.ResponseWriter, r *http.Request) {
	code := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "code")))
	if !codePattern.MatchString(code) {
		httpx.WriteError(w, http.StatusBadRequest, ReasonUnknownApp)
		return
	}
	if err := DeleteEntry(r.Context(), h.DB, code); err != nil {
		log.Printf("app catalog delete: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the catalog could not be written")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// HealRunningInstalls closes at startup any installation left mid-flight.
//
// The work runs in a goroutine, so a panel that was killed leaves a row saying
// "installing" that nothing will ever finish, and the screen would show a
// spinner for good.
func HealRunningInstalls(db *sql.DB) {
	if _, err := db.Exec(
		`UPDATE app_installs
		    SET state='failed', last_error='the panel restarted while this installation was running',
		        finished_at=NOW()
		  WHERE state='installing'`); err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Printf("app installs: could not clear a stale installation state: %v", err)
	}
}
