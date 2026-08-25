package antivirus

// Quarantine across every domain the caller may see.
//
// The per-domain surface answers "what is this domain holding". It is the right
// screen for the person who owns one site and the wrong one for the person who
// runs the server: a sweep contains files across every tenant at once, and
// reaching them meant opening each domain in turn to find out whether it was
// holding anything at all.
//
// Nothing here is a new file operation. The row is resolved, and then the SAME
// functions the per-domain handlers call do the work, so the symlink-safe
// reading and writing exists in one place. What this file adds is the
// narrowing, and that narrowing lives in the QUERY: a row-by-row ownership
// check does not work on a list endpoint, because the rows a reseller may not
// see would already have been read and counted, and on the action endpoints it
// would leak a neighbour's row through the difference between 404 and 403.

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"servika/internal/httpx"
	"servika/internal/middleware"
)

// adminMaxRows bounds one page of the server-wide list. A server that has been
// sweeping for months holds more entries than anybody reads in one sitting, and
// the screen ranks the newest first.
const adminMaxRows = 500

// AdminEntry is one held file with the domain it came from.
//
// The domain NAME is here because this list crosses domains: the path alone
// does not say whose site it is, and the system user is an implementation
// detail the screen has no reason to show.
type AdminEntry struct {
	ID         int64  `json:"id"`
	DomainID   int64  `json:"domain_id"`
	Domain     string `json:"domain"`
	FindingID  *int64 `json:"finding_id"`
	OrigPath   string `json:"orig_path"`
	Size       int64  `json:"size_bytes"`
	Signature  string `json:"signature"`
	Engine     string `json:"engine"`
	CreatedAt  string `json:"created_at"`
	RestoredAt string `json:"restored_at"`
}

// AdminQuarantineList answers GET /admin/antivirus/quarantine (ResellerOrAbove).
//
// The query is narrowed by ScopeSQL, exactly as internal/sitesecurity narrows
// its cross-domain list. An admin is unrestricted and a reseller sees only the
// domains under them.
func (h *Handlers) AdminQuarantineList(w http.ResponseWriter, r *http.Request) {
	condition, args := middleware.ScopeSQL(r, "d")
	// #nosec G202 G701 -- condition is a constant scope fragment from ScopeSQL with a literal alias; every user value is bound through args.
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT q.id, q.domain_id, d.domain_name, q.finding_id, q.system_user, q.orig_rel,
		        q.size_bytes, q.signature, q.engine, q.created_at, q.restored_at
		   FROM av_quarantine q JOIN domains d ON d.id = q.domain_id`+
			condition+` ORDER BY q.id DESC LIMIT `+strconv.Itoa(adminMaxRows), args...)
	if err != nil {
		log.Printf("antivirus: the server-wide quarantine could not be read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the quarantine")
		return
	}
	defer func() { _ = rows.Close() }()

	out := []AdminEntry{}
	for rows.Next() {
		var entry AdminEntry
		var findingID sql.NullInt64
		var systemUser, rel string
		var restored sql.NullString
		if err := rows.Scan(&entry.ID, &entry.DomainID, &entry.Domain, &findingID,
			&systemUser, &rel, &entry.Size, &entry.Signature, &entry.Engine,
			&entry.CreatedAt, &restored); err != nil {
			log.Printf("antivirus: a quarantine row could not be read: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "could not read the quarantine")
			return
		}
		if findingID.Valid {
			value := findingID.Int64
			entry.FindingID = &value
		}
		entry.OrigPath = "/home/" + systemUser + "/" + rel
		entry.RestoredAt = restored.String
		out = append(out, entry)
	}
	// A query that broke half way would otherwise answer 200 with a short list,
	// and "fewer files are being held than I thought" is exactly the reading this
	// screen must not produce.
	if err := rows.Err(); err != nil {
		log.Printf("antivirus: the server-wide quarantine read ended early: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the quarantine")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"entries": out})
}

// entryInScope reads one held file's row, narrowed by the ownership chain.
//
// The narrowing is part of the LOOKUP rather than a check after it. Reading the
// row by id and then comparing would already have read a neighbour's row, and
// answering 403 for it would confirm that the id exists, which is a fact the
// caller is not entitled to. A row outside the caller's scope is therefore
// indistinguishable from one that was never there.
//
// `restoredOnly` narrows further to an entry still being held. A restore needs
// that; a delete and an inspect do not, because the row survives a restore and
// both remain meaningful for it.
func (h *Handlers) entryInScope(r *http.Request, qid int64, heldOnly bool) (systemUser, rel, stored string, ok bool) {
	condition, args, unrestricted := middleware.ScopeCondition(r, "d")
	query := `SELECT q.system_user, q.orig_rel, q.stored_name
	            FROM av_quarantine q JOIN domains d ON d.id = q.domain_id
	           WHERE q.id = ?`
	if !unrestricted {
		query += ` AND ` + condition
	}
	if heldOnly {
		query += ` AND q.restored_at IS NULL`
	}
	// #nosec G202 G701 -- condition is a constant scope fragment from ScopeCondition with a literal alias; every user value is bound through the argument list.
	err := h.DB.QueryRowContext(r.Context(), query, append([]any{qid}, args...)...).
		Scan(&systemUser, &rel, &stored)
	if err != nil {
		return "", "", "", false
	}
	return systemUser, rel, stored, true
}

// AdminQuarantineRestore answers
// POST /admin/antivirus/quarantine/{qid}/restore (ResellerOrAbove).
func (h *Handlers) AdminQuarantineRestore(w http.ResponseWriter, r *http.Request) {
	qid, _ := strconv.ParseInt(chi.URLParam(r, "qid"), 10, 64)
	systemUser, rel, stored, ok := h.entryInScope(r, qid, true)
	if !ok {
		writeReason(w, reasonQuarantineUnknwn)
		return
	}
	path, reason := h.restoreEntry(systemUser, rel, stored, qid)
	if reason != "" {
		writeReason(w, reason)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "path": path})
}

// AdminQuarantineDelete answers
// DELETE /admin/antivirus/quarantine/{qid} (ResellerOrAbove).
func (h *Handlers) AdminQuarantineDelete(w http.ResponseWriter, r *http.Request) {
	qid, _ := strconv.ParseInt(chi.URLParam(r, "qid"), 10, 64)
	systemUser, _, stored, ok := h.entryInScope(r, qid, false)
	if !ok {
		writeReason(w, reasonQuarantineUnknwn)
		return
	}
	if reason := h.deleteEntry(systemUser, stored, qid); reason != "" {
		writeReason(w, reason)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// AdminQuarantineInspect answers
// GET /admin/antivirus/quarantine/{qid}/inspect (ResellerOrAbove).
//
// The file is a KNOWN MALICIOUS one, and it is read the same way the per-domain
// endpoint reads it: through openat2 with RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS,
// with the regular-file test on the DESCRIPTOR.
func (h *Handlers) AdminQuarantineInspect(w http.ResponseWriter, r *http.Request) {
	qid, _ := strconv.ParseInt(chi.URLParam(r, "qid"), 10, 64)
	systemUser, rel, stored, ok := h.entryInScope(r, qid, false)
	if !ok {
		writeReason(w, reasonQuarantineUnknwn)
		return
	}
	response, reason := inspectEntry(systemUser, rel, stored)
	if reason != "" {
		writeReason(w, reason)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, response)
}
