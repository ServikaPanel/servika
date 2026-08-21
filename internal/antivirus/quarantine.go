package antivirus

// Quarantine takes a file out of a tenant tree and keeps it where the account it
// came from cannot reach it.
//
// The store lives under config.QuarantineDir(), OUTSIDE every home. A directory
// inside the home would be owned by the tenant, so the same account that planted
// a webshell could carry it back, it would be charged to their disk quota, and it
// would join their backups. That also means the move crosses a filesystem
// boundary in the general case, so it is a copy followed by a removal rather than
// a rename, and the ORDER matters: the original is removed last, and a copy whose
// original survives is taken back rather than reported as contained.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"servika/internal/config"
	"servika/internal/files"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// quarantineMaxBytes bounds one quarantined file. The store is under /var, which
// the panel itself needs, so a tenant must not be able to fill it by asking for
// a very large file to be contained.
const quarantineMaxBytes = 512 << 20 // 512 MiB

// Stable reason codes. The API answers in English and the panel draws twelve
// languages, so a screen that matched the message would break on the first
// wording change.
const (
	reasonFindingUnknown  = "av_finding_unknown"
	reasonFileMissing     = "av_file_missing"
	reasonPathOutsideHome = "av_path_outside_home"
	reasonTooLarge        = "av_too_large"
	reasonRestoreOccupied = "av_restore_target_exists"
	reasonQuarantineFail  = "av_quarantine_failed"
	// reasonCoreFile is a REFUSAL, not a failure: the file is a WordPress core
	// file, so it is reported and repaired rather than moved out of the tree.
	reasonCoreFile         = "av_core_file_not_quarantined"
	reasonQuarantineUnknwn = "av_quarantine_unknown"
)

// Entry is one file the panel is holding.
type Entry struct {
	ID         int64  `json:"id"`
	FindingID  *int64 `json:"finding_id"`
	OrigPath   string `json:"orig_path"`
	Size       int64  `json:"size"`
	Signature  string `json:"signature"`
	Engine     string `json:"engine"`
	CreatedAt  string `json:"created_at"`
	RestoredAt string `json:"restored_at"`
}

// homeRelative turns a finding's absolute path into a path relative to the
// tenant home, refusing anything that does not sit under it.
//
// The finding rows are written by this package's own scan, so a mismatch is a
// bug rather than an attack, but the conversion is the last point at which a
// path that escaped the home can be caught before a root-privileged file
// operation, so it refuses rather than repairing.
func homeRelative(home, absolute string) (string, bool) {
	clean := filepath.Clean(absolute)
	if !strings.HasPrefix(clean, home+"/") {
		return "", false
	}
	rel := strings.TrimPrefix(clean, home+"/")
	if rel == "" || rel == "." {
		return "", false
	}
	return rel, true
}

// userStore is the directory holding one tenant's quarantined files.
func userStore(systemUser string) string {
	return filepath.Join(config.QuarantineDir(), systemUser)
}

// storedName is the on-disk name, carrying the database id so two files with the
// same base name cannot collide and an orphan left by a crash cannot be taken
// for a live entry.
func storedName(rowID int64, rel string) string {
	return strconv.FormatInt(rowID, 10) + "_" + filepath.Base(rel)
}

// contain copies rel out of the tenant home into the store and then removes the
// original, reporting the size it wrote.
//
// The content comes from a descriptor openat2 already resolved with
// RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS, so no path is walked as text a second
// time and there is no window in which a component could be swapped between the
// check and the copy.
func contain(home, rel, systemUser string, rowID int64) (int64, error) {
	source, err := files.OpenBeneath(home, rel)
	if err != nil {
		return 0, err
	}
	defer func() { _ = source.Close() }()
	// Asserted on the DESCRIPTOR rather than on a separate stat of the path: a
	// fifo or a device node under the home opens successfully, and copying one
	// would block the handler for as long as nothing writes to it.
	info, err := source.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("%w: not a regular file", os.ErrInvalid)
	}
	if info.Size() > quarantineMaxBytes {
		return 0, errTooLarge
	}

	dir := userStore(systemUser)
	// #nosec G301 -- the quarantine store holds files taken out of a tenant tree; 0700 root keeps every tenant out of it.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	target := filepath.Join(dir, storedName(rowID, rel))
	// O_EXCL: the name carries the row id, so an existing file means an orphan
	// from an earlier crash, and overwriting it would destroy evidence.
	// #nosec G304 -- path is built from config.QuarantineDir(), a validated system user and a database row id; no caller text reaches it.
	sink, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	written, copyErr := io.Copy(sink, source)
	closeErr := sink.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(target)
		return 0, errors.Join(copyErr, closeErr)
	}

	if err := files.RemoveAllBeneath(home, rel); err != nil {
		// The copy landed but the original is still live, so the file is NOT
		// contained. Take the copy back rather than report a containment that did
		// not happen.
		_ = os.Remove(target)
		return 0, err
	}
	return written, nil
}

var errTooLarge = errors.New("antivirus: file is too large to quarantine")

// record writes the row that says where a contained file came from, and returns
// its id. The row is written FIRST with the size unknown, because the stored
// name carries that id; the size is filled in once the copy landed.
func (h *Handlers) record(domainID int64, findingID *int64, systemUser, rel, signature, engine string) (int64, error) {
	result, err := h.DB.Exec(
		`INSERT INTO av_quarantine (domain_id, finding_id, system_user, orig_rel, stored_name, signature, engine)
		 VALUES (?,?,?,?,'',?,?)`,
		domainID, findingID, systemUser, rel, signature, engine)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// quarantineFinding contains one finding and returns the reason code when it
// cannot. An empty reason means it worked.
func (h *Handlers) quarantineFinding(domainID int64, systemUser string, findingID int64) string {
	var absolute, signature, engine string
	var already int
	if err := h.DB.QueryRow(
		`SELECT file, signature, engine, quarantined FROM av_findings WHERE id=? AND domain_id=?`,
		findingID, domainID).Scan(&absolute, &signature, &engine, &already); err != nil {
		return reasonFindingUnknown
	}
	if already == 1 {
		return "" // nothing to do, and saying so would read as a failure
	}
	// A core file is reported and left where it is. Moving it takes the site
	// down, and the repair that puts the official file back is a different
	// action the panel already offers. The check is here rather than only in the
	// automatic pass, because the manual button reaches the same file.
	if CoreFileProtected(absolute, signature) {
		return reasonCoreFile
	}
	home := "/home/" + systemUser
	rel, inside := homeRelative(home, absolute)
	if !inside {
		return reasonPathOutsideHome
	}

	rowID, err := h.record(domainID, &findingID, systemUser, rel, signature, engine)
	if err != nil {
		return reasonQuarantineFail
	}
	size, err := contain(home, rel, systemUser, rowID)
	if err != nil {
		// The row describes a containment that did not happen, so it goes.
		_, _ = h.DB.Exec(`DELETE FROM av_quarantine WHERE id=?`, rowID)
		switch {
		case errors.Is(err, errTooLarge):
			return reasonTooLarge
		case errors.Is(err, os.ErrNotExist):
			return reasonFileMissing
		default:
			return reasonQuarantineFail
		}
	}
	if _, err := h.DB.Exec(
		`UPDATE av_quarantine SET stored_name=?, size_bytes=? WHERE id=?`,
		storedName(rowID, rel), size, rowID); err != nil {
		return reasonQuarantineFail
	}
	_, _ = h.DB.Exec(`UPDATE av_findings SET quarantined=1 WHERE id=? AND domain_id=?`, findingID, domainID)
	return ""
}

// POST /domains/{id}/antivirus/quarantine  {finding_id}
//
// The path is read from the FINDING, never from the request. It used to be sent
// by the caller and checked with a string prefix, which is not a boundary: lstat
// and rename follow symlinks in every component except the last, so a tenant who
// planted a link inside their own public_html could have the panel move any file
// on the host, as root.
func (h *Handlers) Quarantine(w http.ResponseWriter, r *http.Request) {
	id, systemUser, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req struct {
		FindingID int64 `json:"finding_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if reason := h.quarantineFinding(id, systemUser, req.FindingID); reason != "" {
		writeReason(w, reason)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /domains/{id}/antivirus/quarantine/all  {scan_id}
//
// The partial result is reported AS a partial result. Calling a cleanup that
// left the one file that mattered a success is how a compromised site looks
// clean on the screen.
func (h *Handlers) QuarantineAll(w http.ResponseWriter, r *http.Request) {
	id, systemUser, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req struct {
		ScanID int64 `json:"scan_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id FROM av_findings WHERE scan_id=? AND domain_id=? AND quarantined=0 ORDER BY id`,
		req.ScanID, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the findings")
		return
	}
	ids := []int64{}
	for rows.Next() {
		var findingID int64
		if rows.Scan(&findingID) == nil {
			ids = append(ids, findingID)
		}
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the findings")
		return
	}

	quarantined := 0
	failures := map[string]int{}
	for _, findingID := range ids {
		if reason := h.quarantineFinding(id, systemUser, findingID); reason != "" {
			failures[reason]++
			continue
		}
		quarantined++
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "quarantined": quarantined, "failed": len(ids) - quarantined, "reasons": failures,
	})
}

// GET /domains/{id}/antivirus/quarantine
func (h *Handlers) QuarantineList(w http.ResponseWriter, r *http.Request) {
	id, systemUser, ok := h.tenant(w, r)
	if !ok {
		return
	}
	out := []Entry{}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, finding_id, orig_rel, size_bytes, signature, engine, created_at, restored_at
		   FROM av_quarantine WHERE domain_id=? ORDER BY id DESC`, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the quarantine")
		return
	}
	defer func() { _ = rows.Close() }()
	home := "/home/" + systemUser
	for rows.Next() {
		var entry Entry
		var findingID sql.NullInt64
		var rel string
		var restored sql.NullString
		if err := rows.Scan(&entry.ID, &findingID, &rel, &entry.Size,
			&entry.Signature, &entry.Engine, &entry.CreatedAt, &restored); err != nil {
			continue
		}
		if findingID.Valid {
			value := findingID.Int64
			entry.FindingID = &value
		}
		entry.OrigPath = home + "/" + rel
		entry.RestoredAt = restored.String
		out = append(out, entry)
	}
	_ = rows.Err()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"entries": out})
}

// POST /domains/{id}/antivirus/quarantine/{qid}/restore
func (h *Handlers) QuarantineRestore(w http.ResponseWriter, r *http.Request) {
	id, systemUser, ok := h.tenant(w, r)
	if !ok {
		return
	}
	qid, _ := strconv.ParseInt(chi.URLParam(r, "qid"), 10, 64)
	var rel, stored string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT orig_rel, stored_name FROM av_quarantine
		  WHERE id=? AND domain_id=? AND restored_at IS NULL`, qid, id).Scan(&rel, &stored); err != nil {
		writeReason(w, reasonQuarantineUnknwn)
		return
	}
	// #nosec G304 -- path is built from config.QuarantineDir(), a validated system user and a stored name derived from a row id; no caller text reaches it.
	source, err := os.Open(filepath.Join(userStore(systemUser), stored))
	if err != nil {
		writeReason(w, reasonFileMissing)
		return
	}
	defer func() { _ = source.Close() }()

	home := "/home/" + systemUser
	// StreamIntoBeneath refuses an existing target, so a restore cannot write over
	// whatever the tenant has since put at that path.
	if _, err := files.StreamIntoBeneath(home, rel, source, systemUser); err != nil {
		if errors.Is(err, os.ErrExist) {
			writeReason(w, reasonRestoreOccupied)
			return
		}
		writeReason(w, reasonQuarantineFail)
		return
	}
	if _, err := h.DB.Exec(`UPDATE av_quarantine SET restored_at=NOW() WHERE id=?`, qid); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the file was restored but the record could not be updated")
		return
	}
	_ = os.Remove(filepath.Join(userStore(systemUser), stored))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "path": home + "/" + rel})
}

// DELETE /domains/{id}/antivirus/quarantine/{qid}
func (h *Handlers) QuarantineDelete(w http.ResponseWriter, r *http.Request) {
	id, systemUser, ok := h.tenant(w, r)
	if !ok {
		return
	}
	qid, _ := strconv.ParseInt(chi.URLParam(r, "qid"), 10, 64)
	var stored string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT stored_name FROM av_quarantine WHERE id=? AND domain_id=?`, qid, id).Scan(&stored); err != nil {
		writeReason(w, reasonQuarantineUnknwn)
		return
	}
	// The file goes first. A row removed while the file survived would leave an
	// orphan nothing can name, since the name is derived from the row id.
	if err := os.Remove(filepath.Join(userStore(systemUser), stored)); err != nil && !errors.Is(err, os.ErrNotExist) {
		writeReason(w, reasonQuarantineFail)
		return
	}
	if _, err := h.DB.Exec(`DELETE FROM av_quarantine WHERE id=? AND domain_id=?`, qid, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not remove the record")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// RemoveStoreForUser deletes a tenant's whole quarantine store.
//
// Domain deletion needs this because the store lives OUTSIDE the home, so
// `userdel -r` never touches it and the rows go with the foreign key while the
// files would stay for good.
func RemoveStoreForUser(systemUser string) error {
	if !strings.HasPrefix(systemUser, "c_") {
		return fmt.Errorf("antivirus: refusing to remove a store for %q", systemUser)
	}
	return os.RemoveAll(userStore(systemUser))
}

// tenant resolves the domain and refuses the cases no file operation may run
// for, so every handler above starts from the same answer.
func (h *Handlers) tenant(w http.ResponseWriter, r *http.Request) (int64, string, bool) {
	id, systemUser, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return 0, "", false
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "not available for demo subscriptions")
		return 0, "", false
	}
	if !strings.HasPrefix(systemUser, "c_") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user")
		return 0, "", false
	}
	return id, systemUser, true
}

// writeReason answers with a stable code beside the English message.
func writeReason(w http.ResponseWriter, reason string) {
	status := http.StatusBadRequest
	message := "the file could not be quarantined"
	switch reason {
	case reasonFindingUnknown, reasonQuarantineUnknwn:
		status, message = http.StatusNotFound, "not found"
	case reasonFileMissing:
		message = "the file is no longer there"
	case reasonPathOutsideHome:
		message = "the path is outside the domain directory"
	case reasonTooLarge:
		status, message = http.StatusRequestEntityTooLarge, "the file is too large to quarantine"
	case reasonRestoreOccupied:
		status, message = http.StatusConflict, "a file already exists at that path"
	case reasonCoreFile:
		// 409 rather than 400: the request was well formed and the refusal is
		// about the state of the target, exactly as the restore conflict above.
		status = http.StatusConflict
		message = "this is a WordPress core file; removing it would take the site down. Repair the core instead."
	case reasonQuarantineFail:
		status = http.StatusInternalServerError
	}
	httpx.WriteJSON(w, status, map[string]any{"error": message, "reason": reason})
}
