// Package backups manages per-domain archives and database dumps.
package backups

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

// backupRoot returns the root directory for domain backup archives.
func backupRoot() string { return config.BackupRoot() }

var systemUserPattern = regexp.MustCompile(`^c_[A-Za-z0-9_]+$`)

func validSystemUser(systemUser string) bool {
	return systemUserPattern.MatchString(systemUser)
}

// RemoveDomainBackups removes a domain's backup directory after validating its system user.
// It is intentionally not called by domain deletion so operators can recover accidental deletions.
func RemoveDomainBackups(systemUser string) error {
	if !validSystemUser(systemUser) {
		return fmt.Errorf("invalid system user: %q", systemUser)
	}
	dir := filepath.Join(backupRoot(), systemUser)
	if dir == backupRoot() || !strings.HasPrefix(dir, backupRoot()+"/") {
		return fmt.Errorf("unsafe backup path: %q", dir)
	}
	return os.RemoveAll(dir)
}

// Backup describes a stored domain backup.
type Backup struct {
	ID        int64  `json:"id"`
	DomainID  int64  `json:"domain_id"`
	Type      string `json:"type"`
	File      string `json:"file"`
	SizeBytes int64  `json:"size_b"`
	Notes     string `json:"notes"`
	CreatedAt string `json:"created_at"`
}

// Handlers provides backup HTTP handlers.
type Handlers struct {
	DB *sql.DB
}

// backupInProgress guards against concurrent manual backups for the same domain.
// A full backup runs mysqldump + tar over the whole tenant tree; two at once for
// one domain waste CPU/disk/IO and can race the shared dump directory.
var backupInProgress sync.Map // domainID (int64) -> struct{}

func (h *Handlers) lookupDomain(r *http.Request) (id int64, domainName, systemUser string, demo bool, err error) {
	id, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var demoValue int
	err = h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, system_user, is_demo FROM domains WHERE id=?`, id).
		Scan(&domainName, &systemUser, &demoValue)
	demo = demoValue == 1
	return
}

// List returns a domain's backup records.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, domain_id, type, file, size_b, notes, DATE_FORMAT(created_at,'%Y-%m-%d %H:%i')
		 FROM backups WHERE domain_id=? ORDER BY id DESC`, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer func() { _ = rows.Close() }()
	out := make([]Backup, 0)
	for rows.Next() {
		var y Backup
		if err := rows.Scan(&y.ID, &y.DomainID, &y.Type, &y.File, &y.SizeBytes, &y.Notes, &y.CreatedAt); err == nil {
			out = append(out, y)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// SummaryRow describes one domain in the server-wide backup summary.
type SummaryRow struct {
	DomainID   int64  `json:"domain_id"`
	DomainName string `json:"domain_name"`
	Count      int    `json:"count"`
	TotalBytes int64  `json:"total_bytes"`
	LastBackup string `json:"last_backup"`
}

// Summary returns the server-wide backup summary using filesystem disk usage.
func (h *Handlers) Summary(w http.ResponseWriter, r *http.Request) {
	// Scope: a reseller sees only its own customers' backup summary.
	cond, arg := middleware.ScopeSQL(r, "d")
	// #nosec G701 G202 -- cond is a constant scope fragment from ScopeSQL with a literal alias; all user values are bound via arg placeholders.
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT d.id, d.domain_name, d.system_user FROM domains d`+cond+` ORDER BY d.domain_name`, arg...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list backups")
		return
	}
	defer func() { _ = rows.Close() }()
	out := []SummaryRow{}
	var totalBytes int64
	var totalBackups int
	for rows.Next() {
		var id int64
		var domainName, systemUser string
		if err := rows.Scan(&id, &domainName, &systemUser); err != nil {
			continue
		}
		s := SummaryRow{DomainID: id, DomainName: domainName}
		var latestModification time.Time
		if entries, e := os.ReadDir(filepath.Join(backupRoot(), systemUser)); e == nil {
			for _, en := range entries {
				if en.IsDir() || !strings.HasSuffix(en.Name(), ".tar.gz") {
					continue
				}
				fi, e2 := en.Info()
				if e2 != nil {
					continue
				}
				s.Count++
				s.TotalBytes += fi.Size()
				if fi.ModTime().After(latestModification) {
					latestModification = fi.ModTime()
				}
			}
		}
		if !latestModification.IsZero() {
			s.LastBackup = latestModification.Format("2006-01-02 15:04")
		}
		out = append(out, s)
		totalBytes += s.TotalBytes
		totalBackups += s.Count
	}
	_ = rows.Err()
	var destinationCount int
	_ = h.DB.QueryRow(`SELECT COUNT(*) FROM backup_destinations WHERE enabled=1`).Scan(&destinationCount)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"domains":           out,
		"total_size_bytes":  totalBytes,
		"total_backups":     totalBackups,
		"destination_count": destinationCount,
		"schedule":          "Daily at 03:00 (automatic)",
	})
}

// Create generates and stores a full domain backup.
func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	id, domainName, systemUser, demo, err := h.lookupDomain(r)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "backups are unavailable for demo subscriptions")
		return
	}
	if !validSystemUser(systemUser) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid system user")
		return
	}

	// Reject a second concurrent backup for the same domain instead of running
	// duplicate dump+archive work over the same data.
	if _, loaded := backupInProgress.LoadOrStore(id, struct{}{}); loaded {
		httpx.WriteError(w, http.StatusConflict, "a backup is already running for this domain")
		return
	}
	defer backupInProgress.Delete(id)

	// Bound the dump+archive work so a pathological dataset cannot pin mysqldump
	// or tar (CPU/IO heavy) indefinitely and starve the host.
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
	defer cancel()

	stamp := time.Now().UTC().Format("20060102-150405")
	dir := filepath.Join(backupRoot(), systemUser)
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	_ = os.MkdirAll(dir, 0700)
	file := fmt.Sprintf("%s-%s.tar.gz", systemUser, stamp)
	abs := filepath.Join(dir, file)

	// Package the home directory plus EVERY domain-owned database (main + wp_* etc.)
	// under __db__/ with a manifest, into one archive. buildArchive fails closed, so
	// a failed dump/tar aborts the backup instead of storing an unrestorable archive.
	sizeBytes, aerr := buildArchive(ctx, h.DB, id, systemUser, dir, file, time.Now().UTC().Format("2006-01-02 15:04:05"))
	if aerr != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers, or error output; no raw tenant string with CR/LF reaches the log.
		log.Printf("backup build failed for %s: %v", systemUser, aerr)
		httpx.WriteError(w, http.StatusInternalServerError, "could not create backup archive")
		return
	}

	res, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO backups(domain_id, type, file, size_b, notes) VALUES(?,?,?,?,?)`,
		id, "full", file, sizeBytes, "domain: "+domainName)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save backup record")
		return
	}
	backupID, _ := res.LastInsertId()
	// Cap manual backups too: retention previously applied only to scheduled
	// backups, so manual ones accumulated on the root disk (outside the tenant
	// quota) and could fill it (a slow disk-exhaustion DoS).
	pruneManualBackups(h.DB, id, systemUser)
	// If a remote destination exists, upload in the background (do not block the API response)
	pushToDestinationAsync(h.DB, id, backupID, abs, file)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"ok":         true,
		"id":         backupID,
		"file":       file,
		"size_bytes": sizeBytes,
	})
}

// Delete removes a domain backup record and archive.
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	backupID, _ := strconv.ParseInt(chi.URLParam(r, "bid"), 10, 64)
	var systemUser, file, remoteStatus string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT d.system_user, b.file, b.remote_status FROM backups b
		 JOIN domains d ON d.id=b.domain_id
		 WHERE b.id=? AND b.domain_id=?`, backupID, id).Scan(&systemUser, &file, &remoteStatus)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "backup not found")
		return
	}
	// Fail closed: the lookup above is the ownership check. Continuing after any
	// other error would delete a row whose domain was never confirmed, so the
	// request is refused instead.
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	_ = os.Remove(filepath.Join(backupRoot(), systemUser, file))
	// The copy on the destination goes with it. Removing only the local archive
	// left a backup the customer had deleted sitting on their S3 bucket.
	removeRemoteCopy(h.DB, id, file, remoteStatus)
	// domain_id is repeated here so the write is scoped exactly like the lookup.
	_, _ = h.DB.ExecContext(r.Context(), `DELETE FROM backups WHERE id=? AND domain_id=?`, backupID, id)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Download streams a domain backup archive.
func (h *Handlers) Download(w http.ResponseWriter, r *http.Request) {
	// This endpoint moves a body far larger than the server's own read and write
	// timeouts allow for, so it lifts them for this request alone.
	if err := httpx.ExtendDeadline(w, httpx.LargeTransferDeadline); err != nil {
		log.Printf("backup download: could not extend the socket deadline: %v", err)
	}

	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	backupID, _ := strconv.ParseInt(chi.URLParam(r, "bid"), 10, 64)
	var systemUser, file string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT d.system_user, b.file FROM backups b
		 JOIN domains d ON d.id=b.domain_id
		 WHERE b.id=? AND b.domain_id=?`, backupID, id).Scan(&systemUser, &file)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "backup not found")
		return
	}
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	abs := filepath.Join(backupRoot(), systemUser, file)
	// #nosec G304 -- fixed system/config path, server-internal temp/archive path, or validated identifier; tenant reads use safeio (openat2).
	f, err := os.Open(abs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer func() { _ = f.Close() }()
	st, _ := f.Stat()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+file+`"`)
	if st != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	}
	_, _ = io.Copy(w, f)
}

// manualBackupKeep is the number of newest manual ('full') backups retained per
// domain. Older ones have their archive and DB row removed so manual backups
// cannot pile up on the root disk (outside the tenant quota).
const manualBackupKeep = 10

// pruneManualBackups deletes every manual backup beyond the newest
// manualBackupKeep for the domain. Best-effort: any error is ignored so it never
// fails the backup that just succeeded.
func pruneManualBackups(db *sql.DB, domainID int64, systemUser string) {
	rows, err := db.Query(
		`SELECT id, file, remote_status FROM backups
		 WHERE domain_id=? AND type='full'
		 ORDER BY id DESC LIMIT 500 OFFSET ?`, domainID, manualBackupKeep)
	if err != nil {
		return
	}
	type item struct {
		id           int64
		file         string
		remoteStatus string
	}
	var old []item
	for rows.Next() {
		var it item
		if rows.Scan(&it.id, &it.file, &it.remoteStatus) == nil {
			old = append(old, it)
		}
	}
	_ = rows.Close()
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	for _, it := range old {
		_ = os.Remove(filepath.Join(backupRoot(), systemUser, it.file))
		removeRemoteCopy(db, domainID, it.file, it.remoteStatus)
		_, _ = db.Exec(`DELETE FROM backups WHERE id=?`, it.id)
	}
}
