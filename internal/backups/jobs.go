package backups

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"servika/internal/httpx"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

// Job is one bulk backup or restore operation with live progress.
type Job struct {
	ID           int64  `json:"id"`
	Type         string `json:"type"`      // manual | scheduled
	Operation    string `json:"operation"` // backup | restore
	Status       string `json:"status"`    // running | done | partial | failed
	Total        int    `json:"total"`
	Completed    int    `json:"completed"`
	Succeeded    int    `json:"succeeded"`
	Failed       int    `json:"failed"`
	SizeBytes    int64  `json:"size_b"`
	ActiveDomain string `json:"active_domain"`
	RestoreMode  string `json:"restore_mode"`
	StartedBy    string `json:"started_by"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
}

const jobColumns = `id, type, operation, status, total, completed, succeeded, failed, size_b,
	active_domain, restore_mode, started_by,
	DATE_FORMAT(started_at,'%Y-%m-%d %H:%i'), COALESCE(DATE_FORMAT(finished_at,'%Y-%m-%d %H:%i'),'')`

// jobStatus maps the per-domain tallies onto the job's terminal status.
func jobStatus(succeeded, failed int) string {
	if failed == 0 {
		return "done"
	}
	if succeeded == 0 {
		return "failed"
	}
	return "partial"
}

// backupOneDomain writes one domain archive and its backups row, tagged with the
// job that produced it. Retention pruning is the caller's job, because manual and
// scheduled backups keep different counts.
func backupOneDomain(ctx context.Context, db *sql.DB, domainID int64, systemUser, backupType, notes string, jobID int64) (int64, string, error) {
	if !validSystemUser(systemUser) {
		return 0, "", fmt.Errorf("invalid system user")
	}
	dir := filepath.Join(backupRoot(), systemUser)
	// #nosec G703 -- path derives from backupRoot() and a validSystemUser-checked identifier.
	_ = os.MkdirAll(dir, 0700)
	stamp := time.Now().UTC().Format("20060102-150405")
	suffix := ""
	if backupType == "scheduled" {
		suffix = "-auto"
	}
	file := fmt.Sprintf("%s%s-%s.tar.gz", systemUser, suffix, stamp)
	size, err := buildArchive(ctx, db, domainID, systemUser, dir, file, time.Now().UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		return 0, "", err
	}
	var job any
	if jobID > 0 {
		job = jobID
	}
	res, err := db.Exec(
		`INSERT INTO backups(domain_id, type, file, size_b, notes, job_id) VALUES(?,?,?,?,?,?)`,
		domainID, backupType, file, size, notes, job)
	if err != nil {
		return size, file, err
	}
	backupID, _ := res.LastInsertId()
	pushToDestinationAsync(db, domainID, backupID, filepath.Join(dir, file), file)
	return size, file, nil
}

// restoreCore applies one backup in a coarse mode (full, files, database). It is the
// non-HTTP path used by multi-domain restore jobs; per-file and per-database selection
// stays on the single-domain restore endpoint.
func restoreCore(ctx context.Context, db *sql.DB, domainID, backupID int64, mode string, clean bool) (string, error) {
	var systemUser, file string
	var isDemo int
	err := db.QueryRowContext(ctx,
		`SELECT d.system_user, d.is_demo, b.file FROM backups b
		 JOIN domains d ON d.id=b.domain_id WHERE b.id=? AND b.domain_id=?`, backupID, domainID).
		Scan(&systemUser, &isDemo, &file)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("backup not found")
	}
	if err != nil {
		return "", fmt.Errorf("backup lookup failed")
	}
	if isDemo == 1 {
		return "", fmt.Errorf("restore is unavailable for demo subscriptions")
	}
	if !validSystemUser(systemUser) || file == "" || filepath.Base(file) != file {
		return "", fmt.Errorf("invalid backup file")
	}
	abs := filepath.Join(backupRoot(), systemUser, file)
	// #nosec G703 -- path derives from backupRoot(), a validSystemUser-checked identifier and a base-name-validated file.
	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("backup file is missing on disk")
	}
	allMembers, _ := listArchiveMembers(abs)
	members := membersForMode(mode, systemUser, allMembers, nil)
	if len(members) == 0 {
		return "", fmt.Errorf("the backup has no content for this restore mode")
	}
	tmpDir, err := os.MkdirTemp("", "servika-restore-*")
	if err != nil {
		return "", fmt.Errorf("could not prepare backup restore")
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	if _, err := extractMembersRoot(ctx, abs, tmpDir, members); err != nil {
		return "", fmt.Errorf("invalid backup archive")
	}

	switch mode {
	case "full":
		if err := restoreHome(ctx, tmpDir, systemUser, clean); err != nil {
			return "", fmt.Errorf("the home directory could not be restored")
		}
		if failedDBRestore(restoreAllDBs(ctx, db, domainID, tmpDir, systemUser, "")) {
			return "", fmt.Errorf("files were restored but a database import failed")
		}
		return "restored files and databases", nil
	case "files":
		if err := restoreHome(ctx, tmpDir, systemUser, clean); err != nil {
			return "", fmt.Errorf("the home directory could not be restored")
		}
		return "restored files", nil
	case "database":
		if failedDBRestore(restoreAllDBs(ctx, db, domainID, tmpDir, systemUser, "")) {
			return "", fmt.Errorf("a database import failed")
		}
		return "restored databases", nil
	}
	return "", fmt.Errorf("invalid restore mode")
}

// scopedDomains returns the in-scope, non-demo domains, optionally narrowed to ids.
// The scope filter runs inside the query, so a reseller can never reach another
// reseller's domains by passing their ids.
func (h *Handlers) scopedDomains(r *http.Request, ids []int64) ([]jobDomain, error) {
	cond, args := middleware.ScopeSQL(r, "d")
	// #nosec G202 -- cond is a constant ScopeSQL fragment with a literal alias; user values are bound via args.
	q := `SELECT d.id, d.system_user, d.domain_name FROM domains d` + cond
	if cond == "" {
		q += ` WHERE d.is_demo=0`
	} else {
		q += ` AND d.is_demo=0`
	}
	if len(ids) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
		q += ` AND d.id IN (` + placeholders + `)`
		for _, id := range ids {
			args = append(args, id)
		}
	}
	q += ` ORDER BY d.domain_name`
	// #nosec G701 G202 -- cond is a constant ScopeSQL fragment with a literal alias and the IN list is literal "?" placeholders; every value is bound.
	rows, err := h.DB.QueryContext(r.Context(), q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []jobDomain{}
	for rows.Next() {
		var d jobDomain
		if rows.Scan(&d.ID, &d.SystemUser, &d.DomainName) == nil && validSystemUser(d.SystemUser) {
			out = append(out, d)
		}
	}
	return out, rows.Err()
}

type jobDomain struct {
	ID         int64
	SystemUser string
	DomainName string
}

// startJob inserts the job row and returns its id.
func (h *Handlers) startJob(operation, restoreMode, startedBy string, total int) (int64, error) {
	res, err := h.DB.Exec(
		`INSERT INTO backup_jobs(type, operation, status, total, restore_mode, started_by)
		 VALUES('manual',?,'running',?,?,?)`, operation, total, restoreMode, startedBy)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// finishJob closes a job with its aggregate status.
func finishJob(db *sql.DB, jobID int64, succeeded, failed int) {
	if _, err := db.Exec(
		`UPDATE backup_jobs SET status=?, active_domain='', finished_at=NOW() WHERE id=?`,
		jobStatus(succeeded, failed), jobID); err != nil {
		log.Printf("backup job %d: could not close: %v", jobID, err)
	}
}

func actorName(r *http.Request) string {
	if c := middleware.ClaimsFrom(r); c != nil {
		return c.Username
	}
	return "system"
}

// StartBackupJob handles POST /admin/backups/jobs and backs up every in-scope domain,
// or only the requested ids, as one tracked job.
func (h *Handlers) StartBackupJob(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DomainIDs []int64 `json:"domain_ids"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	domains, err := h.scopedDomains(r, req.DomainIDs)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list domains")
		return
	}
	if len(domains) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "no domain is available to back up")
		return
	}

	jobID, err := h.startJob("backup", "", actorName(r), len(domains))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not start the backup job")
		return
	}

	// #nosec G118 -- intentional detached context: the job outlives the request, which would otherwise cancel it mid-archive.
	go func() {
		var totalBytes int64
		succeeded, failed := 0, 0
		for _, d := range domains {
			if _, err := h.DB.Exec(`UPDATE backup_jobs SET active_domain=? WHERE id=?`, d.DomainName, jobID); err != nil {
				log.Printf("backup job %d: progress update failed: %v", jobID, err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			size, _, err := backupOneDomain(ctx, h.DB, d.ID, d.SystemUser, "full", "Bulk backup", jobID)
			cancel()
			if err != nil {
				failed++
				log.Printf("backup job %d: domain %d failed: %v", jobID, d.ID, err)
			} else {
				succeeded++
				totalBytes += size
			}
			// Trimmed whether or not the archive was written, for the same
			// reason as the scheduler: the domain that cannot be backed up is
			// usually the one with no room left, and that is the worst moment
			// to stop reclaiming any.
			pruneManualBackups(h.DB, d.ID, d.SystemUser)
			if _, err := h.DB.Exec(
				`UPDATE backup_jobs SET completed=?, succeeded=?, failed=?, size_b=? WHERE id=?`,
				succeeded+failed, succeeded, failed, totalBytes, jobID); err != nil {
				log.Printf("backup job %d: progress update failed: %v", jobID, err)
			}
		}
		finishJob(h.DB, jobID, succeeded, failed)
	}()

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"ok": true, "job_id": jobID, "total": len(domains)})
}

// HealJobsOnStartup closes any backup_jobs row left 'running' by a panel restart.
//
// A bulk backup or restore runs in a detached goroutine, so a restart mid-job
// leaves its row at 'running' with no goroutine to finish it. The polling UI
// then shows a job in progress that will never advance, and the started_by
// operator waits for a result that cannot come. Marking it 'failed' at startup
// tells the truth: the run was interrupted and did not complete. A partial
// backup already wrote its per-domain rows, so nothing done is lost; only the
// job's own status is corrected.
func (h *Handlers) HealJobsOnStartup() {
	res, err := h.DB.Exec(
		`UPDATE backup_jobs SET status='failed', active_domain='', finished_at=NOW()
		 WHERE status='running'`)
	if err != nil {
		log.Printf("backup jobs: startup heal failed: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("backup jobs: %d unfinished job(s) marked as failed", n)
	}
}

// jobScopeFilter narrows a backup_jobs query to the jobs the caller may see. It
// returns a bare boolean fragment, so the caller supplies its own WHERE or AND.
//
// backup_jobs carries no owner column and no domain link of its own: a backup job
// reaches its domains only through backups.job_id, and a restore job's items live
// in the detail JSON, which is not queryable. A reseller therefore sees a job when
// it produced at least one archive of a domain they own, or when they started it.
// A restore job somebody else started stays hidden, which is the right answer,
// because its item list is not scoped either.
//
// An empty fragment means "no narrowing" and is returned ONLY for an admin. It is
// never returned for an unauthenticated caller, who is refused outright: an
// EXISTS that matches nothing would still leave the started_by branch, and
// actorName answers "system" with no claims, which is the nightly job's own name.
func jobScopeFilter(r *http.Request, alias string) (string, []any) {
	c := middleware.ClaimsFrom(r)
	if c == nil {
		return " 1 = 0", nil
	}
	if c.Role == middleware.RoleAdmin {
		return "", nil
	}
	cond, args := middleware.ScopeSQL(r, "d")
	inner := `SELECT 1 FROM backups b JOIN domains d ON d.id=b.domain_id` + cond +
		` AND b.job_id=` + alias + `.id`
	args = append(args, c.Username)
	return ` (EXISTS (` + inner + `) OR ` + alias + `.started_by=?)`, args
}

// redactJobForScope blanks the two job fields that name something outside the
// caller's scope.
//
// Visibility and content are separate questions. A reseller may see the nightly
// job because it backed up one of their domains, but active_domain names whichever
// domain that run is on RIGHT NOW, which is usually somebody else's, and
// started_by names another operator. "system" is kept: it is the scheduler, not a
// person, and hiding it would make the nightly run look anonymous.
func redactJobForScope(r *http.Request, j *Job) {
	c := middleware.ClaimsFrom(r)
	if c == nil {
		j.ActiveDomain, j.StartedBy = "", ""
		return
	}
	if c.Role == middleware.RoleAdmin || j.StartedBy == c.Username {
		return
	}
	j.ActiveDomain = ""
	if j.StartedBy != "system" {
		j.StartedBy = ""
	}
}

// ListJobs handles GET /admin/backups/jobs and returns recent jobs; the panel polls
// this for progress.
func (h *Handlers) ListJobs(w http.ResponseWriter, r *http.Request) {
	filter, args := jobScopeFilter(r, "j")
	q := `SELECT ` + jobColumns + ` FROM backup_jobs j`
	if filter != "" {
		q += ` WHERE` + filter
	}
	// #nosec G701 G202 -- filter is a constant fragment built from ScopeSQL with a literal alias; every value is bound via args.
	rows, err := h.DB.QueryContext(r.Context(), q+` ORDER BY j.id DESC LIMIT 60`, args...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list backup jobs")
		return
	}
	defer func() { _ = rows.Close() }()
	out := []Job{}
	for rows.Next() {
		var j Job
		if scanJob(rows, &j) == nil {
			redactJobForScope(r, &j)
			out = append(out, j)
		}
	}
	_ = rows.Err()
	httpx.WriteJSON(w, http.StatusOK, out)
}

func scanJob(rs interface{ Scan(...any) error }, j *Job) error {
	return rs.Scan(&j.ID, &j.Type, &j.Operation, &j.Status, &j.Total, &j.Completed, &j.Succeeded,
		&j.Failed, &j.SizeBytes, &j.ActiveDomain, &j.RestoreMode, &j.StartedBy, &j.StartedAt, &j.FinishedAt)
}

// JobItem is one archive produced by a backup job.
type JobItem struct {
	BackupID   int64  `json:"backup_id"`
	DomainID   int64  `json:"domain_id"`
	DomainName string `json:"domain_name"`
	SystemUser string `json:"system_user"`
	SizeBytes  int64  `json:"size_b"`
	Type       string `json:"type"`
}

// JobDetail handles GET /admin/backups/jobs/{jid}. A backup job lists the archives it
// produced; a restore job returns the stored per-domain results.
func (h *Handlers) JobDetail(w http.ResponseWriter, r *http.Request) {
	jobID, _ := strconv.ParseInt(chi.URLParam(r, "jid"), 10, 64)
	var j Job
	var detail sql.NullString
	// The header is scoped exactly like the list. Without it the item list below
	// was narrowed while the row above it still named another reseller's domain.
	filter, args := jobScopeFilter(r, "j")
	q := `SELECT ` + jobColumns + `, detail FROM backup_jobs j WHERE j.id=?`
	headerArgs := append([]any{jobID}, args...)
	if filter != "" {
		q += ` AND` + filter
	}
	// #nosec G701 G202 -- filter is a constant fragment built from ScopeSQL with a literal alias; every value is bound via headerArgs.
	err := h.DB.QueryRowContext(r.Context(), q, headerArgs...).
		Scan(&j.ID, &j.Type, &j.Operation, &j.Status, &j.Total, &j.Completed, &j.Succeeded,
			&j.Failed, &j.SizeBytes, &j.ActiveDomain, &j.RestoreMode, &j.StartedBy,
			&j.StartedAt, &j.FinishedAt, &detail)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "backup job not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	redactJobForScope(r, &j)

	resp := map[string]any{"job": j}
	if j.Operation == "restore" {
		var results any
		if detail.Valid && detail.String != "" {
			_ = json.Unmarshal([]byte(detail.String), &results)
		}
		resp["results"] = results
		httpx.WriteJSON(w, http.StatusOK, resp)
		return
	}

	// Scope the item list so a reseller only sees its own domains' archives.
	cond, itemArgs := middleware.ScopeSQL(r, "d")
	itemQuery := `SELECT b.id, b.domain_id, d.domain_name, d.system_user, b.size_b, b.type
	      FROM backups b JOIN domains d ON d.id=b.domain_id` + cond
	if cond == "" {
		itemQuery += ` WHERE b.job_id=?`
	} else {
		itemQuery += ` AND b.job_id=?`
	}
	itemArgs = append(itemArgs, jobID)
	// #nosec G701 G202 -- cond is a constant ScopeSQL fragment with a literal alias; every value is bound.
	rows, err := h.DB.QueryContext(r.Context(), itemQuery+` ORDER BY d.domain_name`, itemArgs...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list job items")
		return
	}
	defer func() { _ = rows.Close() }()
	items := []JobItem{}
	for rows.Next() {
		var it JobItem
		if rows.Scan(&it.BackupID, &it.DomainID, &it.DomainName, &it.SystemUser, &it.SizeBytes, &it.Type) == nil {
			items = append(items, it)
		}
	}
	_ = rows.Err()
	resp["domains"] = items
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// StartRestoreJob handles POST /admin/backups/restore and restores several domains in
// one tracked job. Only coarse modes are accepted here.
func (h *Handlers) StartRestoreJob(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode  string `json:"mode"`
		Clean bool   `json:"clean"`
		Items []struct {
			DomainID int64 `json:"domain_id"`
			BackupID int64 `json:"backup_id"`
		} `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Mode = strings.TrimSpace(req.Mode)
	if req.Mode == "" {
		req.Mode = "full"
	}
	if req.Mode != "full" && req.Mode != "files" && req.Mode != "database" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid restore mode")
		return
	}
	if len(req.Items) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "no item was selected for restore")
		return
	}

	// Resolve the requested domains through the scope filter, so out-of-scope ids
	// are dropped instead of restored.
	ids := make([]int64, 0, len(req.Items))
	for _, it := range req.Items {
		ids = append(ids, it.DomainID)
	}
	allowed, err := h.scopedDomains(r, ids)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not resolve domains")
		return
	}
	names := map[int64]string{}
	for _, d := range allowed {
		names[d.ID] = d.DomainName
	}
	type restoreItem struct {
		domainID, backupID int64
		domainName         string
	}
	items := []restoreItem{}
	for _, it := range req.Items {
		if name, ok := names[it.DomainID]; ok {
			items = append(items, restoreItem{it.DomainID, it.BackupID, name})
		}
	}
	if len(items) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "no valid item was selected")
		return
	}

	jobID, err := h.startJob("restore", req.Mode, actorName(r), len(items))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not start the restore job")
		return
	}

	// #nosec G118 -- intentional detached context: the job outlives the request, which would otherwise cancel it mid-restore.
	go func() {
		type result struct {
			DomainID   int64  `json:"domain_id"`
			DomainName string `json:"domain_name"`
			Status     string `json:"status"`
			Message    string `json:"message"`
		}
		results := []result{}
		succeeded, failed := 0, 0
		for _, it := range items {
			if _, err := h.DB.Exec(`UPDATE backup_jobs SET active_domain=? WHERE id=?`, it.domainName, jobID); err != nil {
				log.Printf("restore job %d: progress update failed: %v", jobID, err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			message, err := restoreCore(ctx, h.DB, it.domainID, it.backupID, req.Mode, req.Clean)
			cancel()
			entry := result{DomainID: it.domainID, DomainName: it.domainName}
			if err != nil {
				failed++
				entry.Status = "failed"
				entry.Message = err.Error()
			} else {
				succeeded++
				entry.Status = "done"
				entry.Message = message
			}
			results = append(results, entry)
			payload, _ := json.Marshal(results)
			if _, err := h.DB.Exec(
				`UPDATE backup_jobs SET completed=?, succeeded=?, failed=?, detail=? WHERE id=?`,
				succeeded+failed, succeeded, failed, string(payload), jobID); err != nil {
				log.Printf("restore job %d: progress update failed: %v", jobID, err)
			}
		}
		finishJob(h.DB, jobID, succeeded, failed)
	}()

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"ok": true, "job_id": jobID, "total": len(items)})
}
