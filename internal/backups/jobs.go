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
	"sync"
	"time"

	"servika/internal/bgjob"
	"servika/internal/httpx"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

// runningJobs holds the cancel func of every bulk job in flight (jobID ->
// context.CancelFunc), so an operator can stop one.
//
// A bulk backup or restore can run for hours (dozens of domains, a single tenant
// tens of gigabytes). The only way to stop one was to restart the panel, which
// killed the running tar mid-file and left a partial archive, because a killed
// process never runs its cleanup. A proper stop cancels the context:
// exec.CommandContext kills tar, and buildArchive removes the partial file.
var runningJobs sync.Map

func registerJob(jobID int64, cancel context.CancelFunc) { runningJobs.Store(jobID, cancel) }
func unregisterJob(jobID int64)                          { runningJobs.Delete(jobID) }

// stopJob cancels a registered job and returns whether one was found. A job that
// is not registered may have been left running by a panel restart; the caller
// closes that hung row itself so the UI does not show it in progress forever.
func stopJob(jobID int64) bool {
	v, ok := runningJobs.Load(jobID)
	if !ok {
		return false
	}
	if cancel, is := v.(context.CancelFunc); is {
		cancel()
	}
	runningJobs.Delete(jobID)
	return true
}

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
//
// The domain lock is taken HERE rather than in each caller, because this is the
// one place every backup goes through: the manual handler, the bulk job and the
// scheduler. A backup that ran while a restore was rewriting the same tree
// captured a half-written document root and recorded it as a normal,
// checksum-verified archive.
func backupOneDomain(ctx context.Context, db *sql.DB, domainID int64, systemUser, backupType, notes string, jobID int64) (int64, string, error) {
	if !validSystemUser(systemUser) {
		return 0, "", fmt.Errorf("invalid system user")
	}
	release, ok := lockDomain(domainID)
	if !ok {
		return 0, "", ErrDomainBusy
	}
	defer release()
	dir := filepath.Join(backupRoot(), systemUser)
	// #nosec G703 -- path derives from backupRoot() and a validSystemUser-checked identifier.
	_ = os.MkdirAll(dir, 0700)
	stamp := time.Now().UTC().Format("20060102-150405")
	suffix := ""
	if backupType == "scheduled" {
		suffix = "-auto"
	}
	file := fmt.Sprintf("%s%s-%s.tar.gz", systemUser, suffix, stamp)
	size, failedDBs, err := buildArchive(ctx, db, domainID, systemUser, dir, file, time.Now().UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		return 0, "", err
	}
	var job any
	if jobID > 0 {
		job = jobID
	}
	abs := filepath.Join(dir, file)
	// The checksum is stored when the backup is written; the integrity scan
	// re-computes it later to catch bit-rot. A hash error is not fatal: the
	// backup exists, it just cannot be integrity-checked, so verification stays ''.
	sum, verification := "", ""
	if s, e := fileSHA256(abs); e == nil {
		sum, verification = s, "ok"
	}
	res, err := db.Exec(
		`INSERT INTO backups(domain_id, type, file, size_b, notes, job_id, sha256, verification) VALUES(?,?,?,?,?,?,?,?)`,
		domainID, backupType, file, size, backupNotes(notes, failedDBs), job, sum, verification)
	if err != nil {
		return size, file, err
	}
	backupID, _ := res.LastInsertId()
	// The scheduler counts this run as succeeded, so without an alert a domain can
	// accumulate weeks of file-only backups with nothing saying its database was
	// never captured.
	notifyDumpsFailed(ctx, db, domainID, backupID, failedDBs)
	pushToDestinationAsync(db, domainID, backupID, abs, file)
	// Also copy to the system-wide off-site destination, if one is configured.
	// This is the shared core, so the scheduler, bulk jobs and a manual backup all
	// reach it; the two uploads are independent.
	pushGlobalAsync(db, domainID, backupID, abs, file)
	return size, file, nil
}

// restoreCore applies one backup in a coarse mode (full, files, database). It is the
// non-HTTP path used by multi-domain restore jobs; per-file and per-database selection
// stays on the single-domain restore endpoint.
func restoreCore(ctx context.Context, db *sql.DB, domainID, backupID int64, mode string, clean bool) (string, error) {
	// Held for the whole restore. rsync -a (with --delete on a clean restore)
	// rewrites the tree a concurrent backup would be reading, and the SQL import
	// lands in a schema a second restore would be importing into as well.
	release, ok := lockDomain(domainID)
	if !ok {
		return "", ErrDomainBusy
	}
	defer release()

	var systemUser, file, verification string
	var isDemo int
	err := db.QueryRowContext(ctx,
		`SELECT d.system_user, d.is_demo, b.file, COALESCE(b.verification,'') FROM backups b
		 JOIN domains d ON d.id=b.domain_id WHERE b.id=? AND b.domain_id=?`, backupID, domainID).
		Scan(&systemUser, &isDemo, &file, &verification)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("backup not found")
	}
	if err != nil {
		return "", fmt.Errorf("backup lookup failed")
	}
	if isDemo == 1 {
		return "", fmt.Errorf("restore is unavailable for demo subscriptions")
	}
	// A bulk job carries no per-item override, so an archive the integrity scan
	// recorded as corrupt is refused outright here. The single-domain endpoint is
	// where an operator confirms one deliberately.
	if verification == "corrupt" {
		return "", fmt.Errorf("this backup is recorded as corrupt; restore it from the domain's own backup page to confirm that")
	}
	if !validSystemUser(systemUser) || file == "" || filepath.Base(file) != file {
		return "", fmt.Errorf("invalid backup file")
	}
	// Fetch the archive from the off-site destination when the local copy was
	// pruned or removed, so a backup that uploaded successfully stays restorable.
	if err := ensureLocalArchive(ctx, db, domainID, backupID, systemUser, file); err != nil {
		return "", err
	}
	abs := filepath.Join(backupRoot(), systemUser, file)
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
		restored, _, failed, summary := dbSummary(restoreAllDBs(ctx, db, domainID, tmpDir, systemUser, ""))
		if failed > 0 {
			return "", fmt.Errorf("files were restored but %d database import(s) failed — %s", failed, summary)
		}
		// The test is on `restored` alone, never on `skipped > 0`: an archive that
		// carried no dump at all reports skipped=0 too, so that guard passed a
		// recovery in which nothing the site connects to came back, and the bulk
		// job counted the domain in `succeeded`.
		if restored == 0 {
			return "", fmt.Errorf("files were restored but no database was restored — %s", summary)
		}
		return fmt.Sprintf("restored files and %d database(s)", restored), nil
	case "files":
		if err := restoreHome(ctx, tmpDir, systemUser, clean); err != nil {
			return "", fmt.Errorf("the home directory could not be restored")
		}
		return "restored files", nil
	case "database":
		restored, skipped, failed, summary := dbSummary(restoreAllDBs(ctx, db, domainID, tmpDir, systemUser, ""))
		if failed > 0 {
			return "", fmt.Errorf("%d database import(s) failed — %s", failed, summary)
		}
		// Zero databases restored is not success. Previously this returned
		// "restored databases" even when the whitelist was empty and every database
		// was skipped, so the job read as done with nothing restored.
		if restored == 0 {
			if skipped == 0 {
				return "", fmt.Errorf("the backup has no database to restore")
			}
			return "", fmt.Errorf("no database was restored — %s", summary)
		}
		return fmt.Sprintf("restored %d database(s)", restored), nil
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
		if err := rows.Scan(&d.ID, &d.SystemUser, &d.DomainName); err != nil {
			// A dropped row is a domain the bulk job never touches while its total
			// says it did.
			log.Printf("backups: skipping an unreadable job domain row: %v", err)
			continue
		}
		// A name that fails the identifier rule is refused rather than dropped in
		// silence, because every path below builds a filesystem path from it.
		if !validSystemUser(d.SystemUser) {
			log.Printf("backups: refusing a job domain with an invalid system user: domain %d", d.ID)
			continue
		}
		out = append(out, d)
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

// finishJobStopped closes a job, recording 'stopped' when the operator stopped it
// so the UI can tell a stopped run apart from a failed one.
//
// Every bulk job goes through this one function. The wrapper that dropped the
// stopped flag went with the last caller that could not be stopped: a run whose
// tallies say "done" because it was cut short after two clean domains would
// otherwise be indistinguishable from one that finished.
func finishJobStopped(db *sql.DB, jobID int64, succeeded, failed int, stopped bool) {
	status := jobStatus(succeeded, failed)
	if stopped {
		status = "stopped"
	}
	if _, err := db.Exec(
		`UPDATE backup_jobs SET status=?, active_domain='', finished_at=NOW() WHERE id=?`,
		status, jobID); err != nil {
		log.Printf("backup job %d: could not close: %v", jobID, err)
	}
}

// failJob closes a job row after a panic. The counters live inside the goroutine
// that died, so only the status is corrected here: what matters is that the row
// stops saying "running", which is what would otherwise block a second attempt
// until the next restart heals it.
func failJob(db *sql.DB, jobID int64) {
	if _, err := db.Exec(
		`UPDATE backup_jobs SET status='failed', active_domain='', finished_at=NOW() WHERE id=?`,
		jobID); err != nil {
		log.Printf("backup job %d: could not close after a panic: %v", jobID, err)
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

	jobCtx, jobCancel := context.WithCancel(context.Background())
	registerJob(jobID, jobCancel)
	// #nosec G118 -- intentional detached context: the job outlives the request, which would otherwise cancel it mid-archive.
	bgjob.Go("backups: bulk backup job", func(error) { failJob(h.DB, jobID) }, func() {
		defer func() {
			jobCancel()
			unregisterJob(jobID)
		}()
		var totalBytes int64
		succeeded, failed := 0, 0
		stopped := false
		for _, d := range domains {
			// Check for a stop BETWEEN domains: the domain in flight is killed by
			// its own context, and the remaining ones are never started.
			if jobCtx.Err() != nil {
				stopped = true
				break
			}
			if _, err := h.DB.Exec(`UPDATE backup_jobs SET active_domain=? WHERE id=?`, d.DomainName, jobID); err != nil {
				httpx.LogR(r, "backup job %d: progress update failed: %v", jobID, err)
			}
			ctx, cancel := context.WithTimeout(jobCtx, 20*time.Minute)
			size, _, err := backupOneDomain(ctx, h.DB, d.ID, d.SystemUser, "full", "Bulk backup", jobID)
			cancel()
			if err != nil {
				if jobCtx.Err() != nil {
					// The failure came from the stop, not the backup: do not count it.
					stopped = true
					break
				}
				failed++
				httpx.LogR(r, "backup job %d: domain %d failed: %v", jobID, d.ID, err)
				// The one event that means this domain has no recovery point from
				// this run. Without this it reached nothing but the log and a
				// partial job row nobody reads.
				notifyBackupFailed(jobCtx, h.DB, d.ID, err.Error())
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
				httpx.LogR(r, "backup job %d: progress update failed: %v", jobID, err)
			}
		}
		finishJobStopped(h.DB, jobID, succeeded, failed, stopped)
	})

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
		if err := rows.Scan(&it.BackupID, &it.DomainID, &it.DomainName, &it.SystemUser, &it.SizeBytes, &it.Type); err != nil {
			httpx.LogR(r, "backups: skipping an unreadable job item row: %v", err)
			continue
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		// A short item list beside the job's own counts reads as a job that
		// produced fewer archives than it did.
		httpx.WriteError(w, http.StatusInternalServerError, "job detail read failed")
		return
	}
	resp["domains"] = items
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// StopJob handles POST /admin/backups/jobs/{jid}/stop and stops a running bulk
// job. The domain in flight is killed by its context, the remaining ones are
// never started, and the job closes as 'stopped'.
//
// The caller must be allowed to see the job, exactly like the list, so a reseller
// cannot stop a job that is not theirs. A job left running by a panel restart is
// not registered; the row is closed as 'failed' so the UI stops showing it in
// progress.
func (h *Handlers) StopJob(w http.ResponseWriter, r *http.Request) {
	jobID, _ := strconv.ParseInt(chi.URLParam(r, "jid"), 10, 64)
	// The scope filter is a READ filter and cannot serve as the write guard on its
	// own. It shows a reseller the server-wide nightly job because that job
	// archived one of their domains, and stopping it would end the backup of every
	// other tenant on the host. Stopping is reserved to an admin and to whoever
	// started the job.
	filter, args := jobScopeFilter(r, "j")
	q := `SELECT status, started_by FROM backup_jobs j WHERE j.id=?`
	scopedArgs := append([]any{jobID}, args...)
	if filter != "" {
		q += ` AND` + filter
	}
	var status, startedBy string
	// #nosec G701 G202 -- filter is a constant fragment built from ScopeSQL with a literal alias; every value is bound.
	err := h.DB.QueryRowContext(r.Context(), q, scopedArgs...).Scan(&status, &startedBy)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "backup job not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if !mayStopJob(r, startedBy) {
		httpx.WriteError(w, http.StatusForbidden, "only the operator who started this job may stop it")
		return
	}
	if status != "running" {
		httpx.WriteError(w, http.StatusConflict, "the job is not running")
		return
	}
	if !stopJob(jobID) {
		// Not registered: a restart left it hung. Close the row as failed. Every
		// job this panel starts registers itself, so a running row with no cancel
		// function belongs to a process that is gone.
		if _, err := h.DB.Exec(
			`UPDATE backup_jobs SET status='failed', active_domain='', finished_at=NOW()
			 WHERE id=? AND status='running'`, jobID); err != nil {
			httpx.LogR(r, "backup job %d: could not close hung job: %v", jobID, err)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// mayStopJob reports whether the caller may end this job.
//
// Seeing a job and ending it are different questions. jobScopeFilter answers the
// first, and it deliberately shows a reseller a job that produced one archive of
// a domain they own; the nightly pass over every tenant on the host qualifies.
// Ending that is not a decision one of its subjects gets to make.
func mayStopJob(r *http.Request, startedBy string) bool {
	c := middleware.ClaimsFrom(r)
	if c == nil {
		return false
	}
	return c.Role == middleware.RoleAdmin || c.Username == startedBy
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

	jobCtx, jobCancel := context.WithCancel(context.Background())
	registerJob(jobID, jobCancel)
	// #nosec G118 -- intentional detached context: the job outlives the request, which would otherwise cancel it mid-restore.
	bgjob.Go("backups: bulk restore job", func(error) { failJob(h.DB, jobID) }, func() {
		defer func() {
			jobCancel()
			unregisterJob(jobID)
		}()
		type result struct {
			DomainID   int64  `json:"domain_id"`
			DomainName string `json:"domain_name"`
			Status     string `json:"status"`
			Message    string `json:"message"`
		}
		results := []result{}
		succeeded, failed := 0, 0
		stopped := false
		for _, it := range items {
			if jobCtx.Err() != nil {
				stopped = true
				break
			}
			if _, err := h.DB.Exec(`UPDATE backup_jobs SET active_domain=? WHERE id=?`, it.domainName, jobID); err != nil {
				httpx.LogR(r, "restore job %d: progress update failed: %v", jobID, err)
			}
			ctx, cancel := context.WithTimeout(jobCtx, 30*time.Minute)
			message, err := restoreCore(ctx, h.DB, it.domainID, it.backupID, req.Mode, req.Clean)
			cancel()
			if err != nil && jobCtx.Err() != nil {
				stopped = true
				break
			}
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
				httpx.LogR(r, "restore job %d: progress update failed: %v", jobID, err)
			}
		}
		finishJobStopped(h.DB, jobID, succeeded, failed, stopped)
	})

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"ok": true, "job_id": jobID, "total": len(items)})
}
