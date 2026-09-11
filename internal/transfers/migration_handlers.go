package transfers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"servika/internal/auth"
	"servika/internal/config"
	"servika/internal/httpx"
	"servika/internal/middleware"
	"servika/internal/secret"
)

// Only ONE migration job runs at a time: rsync and mysqldump are heavy, and in
// parallel they would drown the server and race on the same system user.
//
// reservedSlot marks the slot as taken before the job record exists.
const reservedSlot int64 = -1

var (
	migrationMu     sync.Mutex
	activeJobID     int64
	activeJobCancel context.CancelFunc
)

func migrationLogPath(jobID int64) string {
	return filepath.Join(config.LogDir(), fmt.Sprintf("migration-%d.log", jobID))
}

// ---------------------------------------------------------------------------
// Connection test + discovery
// ---------------------------------------------------------------------------

type sourceInput struct {
	Type     string `json:"type"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Key      string `json:"key"`
}

func (in sourceInput) source() *RemoteSource {
	port := in.Port
	if port == 0 {
		port = 22
	}
	return &RemoteSource{
		Type: strings.ToLower(strings.TrimSpace(in.Type)), Host: in.Host, Port: port,
		User: in.User, Password: in.Password, Key: in.Key,
	}
}

// MigrationTest handles POST /admin/migrations/test.
func (h *Handlers) MigrationTest(w http.ResponseWriter, r *http.Request) {
	var in sourceInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	source := in.source()
	if err := source.Validate(); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	name, err := source.TestConnection(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "could not connect: "+err.Error())
		return
	}
	detected, _ := source.DetectPanel(r.Context())
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": true, "server_name": name, "detected": detected,
		"matches": detected == source.Type,
	})
}

// MigrationDiscover handles POST /admin/migrations/discover.
func (h *Handlers) MigrationDiscover(w http.ResponseWriter, r *http.Request) {
	var in sourceInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	source := in.source()
	if err := source.Validate(); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	accounts, err := source.Discover(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "discovery failed: "+err.Error())
		return
	}
	// Flag the accounts that already exist on this server.
	type entry struct {
		RemoteAccount
		Exists bool `json:"exists"`
	}
	out := make([]entry, 0, len(accounts))
	for _, account := range accounts {
		var n int
		_ = h.DB.QueryRow(`SELECT COUNT(*) FROM domains WHERE domain_name=?`, account.DomainName).Scan(&n)
		out = append(out, entry{RemoteAccount: account, Exists: n > 0})
	}
	// Persist the session so a reload resumes without re-entering the server
	// details, the credentials, or re-running discovery. Best-effort: a failure
	// returns id 0 and discovery still answers.
	discoveryJSON, _ := json.Marshal(out)
	startedBy := ""
	if claims := middleware.ClaimsFrom(r); claims != nil {
		startedBy = claims.Username
	}
	sessionID := h.saveSession(source, discoveryJSON, startedBy)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"accounts": out, "total": len(out), "session_id": sessionID,
	})
}

// ---------------------------------------------------------------------------
// Starting a job
// ---------------------------------------------------------------------------

type startInput struct {
	sourceInput
	SessionID int64             `json:"session_id"` // resume a saved session's stored credentials
	Mode      string            `json:"mode"`       // single | bulk
	Settings  MigrationSettings `json:"settings"`
	Selected  []RemoteAccount   `json:"selected"` // accounts the operator picked after discovery
}

// MigrationStart handles POST /admin/migrations.
func (h *Handlers) MigrationStart(w http.ResponseWriter, r *http.Request) {
	// Reserve the slot ATOMICALLY: releasing the lock between the check and the
	// assignment (JSON decode + encryption + insert time) would let two requests
	// through and run two rsync/import passes against the SAME target.
	migrationMu.Lock()
	if activeJobID != 0 {
		migrationMu.Unlock()
		httpx.WriteError(w, http.StatusConflict, "a migration job is already running")
		return
	}
	activeJobID = reservedSlot
	migrationMu.Unlock()

	// Every error path must release the reservation.
	reserved := true
	release := func() {
		if !reserved {
			return
		}
		reserved = false
		migrationMu.Lock()
		if activeJobID == reservedSlot {
			activeJobID = 0
		}
		migrationMu.Unlock()
	}
	defer release()

	in, source, valid, ok := h.readStartRequest(w, r)
	if !ok {
		return
	}
	jobID, ok := h.recordMigrationJob(w, r, in, source, valid)
	if !ok {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	migrationMu.Lock()
	activeJobID, activeJobCancel = jobID, cancel
	migrationMu.Unlock()
	reserved = false // a real job id holds the slot now; the deferred release must not clear it

	// The session is consumed: the job now holds the credentials in migration_jobs
	// (encrypted, host-bound), so the resumable session is no longer needed.
	if in.SessionID > 0 {
		_, _ = h.DB.Exec(`DELETE FROM migration_sessions WHERE id=?`, in.SessionID)
	}

	go runMigration(h, ctx, jobID, source, valid, in.Settings)

	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"job_id": jobID, "total": len(valid)})
}

// readStartRequest decodes a start request, opens a saved session's credentials
// when none were typed, validates the source and keeps the valid accounts. It
// writes the refusal itself and returns false when the request cannot start a job.
func (h *Handlers) readStartRequest(w http.ResponseWriter, r *http.Request) (startInput, *RemoteSource, []RemoteAccount, bool) {
	var in startInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&in); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return in, nil, nil, false
	}
	source := in.source()
	// Resume a saved session: when the operator did not re-type the credentials,
	// decrypt the stored ones SERVER-SIDE. The password never travelled back to
	// the browser, so this is the only place it re-enters the flow.
	if source.Password == "" && source.Key == "" && in.SessionID > 0 {
		pass, key, err := h.loadSessionCredentials(r.Context(), in.SessionID, source.Host)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "the saved credentials could not be used: "+err.Error())
			return in, nil, nil, false
		}
		source.Password, source.Key = pass, key
	}
	if err := source.Validate(); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return in, nil, nil, false
	}
	valid, ok := selectedAccounts(w, in.Selected)
	return in, source, valid, ok
}

// selectedAccounts keeps the picked accounts whose domain and account name pass
// the allowlist. It writes the refusal itself and returns false when the
// selection is empty, too large, or holds no valid account.
func selectedAccounts(w http.ResponseWriter, selected []RemoteAccount) ([]RemoteAccount, bool) {
	if len(selected) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "no account was selected")
		return nil, false
	}
	if len(selected) > 500 {
		httpx.WriteError(w, http.StatusBadRequest, "at most 500 sites can be migrated at once")
		return nil, false
	}
	// Filter the accounts again — this is remote-sourced data.
	var valid []RemoteAccount
	for _, account := range selected {
		account.DomainName = strings.ToLower(strings.TrimSpace(account.DomainName))
		if !reRemoteDomain.MatchString(account.DomainName) || !strings.Contains(account.DomainName, ".") {
			continue
		}
		if account.SourceAccount != "" && !reRemoteAccount.MatchString(account.SourceAccount) {
			continue
		}
		valid = append(valid, account)
	}
	if len(valid) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "no valid account was found")
		return nil, false
	}
	return valid, true
}

// recordMigrationJob seals the credentials, writes the job and one item per
// account, and audits the start. It writes the refusal itself and returns false
// when the job record cannot be created.
func (h *Handlers) recordMigrationJob(w http.ResponseWriter, r *http.Request, in startInput, source *RemoteSource, valid []RemoteAccount) (int64, bool) {
	mode := "bulk"
	if in.Mode == "single" || len(in.Selected) == 1 {
		mode = "single"
	}
	settingsJSON, _ := json.Marshal(in.Settings)
	claims := middleware.ClaimsFrom(r)
	var actorID int64
	actor := ""
	if claims != nil {
		actorID, actor = claims.UserID, claims.Username
	}

	encryptedPassword, encryptedKey, err := sealSourceCredentials(source)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the credentials could not be stored")
		return 0, false
	}

	res, err := h.DB.Exec(
		`INSERT INTO migration_jobs(source_type, source_host, source_port, source_user,
		   source_password, source_key, mode, status, total, settings, started_by, started_at)
		 VALUES(?,?,?,?,?,?,?, 'running', ?, ?, ?, NOW())`,
		source.Type, source.Host, source.Port, source.User, encryptedPassword, encryptedKey,
		mode, len(valid), string(settingsJSON), actor)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the job record could not be created")
		return 0, false
	}
	jobID, _ := res.LastInsertId()

	for _, account := range valid {
		_, _ = h.DB.Exec(
			`INSERT INTO migration_items(job_id, source_account, domain_name, status)
			 VALUES(?,?,?, 'pending')`, jobID, account.SourceAccount, account.DomainName)
	}

	auth.WriteAudit(h.DB, actorID, actor, httpx.AuditIP(r), "migration.start",
		fmt.Sprintf("%s@%s (%d sites)", source.Type, source.Host, len(valid)), true)
	return jobID, true
}

// sealSourceCredentials encrypts the password and the key for storage. An empty
// credential stays empty.
func sealSourceCredentials(source *RemoteSource) (string, string, error) {
	// Credentials are encrypted at rest, bound to the host so a stolen row
	// cannot be replayed against a different server.
	encryptedPassword := ""
	if source.Password != "" {
		v, err := secret.EncryptWith(source.Password, source.Host)
		if err != nil {
			return "", "", err
		}
		encryptedPassword = v
	}
	encryptedKey := ""
	if source.Key != "" {
		v, err := secret.EncryptWith(source.Key, source.Host)
		if err != nil {
			return "", "", err
		}
		encryptedKey = v
	}
	return encryptedPassword, encryptedKey, nil
}

// runMigrationJob is the job runner goroutine.
func (h *Handlers) runMigrationJob(ctx context.Context, jobID int64, source *RemoteSource,
	accounts []RemoteAccount, settings MigrationSettings) {

	defer h.closeMigrationJob(jobID, source)

	logf, closeLog := openMigrationLog(jobID)
	defer closeLog()

	logf("migration started — source %s (%s), %d site(s)", source.Host, source.Type, len(accounts))

	var done, failed int
	for i, account := range accounts {
		select {
		case <-ctx.Done():
			logf("CANCELLED — %d remaining site(s) skipped", len(accounts)-i)
			_, _ = h.DB.Exec(`UPDATE migration_jobs SET status='cancelled', finished_at=NOW() WHERE id=?`, jobID)
			return
		default:
		}

		logf("-------- [%d/%d] %s --------", i+1, len(accounts), account.DomainName)
		_, _ = h.DB.Exec(
			`UPDATE migration_items SET status='running', started_at=NOW() WHERE job_id=? AND domain_name=?`,
			jobID, account.DomainName)

		result, err := migrateAccount(h, ctx, source, account, settings, logf)
		if err != nil && ctx.Err() != nil {
			// When the cancellation lands during the last account the loop never
			// returns to its ctx check, so the job used to close as 'failed' with
			// an EMPTY message.
			logf("CANCELLED — %s was interrupted", account.DomainName)
			_, _ = h.DB.Exec(
				`UPDATE migration_items SET status='skipped', error_text='cancelled by the operator',
				   finished_at=NOW() WHERE job_id=? AND domain_name=?`,
				jobID, account.DomainName)
			_, _ = h.DB.Exec(`UPDATE migration_jobs SET status='cancelled', finished_at=NOW() WHERE id=?`, jobID)
			return
		}
		if err != nil {
			failed++
			logf("ERROR: %s -> %v", account.DomainName, err)
			_, _ = h.DB.Exec(
				`UPDATE migration_items SET status='failed', error_text=?, finished_at=NOW()
				 WHERE job_id=? AND domain_name=?`,
				truncate(err.Error(), 500), jobID, account.DomainName)
		} else {
			done++
			warning := ""
			if len(result.Warnings) > 0 {
				warning = " | warning: " + strings.Join(result.Warnings, "; ")
			}
			logf("DONE: %s (%.1f MB, %d DB, %d DNS, %d mail)%s", account.DomainName,
				float64(result.FileBytes)/(1024*1024), result.DBCount, result.DNSCount, result.MailCount, warning)
			_, _ = h.DB.Exec(
				`UPDATE migration_items SET status='done', domain_id=?, file_bytes=?, db_count=?,
				   dns_count=?, mail_count=?, error_text=NULLIF(?,''), finished_at=NOW()
				 WHERE job_id=? AND domain_name=?`,
				result.DomainID, result.FileBytes, result.DBCount, result.DNSCount, result.MailCount,
				strings.Join(result.Warnings, "; "), jobID, account.DomainName)
		}
		_, _ = h.DB.Exec(`UPDATE migration_jobs SET completed=?, failed=? WHERE id=?`, done, failed, jobID)
	}

	status := "done"
	if failed > 0 && done == 0 {
		status = "failed"
	}
	logf("migration finished — %d succeeded, %d failed", done, failed)
	_, _ = h.DB.Exec(
		`UPDATE migration_jobs SET status=?, completed=?, failed=?, finished_at=NOW() WHERE id=?`,
		status, done, failed, jobID)
}

// closeMigrationJob runs when the job runner returns or panics. It is deferred
// directly so its recover sees the panic: a panic is recorded as the job's
// failure, then the slot is freed and the credentials are cleared.
func (h *Handlers) closeMigrationJob(jobID int64, source *RemoteSource) {
	if rec := recover(); rec != nil {
		// A panic value can carry a line break, which would forge a second
		// log line; sanitizeRemoteError collapses it to one line.
		detail := sanitizeRemoteError(fmt.Sprintf("%v", rec))
		// #nosec G706 -- sanitizeRemoteError already replaces every CR and LF with a space, so the value cannot forge a log line.
		log.Printf("migration: panic (job=%d): %s", jobID, detail)
		_, _ = h.DB.Exec(
			`UPDATE migration_jobs SET status='failed', error_text=?, finished_at=NOW() WHERE id=?`,
			"unexpected error: "+detail, jobID)
	}
	migrationMu.Lock()
	activeJobID, activeJobCancel = 0, nil
	migrationMu.Unlock()
	// Clear the credentials from the database — the job is over.
	_, _ = h.DB.Exec(
		`UPDATE migration_jobs SET source_password=NULL, source_key=NULL, credentials_cleared=1 WHERE id=?`,
		jobID)
	source.Password, source.Key = "", ""
}

// openMigrationLog opens the job's log file and returns the line writer and the
// function that closes the file. A log that cannot be opened is reported once,
// and its lines are dropped.
func openMigrationLog(jobID int64) (func(string, ...any), func()) {
	_ = os.MkdirAll(config.LogDir(), 0o750)
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	logFile, err := os.OpenFile(migrationLogPath(jobID), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		log.Printf("migration: the log file could not be opened: %v", err)
	}
	logf := func(format string, args ...any) {
		line := fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
		if logFile != nil {
			_, _ = logFile.WriteString(line)
			_ = logFile.Sync()
		}
	}
	closeLog := func() {
		if logFile != nil {
			_ = logFile.Close()
		}
	}
	return logf, closeLog
}

// ---------------------------------------------------------------------------
// Status / list / log / cancel
// ---------------------------------------------------------------------------

// MigrationList handles GET /admin/migrations (recent jobs + the active one).
func (h *Handlers) MigrationList(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(
		`SELECT id, source_type, source_host, mode, status, total, completed, failed,
		        COALESCE(error_text,''), COALESCE(started_by,''), started_at, finished_at, created_at
		 FROM migration_jobs ORDER BY id DESC LIMIT 25`)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the jobs could not be read")
		return
	}
	defer func() { _ = rows.Close() }()
	type job struct {
		ID         int64      `json:"id"`
		Type       string     `json:"type"`
		Host       string     `json:"host"`
		Mode       string     `json:"mode"`
		Status     string     `json:"status"`
		Total      int        `json:"total"`
		Completed  int        `json:"completed"`
		Failed     int        `json:"failed"`
		Error      string     `json:"error_text"`
		StartedBy  string     `json:"started_by"`
		StartedAt  *time.Time `json:"started_at"`
		FinishedAt *time.Time `json:"finished_at"`
		CreatedAt  time.Time  `json:"created_at"`
	}
	out := []job{}
	for rows.Next() {
		var v job
		if err := rows.Scan(&v.ID, &v.Type, &v.Host, &v.Mode, &v.Status, &v.Total,
			&v.Completed, &v.Failed, &v.Error, &v.StartedBy, &v.StartedAt, &v.FinishedAt, &v.CreatedAt); err != nil {
			// A dropped row hides a migration job from the only screen that lists
			// them, including one still marked running.
			httpx.LogR(r, "migrations: skipping an unreadable job row: %v", err)
			continue
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "migration job list failed")
		return
	}
	migrationMu.Lock()
	active := activeJobID
	migrationMu.Unlock()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"jobs": out, "active_job": active})
}

// MigrationDetail handles GET /admin/migrations/{id}.
func (h *Handlers) MigrationDetail(w http.ResponseWriter, r *http.Request) {
	jobID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || jobID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid job")
		return
	}
	rows, err := h.DB.Query(
		`SELECT id, source_account, domain_name, status, COALESCE(domain_id,0),
		        file_bytes, db_count, dns_count, mail_count, COALESCE(error_text,''), started_at, finished_at
		 FROM migration_items WHERE job_id=? ORDER BY id`, jobID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the items could not be read")
		return
	}
	defer func() { _ = rows.Close() }()
	type item struct {
		ID            int64      `json:"id"`
		SourceAccount string     `json:"source_account"`
		DomainName    string     `json:"domain_name"`
		Status        string     `json:"status"`
		DomainID      int64      `json:"domain_id"`
		FileBytes     int64      `json:"file_bytes"`
		DBCount       int        `json:"db_count"`
		DNSCount      int        `json:"dns_count"`
		MailCount     int        `json:"mail_count"`
		Error         string     `json:"error_text"`
		StartedAt     *time.Time `json:"started_at"`
		FinishedAt    *time.Time `json:"finished_at"`
	}
	out := []item{}
	for rows.Next() {
		var v item
		if err := rows.Scan(&v.ID, &v.SourceAccount, &v.DomainName, &v.Status, &v.DomainID,
			&v.FileBytes, &v.DBCount, &v.DNSCount, &v.MailCount, &v.Error, &v.StartedAt, &v.FinishedAt); err != nil {
			// A dropped item beside the job's own counts reads as a migration that
			// moved sites it did not, and a failed item disappears with it.
			httpx.LogR(r, "migrations: skipping an unreadable item row: %v", err)
			continue
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		// A short item list beside a "completed" count is the worst shape this
		// screen can take: the migration reads as having moved sites it did not.
		httpx.WriteError(w, http.StatusInternalServerError, "migration detail read failed")
		return
	}
	var status string
	var total, completed, failed int
	_ = h.DB.QueryRow(
		`SELECT status, total, completed, failed FROM migration_jobs WHERE id=?`, jobID).
		Scan(&status, &total, &completed, &failed)
	migrationMu.Lock()
	running := activeJobID == jobID
	migrationMu.Unlock()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"items": out, "status": status, "total": total,
		"completed": completed, "failed": failed, "running": running,
	})
}

// MigrationLog handles GET /admin/migrations/{id}/log.
func (h *Handlers) MigrationLog(w http.ResponseWriter, r *http.Request) {
	jobID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || jobID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid job")
		return
	}
	text := tailFile(migrationLogPath(jobID), 120<<10)
	migrationMu.Lock()
	running := activeJobID == jobID
	migrationMu.Unlock()
	var status string
	_ = h.DB.QueryRow(`SELECT status FROM migration_jobs WHERE id=?`, jobID).Scan(&status)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"log": text, "running": running, "status": status,
	})
}

// MigrationCancel handles POST /admin/migrations/{id}/cancel.
func (h *Handlers) MigrationCancel(w http.ResponseWriter, r *http.Request) {
	jobID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || jobID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid job")
		return
	}
	migrationMu.Lock()
	matched := activeJobID == jobID && activeJobCancel != nil
	if matched {
		activeJobCancel()
	}
	migrationMu.Unlock()
	if !matched {
		httpx.WriteError(w, http.StatusNotFound, "this job is not running")
		return
	}
	claims := middleware.ClaimsFrom(r)
	var actorID int64
	actor := ""
	if claims != nil {
		actorID, actor = claims.UserID, claims.Username
	}
	auth.WriteAudit(h.DB, actorID, actor, httpx.AuditIP(r), "migration.cancel",
		strconv.FormatInt(jobID, 10), true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// HealMigrationsOnStartup closes jobs that a panel restart left half done and
// clears their stored credentials. main.go calls it at boot.
func (h *Handlers) HealMigrationsOnStartup() {
	res, err := h.DB.Exec(
		`UPDATE migration_jobs SET status='interrupted', error_text='the panel was restarted',
		   finished_at=NOW()
		 WHERE status IN ('running','discovery')`)
	if err != nil {
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("migration: %d unfinished job(s) marked as interrupted", n)
		_, _ = h.DB.Exec(
			`UPDATE migration_items SET status='failed', error_text='the panel was restarted',
			   finished_at=NOW() WHERE status='running'`)
	}
	// Security: clear the credentials of every finished job too.
	_, _ = h.DB.Exec(
		`UPDATE migration_jobs SET source_password=NULL, source_key=NULL, credentials_cleared=1
		 WHERE status IN ('done','failed','cancelled','interrupted') AND credentials_cleared=0`)
	// Drop the migration sessions whose TTL has passed. Their credentials are
	// sealed, but an expired session is dead weight and must not be resumable.
	_, _ = h.DB.Exec(`DELETE FROM migration_sessions WHERE expires_at <= NOW()`)
}

// tailFile safely reads the last n bytes of a file (symlinks and special files
// are rejected).
func tailFile(path string, n int64) string {
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return ""
	}
	if size := st.Size(); size > n {
		if _, err := f.Seek(size-n, 0); err != nil {
			return ""
		}
	}
	buf := make([]byte, n)
	read, _ := f.Read(buf)
	if read <= 0 {
		return ""
	}
	return string(buf[:read])
}
