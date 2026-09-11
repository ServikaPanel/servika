package transfers

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"servika/internal/auth"
	"servika/internal/secret"
)

func setSlot(id int64, cancel context.CancelFunc) {
	migrationMu.Lock()
	defer migrationMu.Unlock()
	if activeJobCancel != nil {
		activeJobCancel()
	}
	activeJobID, activeJobCancel = id, cancel
}

func slotHolder() int64 {
	migrationMu.Lock()
	defer migrationMu.Unlock()
	return activeJobID
}

// freeSlot empties the migration job slot for one test and empties it again
// after the test.
func freeSlot(t *testing.T) {
	t.Helper()
	setSlot(0, nil)
	t.Cleanup(func() { setSlot(0, nil) })
}

type startedJob struct {
	jobID    int64
	source   RemoteSource
	accounts []RemoteAccount
	settings MigrationSettings
}

// withStartedJobs replaces the job runner with one that reports what it was
// started with.
func withStartedJobs(t *testing.T) chan startedJob {
	t.Helper()
	started := make(chan startedJob, 1)
	setForTest(t, &runMigration, func(_ *Handlers, _ context.Context, jobID int64, source *RemoteSource, accounts []RemoteAccount, settings MigrationSettings) {
		started <- startedJob{jobID: jobID, source: *source, accounts: accounts, settings: settings}
	})
	return started
}

func receiveJob(t *testing.T, started chan startedJob) startedJob {
	t.Helper()
	select {
	case job := <-started:
		return job
	case <-time.After(5 * time.Second):
		t.Fatal("the job runner was not started")
		return startedJob{}
	}
}

func claimedRequest(r *http.Request) *http.Request {
	return r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{UserID: 1, Username: "admin"}))
}

func startRequest(t *testing.T, in map[string]any) *http.Request {
	t.Helper()
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return claimedRequest(httptest.NewRequest(http.MethodPost, "/admin/migrations", bytes.NewReader(body)))
}

// startWith is a valid start request for one account, with changes applied.
func startWith(changes map[string]any) map[string]any {
	in := map[string]any{
		"type": "cpanel", "host": "src.example.com", "port": 22, "user": "root", "password": "pw-secret",
		"selected": []map[string]string{{"source_account": "acme", "domain_name": "example.com"}},
	}
	maps.Copy(in, changes)
	return in
}

func initSecret(t *testing.T) {
	t.Helper()
	if err := secret.Init([]byte("test-key-that-is-long-enough-32b!")); err != nil {
		t.Fatalf("secret init: %v", err)
	}
}

func assertSlotFree(t *testing.T, started chan startedJob) {
	t.Helper()
	if slotHolder() != 0 || len(started) != 0 {
		t.Fatalf("slot %d, started jobs %d", slotHolder(), len(started))
	}
}

// A second job is refused while one holds the slot, and the holder keeps it.
func TestMigrationStartRefusesWhileAJobRuns(t *testing.T) {
	freeSlot(t)
	setSlot(5, nil)
	w := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, newScript())}).MigrationStart(w, startRequest(t, startWith(nil)))
	assertResponse(t, w, http.StatusConflict, "a migration job is already running")
	if slotHolder() != 5 {
		t.Fatalf("slot = %d, want 5", slotHolder())
	}
}

// Every refusal answers its reason and gives the reserved slot back.
func TestMigrationStartRefusals(t *testing.T) {
	initSecret(t)
	many := make([]map[string]string, 501)
	for i := range many {
		many[i] = map[string]string{"domain_name": "example.com"}
	}
	noScript := func(*sqlScript) {}
	cases := []struct {
		name     string
		request  func(*testing.T) *http.Request
		breaks   func(*sqlScript)
		status   int
		fragment string
	}{
		{"a body that is not JSON", func(*testing.T) *http.Request {
			return claimedRequest(httptest.NewRequest(http.MethodPost, "/admin/migrations", strings.NewReader("{")))
		}, noScript, http.StatusBadRequest, "invalid request"},
		{"a saved session that is gone", func(t *testing.T) *http.Request {
			return startRequest(t, startWith(map[string]any{"password": "", "session_id": 5}))
		}, func(s *sqlScript) { s.rows["FROM migration_sessions"] = [][]driver.Value{} }, http.StatusBadRequest,
			"the saved credentials could not be used: the migration session was not found or has expired"},
		{"an invalid source", func(t *testing.T) *http.Request {
			return startRequest(t, startWith(map[string]any{"type": "ispconfig"}))
		}, noScript, http.StatusBadRequest, "invalid source panel type"},
		{"no selected account", func(t *testing.T) *http.Request {
			return startRequest(t, startWith(map[string]any{"selected": []map[string]string{}}))
		}, noScript, http.StatusBadRequest, "no account was selected"},
		{"more than 500 accounts", func(t *testing.T) *http.Request {
			return startRequest(t, startWith(map[string]any{"selected": many}))
		}, noScript, http.StatusBadRequest, "at most 500 sites can be migrated at once"},
		{"no valid account", func(t *testing.T) *http.Request {
			return startRequest(t, startWith(map[string]any{"selected": []map[string]string{
				{"source_account": "-bad", "domain_name": "example.com"}, {"domain_name": "nodot"},
			}}))
		}, noScript, http.StatusBadRequest, "no valid account was found"},
		{"a job record the database refuses", func(t *testing.T) *http.Request {
			return startRequest(t, startWith(nil))
		}, func(s *sqlScript) { s.fail["INSERT INTO migration_jobs"] = errScripted }, http.StatusInternalServerError, "the job record could not be created"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			freeSlot(t)
			started := withStartedJobs(t)
			s := newScript()
			c.breaks(s)
			w := httptest.NewRecorder()
			(&Handlers{DB: scriptDB(t, s)}).MigrationStart(w, c.request(t))
			assertResponse(t, w, c.status, c.fragment)
			assertSlotFree(t, started)
		})
	}
}

func assertSealed(t *testing.T, value driver.Value, plain string) {
	t.Helper()
	sealed, _ := value.(string)
	got, err := secret.DecryptWith(sealed, "src.example.com")
	if !strings.HasPrefix(sealed, "enc:v1:") || err != nil || got != plain {
		t.Fatalf("stored credential %q opens to %q (%v), want %q", sealed, got, err, plain)
	}
}

// A start keeps only the valid accounts, stores the credentials sealed to the
// host, records one item per account, audits the start and hands the job to the
// runner, which then holds the slot.
func TestMigrationStartQueuesTheValidAccounts(t *testing.T) {
	initSecret(t)
	freeSlot(t)
	started := withStartedJobs(t)
	s := newScript()
	s.insertID = 42
	in := startWith(map[string]any{
		"key": "-----BEGIN KEY-----", "mode": "bulk",
		"settings": map[string]any{"files": true, "dns": true},
		"selected": []map[string]string{
			{"source_account": "acme", "domain_name": " Example.COM "},
			{"source_account": "-bad", "domain_name": "b.example.com"},
			{"domain_name": "nodot"},
			{"source_account": "acme", "domain_name": "shop.example.com"},
		},
	})
	w := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, s)}).MigrationStart(w, startRequest(t, in))

	assertResponse(t, w, http.StatusAccepted, `"job_id":42`)
	assertResponse(t, w, http.StatusAccepted, `"total":2`)
	job := s.onlyExec(t, "INSERT INTO migration_jobs")
	assertSealed(t, job.args[4], "pw-secret")
	assertSealed(t, job.args[5], "-----BEGIN KEY-----")
	const settings = `{"files":true,"databases":false,"dns":true,"ssl":false,"mail":false,"overwrite":false,"target_php":"","plan_id":0,"customer_id":0,"accounts":null}`
	plain := []driver.Value{job.args[0], job.args[1], job.args[2], job.args[3], job.args[6], job.args[7], job.args[8], job.args[9]}
	if want := []driver.Value{"cpanel", "src.example.com", int64(22), "root", "bulk", int64(2), settings, "admin"}; !reflect.DeepEqual(plain, want) {
		t.Fatalf("job record = %v, want %v", plain, want)
	}
	assertExecArgs(t, s, "INSERT INTO migration_items",
		[]driver.Value{int64(42), "acme", "example.com"}, []driver.Value{int64(42), "acme", "shop.example.com"})
	audit := s.onlyExec(t, "INSERT INTO audit_log")
	if audit.args[3] != "migration.start" || audit.args[4] != "cpanel@src.example.com (2 sites)" {
		t.Fatalf("audit = %v", audit.args)
	}
	assertExecArgs(t, s, "DELETE FROM migration_sessions")

	queued := receiveJob(t, started)
	wantJob := startedJob{
		jobID:    42,
		source:   RemoteSource{Type: "cpanel", Host: "src.example.com", Port: 22, User: "root", Password: "pw-secret", Key: "-----BEGIN KEY-----"},
		accounts: []RemoteAccount{{SourceAccount: "acme", DomainName: "example.com"}, {SourceAccount: "acme", DomainName: "shop.example.com"}},
		settings: MigrationSettings{Files: true, DNS: true},
	}
	if !reflect.DeepEqual(queued, wantJob) || slotHolder() != 42 {
		t.Fatalf("queued = %+v, slot %d", queued, slotHolder())
	}
}

// A start with no typed credential opens the saved session's, runs one account
// as a single job and consumes the session.
func TestMigrationStartResumesASavedSession(t *testing.T) {
	initSecret(t)
	freeSlot(t)
	started := withStartedJobs(t)
	sealed, err := secret.EncryptWith("pw-saved", "src.example.com")
	if err != nil {
		t.Fatal(err)
	}
	s := newScript()
	s.insertID = 43
	s.rows["FROM migration_sessions"] = [][]driver.Value{{sealed, nil}}
	w := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, s)}).MigrationStart(w, startRequest(t, startWith(map[string]any{"password": "", "session_id": 5})))

	assertResponse(t, w, http.StatusAccepted, `"job_id":43`)
	if job := s.onlyExec(t, "INSERT INTO migration_jobs"); job.args[5] != "" || job.args[6] != "single" {
		t.Fatalf("job record = %v", job.args)
	}
	assertExecArgs(t, s, "DELETE FROM migration_sessions", []driver.Value{int64(5)})
	if queued := receiveJob(t, started); queued.source.Password != "pw-saved" {
		t.Fatalf("queued source = %+v", queued.source)
	}
}

// scriptedAccounts answers each account migration by its domain: a panic for
// panicOn, an error for a domain in fail (after cancelling, when cancel is set),
// and a result carrying two warnings otherwise.
type scriptedAccounts struct {
	mu      sync.Mutex
	seen    []string
	fail    map[string]error
	panicOn string
	cancel  context.CancelFunc
}

func (sa *scriptedAccounts) migrate(_ *Handlers, _ context.Context, _ *RemoteSource, account RemoteAccount, _ MigrationSettings, logf func(string, ...any)) (*MigrationResult, error) {
	sa.mu.Lock()
	sa.seen = append(sa.seen, account.DomainName)
	sa.mu.Unlock()
	if account.DomainName == sa.panicOn {
		panic("boom\nforged line")
	}
	if err := sa.fail[account.DomainName]; err != nil {
		sa.cancelIfSet()
		return nil, err
	}
	logf("migrating %s", account.DomainName)
	return &MigrationResult{DomainID: 11, FileBytes: 1 << 20, DBCount: 1, DNSCount: 2, MailCount: 3, Warnings: []string{"w1", "w2"}}, nil
}

func (sa *scriptedAccounts) cancelIfSet() {
	if sa.cancel != nil {
		sa.cancel()
	}
}

// runJob runs job 77 over domains, logging under logDir, and returns the script
// and the source it ran with.
func runJob(t *testing.T, ctx context.Context, sa *scriptedAccounts, logDir string, domains ...string) (*sqlScript, *RemoteSource) {
	t.Helper()
	t.Setenv("SERVIKA_LOG_DIR", logDir)
	setForTest(t, &migrateAccount, sa.migrate)
	freeSlot(t)
	setSlot(77, nil)
	s := newScript()
	source := passwordSource("cpanel")
	source.Key = "KEY"
	accounts := make([]RemoteAccount, 0, len(domains))
	for _, d := range domains {
		accounts = append(accounts, RemoteAccount{DomainName: d})
	}
	(&Handlers{DB: scriptDB(t, s)}).runMigrationJob(ctx, 77, source, accounts, MigrationSettings{})
	return s, source
}

// jobLog returns the job log lines without their time stamps.
func jobLog(t *testing.T, logDir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(logDir, "migration-77.log"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for line := range strings.SplitSeq(strings.TrimSuffix(string(raw), "\n"), "\n") {
		_, body, _ := strings.Cut(line, "] ")
		lines = append(lines, body)
	}
	return lines
}

// assertJobClosed checks what every run leaves behind: the credentials cleared
// in the database and in memory, and the slot free.
func assertJobClosed(t *testing.T, s *sqlScript, source *RemoteSource) {
	t.Helper()
	assertExecArgs(t, s, "credentials_cleared=1", []driver.Value{int64(77)})
	if source.Password != "" || source.Key != "" || slotHolder() != 0 {
		t.Fatalf("source %+v, slot %d", source, slotHolder())
	}
}

// Each account is marked running, then done with its counts and warnings or
// failed with its error, and the job closes as done when any account succeeded.
func TestRunMigrationJobRecordsEachAccount(t *testing.T) {
	logDir := t.TempDir()
	sa := &scriptedAccounts{fail: map[string]error{"b.example.com": errors.New("boom")}}
	s, source := runJob(t, t.Context(), sa, logDir, "a.example.com", "b.example.com")

	assertExecArgs(t, s, "SET status='running'", []driver.Value{int64(77), "a.example.com"}, []driver.Value{int64(77), "b.example.com"})
	assertExecArgs(t, s, "SET status='done'",
		[]driver.Value{int64(11), int64(1 << 20), int64(1), int64(2), int64(3), "w1; w2", int64(77), "a.example.com"})
	assertExecArgs(t, s, "UPDATE migration_items SET status='failed'", []driver.Value{"boom", int64(77), "b.example.com"})
	assertExecArgs(t, s, "SET completed=?", []driver.Value{int64(1), int64(0), int64(77)}, []driver.Value{int64(1), int64(1), int64(77)})
	assertExecArgs(t, s, "UPDATE migration_jobs SET status=?", []driver.Value{"done", int64(1), int64(1), int64(77)})
	assertJobClosed(t, s, source)
	want := []string{
		"migration started — source src.example.com (cpanel), 2 site(s)",
		"-------- [1/2] a.example.com --------",
		"migrating a.example.com",
		"DONE: a.example.com (1.0 MB, 1 DB, 2 DNS, 3 mail) | warning: w1; w2",
		"-------- [2/2] b.example.com --------",
		"ERROR: b.example.com -> boom",
		"migration finished — 1 succeeded, 1 failed",
	}
	if got := jobLog(t, logDir); !reflect.DeepEqual(got, want) {
		t.Fatalf("log =\n%q\nwant\n%q", got, want)
	}
}

// A job where every account failed closes as failed, and a log directory that
// cannot be made does not stop the job.
func TestRunMigrationJobFailsWhenNoAccountSucceeds(t *testing.T) {
	blocked := writeFile(t, "log-dir", nil)
	sa := &scriptedAccounts{fail: map[string]error{"a.example.com": errScripted}}
	s, source := runJob(t, t.Context(), sa, blocked, "a.example.com")
	assertExecArgs(t, s, "UPDATE migration_jobs SET status=?", []driver.Value{"failed", int64(0), int64(1), int64(77)})
	assertJobClosed(t, s, source)
}

// A cancelled job skips the accounts left, and a cancellation during the last
// account marks that account skipped rather than failed.
func TestRunMigrationJobStopsOnCancel(t *testing.T) {
	logDir := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	sa := &scriptedAccounts{}
	s, source := runJob(t, ctx, sa, logDir, "a.example.com", "b.example.com")
	assertExecArgs(t, s, "SET status='cancelled'", []driver.Value{int64(77)})
	assertJobClosed(t, s, source)
	if len(sa.seen) != 0 || !reflect.DeepEqual(jobLog(t, logDir)[1:], []string{"CANCELLED — 2 remaining site(s) skipped"}) {
		t.Fatalf("seen %q, log %q", sa.seen, jobLog(t, logDir))
	}

	logDir = t.TempDir()
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	sa = &scriptedAccounts{fail: map[string]error{"a.example.com": context.Canceled}, cancel: cancel}
	s, source = runJob(t, ctx, sa, logDir, "a.example.com", "b.example.com")
	assertExecArgs(t, s, "SET status='skipped'", []driver.Value{int64(77), "a.example.com"})
	assertExecArgs(t, s, "SET status='cancelled'", []driver.Value{int64(77)})
	assertJobClosed(t, s, source)
	if log := jobLog(t, logDir); !reflect.DeepEqual(sa.seen, []string{"a.example.com"}) || log[len(log)-1] != "CANCELLED — a.example.com was interrupted" {
		t.Fatalf("seen %q, log %q", sa.seen, log)
	}
}

// A panic closes the job as failed with the panic value on one line.
func TestRunMigrationJobRecoversFromAPanic(t *testing.T) {
	sa := &scriptedAccounts{panicOn: "a.example.com"}
	s, source := runJob(t, t.Context(), sa, t.TempDir(), "a.example.com")
	assertExecArgs(t, s, "UPDATE migration_jobs SET status='failed'", []driver.Value{"unexpected error: boom forged line", int64(77)})
	assertJobClosed(t, s, source)
}
