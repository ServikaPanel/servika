package mail

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"servika/internal/secret"
)

// A recording driver, in the same shape as the one in purge_test.go: the
// repository carries no sqlmock dependency, and what has to be asserted here is
// which statement ran and what the queue then did with the row.
type migrateRecorder struct {
	mu       sync.Mutex
	steps    []string
	insertID int64
	// claimed is how many rows the claim UPDATE reports. Zero stands for a job
	// that was cancelled, or closed by the startup heal, while it waited.
	claimed int64
	// failClaim makes the claim UPDATE return an error rather than a count.
	failClaim bool
	// args collects every string bound into a statement, so a test can prove
	// what did NOT reach the database.
	args []string
	// queued is what the resume's SELECT returns.
	queued [][]driver.Value
}

// sawArgument reports whether any statement was given this exact value.
func (r *migrateRecorder) sawArgument(value string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(r.args, value)
}

func (r *migrateRecorder) record(step string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, step)
}

// sawStatement reports whether any recorded statement contains the fragment.
func (r *migrateRecorder) sawStatement(fragment string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, step := range r.steps {
		if strings.Contains(step, fragment) {
			return true
		}
	}
	return false
}

var (
	migrateStateMu sync.Mutex
	migrateState   = map[string]*migrateRecorder{}
	errMigrateExec = errors.New("statement failed")
)

type migrateDriver struct{}

func (migrateDriver) Open(name string) (driver.Conn, error) {
	migrateStateMu.Lock()
	defer migrateStateMu.Unlock()
	recorder, ok := migrateState[name]
	if !ok {
		return nil, fmt.Errorf("no recorder registered for %q", name)
	}
	return &migrateConn{recorder: recorder}, nil
}

func init() { sql.Register("mail_migrate_recorder", migrateDriver{}) }

type migrateConn struct{ recorder *migrateRecorder }

func (c *migrateConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not used by this test")
}
func (c *migrateConn) Close() error              { return nil }
func (c *migrateConn) Begin() (driver.Tx, error) { return nil, errors.New("no transactions here") }

type migrateResult struct{ id, rows int64 }

func (r migrateResult) LastInsertId() (int64, error) { return r.id, nil }
func (r migrateResult) RowsAffected() (int64, error) { return r.rows, nil }

func (c *migrateConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.recorder.record(query)
	c.recorder.mu.Lock()
	for _, arg := range args {
		if text, ok := arg.Value.(string); ok {
			c.recorder.args = append(c.recorder.args, text)
		}
	}
	c.recorder.mu.Unlock()
	switch {
	case strings.Contains(query, "INSERT INTO mail_migration_jobs"):
		return migrateResult{id: c.recorder.insertID, rows: 1}, nil
	case strings.Contains(query, "SET status='running'"):
		if c.recorder.failClaim {
			return nil, errMigrateExec
		}
		return migrateResult{rows: c.recorder.claimed}, nil
	}
	return migrateResult{rows: 1}, nil
}

// QueryContext answers the one SELECT the resume issues. Anything else comes
// back empty, which is what a caller expecting no rows sees.
func (c *migrateConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.recorder.record(query)
	if strings.Contains(query, "FROM mail_migration_jobs") && strings.Contains(query, "status='queued'") {
		return &migrateRows{
			columns: []string{"id", "mailbox_id", "remote_host", "remote_port",
				"remote_security", "remote_user", "remote_password"},
			values: c.recorder.queued,
		}, nil
	}
	return &migrateRows{}, nil
}

type migrateRows struct {
	columns []string
	values  [][]driver.Value
	next    int
}

func (r *migrateRows) Columns() []string { return r.columns }
func (r *migrateRows) Close() error      { return nil }
func (r *migrateRows) Next(dest []driver.Value) error {
	if r.next >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.next])
	r.next++
	return nil
}

func migrateHarness(t *testing.T) (*sql.DB, *migrateRecorder) {
	t.Helper()
	// The credential is sealed before it reaches a row, so the encryption has to
	// be live for any of this to run at all.
	if err := secret.Init([]byte(strings.Repeat("k", 32))); err != nil {
		t.Fatalf("initialise the encryption: %v", err)
	}
	recorder := &migrateRecorder{insertID: 41, claimed: 1}
	name := t.Name()

	migrateStateMu.Lock()
	migrateState[name] = recorder
	migrateStateMu.Unlock()
	t.Cleanup(func() {
		migrateStateMu.Lock()
		delete(migrateState, name)
		migrateStateMu.Unlock()
	})

	db, err := sql.Open("mail_migrate_recorder", name)
	if err != nil {
		t.Fatalf("open the recording database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// The queue is package state, so a test that leaves entries behind would
	// change the next one's result.
	drainMigrationQueue()
	t.Cleanup(drainMigrationQueue)
	return db, recorder
}

func drainMigrationQueue() {
	for {
		select {
		case <-migrationQueue:
		default:
			return
		}
	}
}

// swapCopy replaces the copy with one that only records that it was reached, so
// the claim guard can be tested without an IMAP server anywhere.
func swapCopy(t *testing.T, ran *bool) {
	t.Helper()
	original := copyMailboxFn
	copyMailboxFn = func(context.Context, *sql.DB, int64, int64, RemoteAccount) error {
		*ran = true
		return nil
	}
	t.Cleanup(func() { copyMailboxFn = original })
}

// Only four copies run at a time, so a started job is WAITING, not running. A
// row written as running would make the screen show a copy that is not
// happening, and the status endpoint would then contradict the start response.
func TestAStartedMigrationIsWrittenAsQueuedAndPutOnTheQueue(t *testing.T) {
	db, recorder := migrateHarness(t)

	remote := RemoteAccount{
		Host: "imap.example.com", Port: 993, Security: "ssl",
		Username: "someone@example.com", Password: "the-remote-password",
	}
	id, err := startMigrationJob(db, 7, remote)
	if err != nil {
		t.Fatalf("startMigrationJob: %v", err)
	}
	if id != recorder.insertID {
		t.Errorf("id = %d, want %d", id, recorder.insertID)
	}
	if !recorder.sawStatement("'queued'") {
		t.Error("the job was not written as queued")
	}
	if recorder.sawStatement("'running'") {
		t.Error("the job was written as running before any worker claimed it")
	}

	select {
	case job := <-migrationQueue:
		if job.id != id || job.mailboxID != 7 {
			t.Errorf("queued job = %+v, want id %d for mailbox 7", job, id)
		}
		// The queue entry carries the plaintext so a worker does not have to open
		// the seal again on the common path. Losing it here would start a copy
		// that cannot sign in.
		if job.remote.Password != remote.Password {
			t.Error("the remote password did not travel with the queued job")
		}
	default:
		t.Fatal("the job was not put on the queue")
	}
}

// The wait list is bounded because every entry holds a credential in memory.
// Past the bound the panel has to say no, and the row it already wrote must not
// be left occupying the mailbox's only migration slot.
func TestTheWaitListRefusesInsteadOfGrowing(t *testing.T) {
	db, recorder := migrateHarness(t)
	for i := range maxQueuedMigrations {
		migrationQueue <- pendingMigration{id: int64(i)}
	}

	if _, err := startMigrationJob(db, 7, RemoteAccount{}); !errors.Is(err, ErrTooManyMigrations) {
		t.Fatalf("err = %v, want ErrTooManyMigrations", err)
	}
	if !recorder.sawStatement("too_many_migrations") {
		t.Error("the refused row was not closed, so it still holds the mailbox")
	}
}

// The other direction: with room on the queue the same call must succeed, or the
// bound above would be indistinguishable from a migration that never starts.
func TestAMigrationStartsWhenTheWaitListHasRoom(t *testing.T) {
	db, _ := migrateHarness(t)
	for i := range maxQueuedMigrations - 1 {
		migrationQueue <- pendingMigration{id: int64(i)}
	}

	if _, err := startMigrationJob(db, 7, RemoteAccount{}); err != nil {
		t.Fatalf("startMigrationJob with one free slot: %v", err)
	}
}

// A job cancelled while it waited has no goroutine for CancelMigration to
// interrupt, so that endpoint only writes the row. The claim guard is what makes
// the write bite.
func TestAJobCancelledWhileItWaitedIsNeverCopied(t *testing.T) {
	db, recorder := migrateHarness(t)
	recorder.claimed = 0

	var ran bool
	swapCopy(t, &ran)
	runMigrationJob(context.Background(), db, pendingMigration{id: 5, mailboxID: 7})

	if ran {
		t.Error("a job that was no longer queued was copied anyway")
	}
}

// The other direction: a row still queued must actually be copied, or the guard
// above would simply have stopped every migration.
func TestAJobStillQueuedIsCopied(t *testing.T) {
	db, recorder := migrateHarness(t)
	recorder.claimed = 1

	var ran bool
	swapCopy(t, &ran)
	runMigrationJob(context.Background(), db, pendingMigration{id: 5, mailboxID: 7})

	if !ran {
		t.Error("a queued job was claimed but never copied")
	}
}

// A claim that could not be written leaves the row queued on purpose: every
// reason code this package has blames the remote server, which did nothing
// wrong. Starting the copy anyway would run it against a row saying it never
// started.
func TestAClaimThatFailsDoesNotStartTheCopy(t *testing.T) {
	db, recorder := migrateHarness(t)
	recorder.failClaim = true

	var ran bool
	swapCopy(t, &ran)
	runMigrationJob(context.Background(), db, pendingMigration{id: 5, mailboxID: 7})

	if ran {
		t.Error("the copy ran even though the row was never claimed")
	}
	if recorder.sawStatement("SET status=?") {
		t.Error("an unclaimed job was reported as finished")
	}
}

// The row now carries the credential so a restart can finish the copy, and the
// only acceptable form is sealed: a dump of this table must not be a list of
// customers' passwords at other providers.
func TestTheStoredCredentialIsSealedNotPlaintext(t *testing.T) {
	db, recorder := migrateHarness(t)
	const password = "the-remote-password"

	if _, err := startMigrationJob(db, 7, RemoteAccount{
		Host: "imap.example.com", Port: 993, Security: "ssl",
		Username: "someone@example.com", Password: password,
	}); err != nil {
		t.Fatalf("startMigrationJob: %v", err)
	}
	if recorder.sawArgument(password) {
		t.Fatal("the password reached the database in plain text")
	}
	if !recorder.sawStatement("remote_password") {
		t.Error("no credential was stored, so a restart could not resume the copy")
	}
}

// The seal is bound to the host, so a row edited to name another server stops
// opening instead of replaying the password at it.
func TestTheSealDoesNotOpenForAnotherHost(t *testing.T) {
	if err := secret.Init([]byte(strings.Repeat("k", 32))); err != nil {
		t.Fatalf("initialise the encryption: %v", err)
	}
	sealed, err := secret.EncryptWith("password", "imap.example.com")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := secret.DecryptWith(sealed, "imap.attacker.test"); err == nil {
		t.Error("the credential opened under a different host")
	}
	// The other direction: the right host must still open it, or resuming would
	// never work at all.
	if got, err := secret.DecryptWith(sealed, "imap.example.com"); err != nil || got != "password" {
		t.Errorf("DecryptWith = (%q, %v), want the original password", got, err)
	}
}

// A copy that was hours in used to be thrown away by a restart. The sealed
// credential is what lets it be finished instead.
func TestAnUnfinishedJobIsPutBackOnTheQueue(t *testing.T) {
	db, recorder := migrateHarness(t)
	sealed, err := secret.EncryptWith("remote-secret", "imap.example.com")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	recorder.queued = [][]driver.Value{
		{int64(5), int64(7), "imap.example.com", int64(993), "ssl", "someone@example.com", sealed},
	}

	HealMigrationJobs(db)

	// A row left mid-copy has to go back to queued first, or the resume's own
	// SELECT would not see it.
	if !recorder.sawStatement("SET status='queued'") {
		t.Error("a running job was not put back to queued")
	}
	select {
	case job := <-migrationQueue:
		if job.id != 5 || job.remote.Password != "remote-secret" {
			t.Errorf("resumed job = %+v, want id 5 with its credential recovered", job)
		}
	default:
		t.Fatal("the unfinished job was not requeued")
	}
	if recorder.sawStatement("'interrupted'") {
		t.Error("a resumable job was closed as interrupted")
	}
}

// A credential that will not open ends the job. The key may have been rotated
// or the row may predate the column; either way it must be closed rather than
// left queued for ever holding the mailbox.
func TestAJobWhoseCredentialWillNotOpenIsClosed(t *testing.T) {
	db, recorder := migrateHarness(t)
	recorder.queued = [][]driver.Value{
		// Sealed under a different key: what a rotated SERVIKA_SECRET_KEY leaves.
		{int64(5), int64(7), "imap.example.com", int64(993), "ssl", "someone@example.com",
			"enc:v1:bm90LWEtcmVhbC1jaXBoZXJ0ZXh0"},
		// And a row from before the column existed.
		{int64(6), int64(8), "imap.example.com", int64(993), "ssl", "another@example.com", ""},
	}

	HealMigrationJobs(db)

	select {
	case job := <-migrationQueue:
		t.Fatalf("job %d was queued with a credential that cannot be used", job.id)
	default:
	}
	if !recorder.sawStatement("'interrupted'") {
		t.Error("an unresumable job was left queued instead of being closed")
	}
	if !recorder.sawStatement("credentials_cleared=1") {
		t.Error("the unusable credential was left in the row")
	}
}

// The credential exists only while a copy is pending or running. A finished row
// must not still hold one.
func TestFinishingAJobClearsItsCredential(t *testing.T) {
	db, recorder := migrateHarness(t)
	finishJob(db, 5, nil)

	if !recorder.sawStatement("remote_password=NULL") {
		t.Error("a finished job kept its credential")
	}
	if !recorder.sawStatement("credentials_cleared=1") {
		t.Error("the finished job was not marked as cleared")
	}
}
