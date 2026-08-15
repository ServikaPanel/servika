package mail

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"servika/internal/secret"
)

// migrationBudget is how long one copy may run before it is abandoned.
//
// It is generous because a large mailbox on a slow provider genuinely takes
// hours, and short because a job that has stopped making progress must not hold
// a mailbox's only migration slot for ever.
const migrationBudget = 12 * time.Hour

// migrationBatch is how many messages are fetched per FETCH command. Large
// enough that a mailbox of thousands does not cost thousands of round trips,
// small enough that progress is reported while it runs.
const migrationBatch = 200

// ErrMigrationRunning reports that this mailbox already has an unfinished job.
var ErrMigrationRunning = errors.New("a migration is already running for this mailbox")

// ErrTooManyMigrations reports that the wait list is full.
var ErrTooManyMigrations = errors.New("too many migrations are already waiting")

// maxConcurrentMigrations is how many copies this node runs at once.
//
// Each one holds an IMAP session to another provider, fetches in batches of
// migrationBatch and writes every message to disk, for up to migrationBudget.
// The unique index over the active mailbox refuses a SECOND job for the same
// mailbox and nothing more, so a reseller with three hundred mailboxes could
// otherwise start three hundred copies, each of them for a different mailbox and
// each of them legitimate on its own.
const maxConcurrentMigrations = 4

// maxQueuedMigrations bounds the wait list.
//
// The queue is held in memory and rebuilt from the rows at startup. Every entry
// costs a decrypted credential in memory as well as a slot, so it is bounded
// rather than allowed to grow: this is the point at which the panel says no.
const maxQueuedMigrations = 100

// pendingMigration is one job waiting for a worker. It carries the OPENED
// credential, so a worker does not have to unseal the row again on the common
// path; the sealed copy in the row exists for the restart case.
type pendingMigration struct {
	id        int64
	mailboxID int64
	remote    RemoteAccount
}

var migrationQueue = make(chan pendingMigration, maxQueuedMigrations)

// copyMailboxFn is the copy the workers run. It is a variable so a test can
// observe WHETHER a queued job was started without an IMAP server, which is the
// whole question the claim guard answers.
var copyMailboxFn = copyMailbox

// RemoteAccount is the source of a copy. The password is never stored; it lives
// in this value for as long as the job runs and nowhere else.
type RemoteAccount struct {
	Host     string
	Port     int
	Security string
	Username string
	Password string
}

// running tracks the cancel function of every job in flight, so the delete
// endpoint can stop one rather than only marking the row.
var running = struct {
	sync.Mutex
	cancels map[int64]context.CancelFunc
}{cancels: map[int64]context.CancelFunc{}}

func rememberJob(id int64, cancel context.CancelFunc) {
	running.Lock()
	running.cancels[id] = cancel
	running.Unlock()
}

func forgetJob(id int64) {
	running.Lock()
	delete(running.cancels, id)
	running.Unlock()
}

// cancelMigrationJob stops a running job. It reports whether one was in flight in
// this process; a job left by an earlier process has no goroutine to stop.
func cancelMigrationJob(id int64) bool {
	running.Lock()
	cancel, found := running.cancels[id]
	running.Unlock()
	if found {
		cancel()
	}
	return found
}

// startMigrationJob records the job and puts it on the queue.
//
// The insert is what refuses a second job for one mailbox: the unique index over
// the active mailbox does it in the database, so two requests arriving together
// cannot both decide they are the first. The row is written as queued and stays
// that way until a worker claims it, so the screen shows "waiting to start"
// rather than a copy that is not actually running.
func startMigrationJob(db *sql.DB, mailboxID int64, remote RemoteAccount) (int64, error) {
	// The credential is sealed before it reaches the row, bound to the host so a
	// row edited to name another server stops decrypting rather than replaying
	// the password at it. Only failing here loses the job; the alternative,
	// starting a copy whose credential cannot be recovered after a restart, is
	// what this whole column exists to avoid.
	sealed, err := secret.EncryptWith(remote.Password, remote.Host)
	if err != nil {
		return 0, fmt.Errorf("seal the remote credential: %w", err)
	}

	result, err := db.Exec(
		`INSERT INTO mail_migration_jobs
		   (mailbox_id, remote_host, remote_port, remote_security, remote_user, remote_password, status)
		 VALUES (?,?,?,?,?,?, 'queued')`,
		mailboxID, remote.Host, remote.Port, remote.Security, remote.Username, sealed)
	if err != nil {
		if isDuplicateKey(err) {
			return 0, ErrMigrationRunning
		}
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	select {
	case migrationQueue <- pendingMigration{id: id, mailboxID: mailboxID, remote: remote}:
		return id, nil
	default:
		// The wait list is full. The row is CLOSED rather than deleted: one
		// statement, the attempt stays in the history the screen shows, and
		// active_mailbox_id becomes NULL so the unique index releases the mailbox
		// immediately instead of holding it against a job that will never run.
		if _, err := db.Exec(
			`UPDATE mail_migration_jobs
			    SET status='failed', error_code='too_many_migrations', finished_at=NOW(),
			        remote_password=NULL, credentials_cleared=1
			  WHERE id=?`, id); err != nil {
			// #nosec G706 -- integer id and a database driver error.
			log.Printf("mail migration job=%d: could not be closed after the queue refused it: %v", id, err)
		}
		return 0, ErrTooManyMigrations
	}
}

// StartMigrationQueue runs the workers that drain the migration queue.
//
// It must be started AFTER HealMigrationJobs, which puts the previous process's
// unfinished jobs back on the queue: started first, a worker could claim a row
// while that requeue is still moving it, and the copy would run against a row
// the resume then overwrites.
func StartMigrationQueue(ctx context.Context, db *sql.DB) {
	for range maxConcurrentMigrations {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case job := <-migrationQueue:
					runMigrationJob(ctx, db, job)
				}
			}
		}()
	}
}

// runMigrationJob claims a queued row and copies the mailbox.
//
// The claim is GUARDED on the row still being queued. A job cancelled while it
// waited has no goroutine for CancelMigration to interrupt, so that endpoint
// only writes the row; this guard is what makes the write bite, and the job is
// dropped here instead of starting after the customer stopped it.
func runMigrationJob(ctx context.Context, db *sql.DB, job pendingMigration) {
	claimCtx, cancelClaim := context.WithTimeout(ctx, 15*time.Second)
	result, err := db.ExecContext(claimCtx,
		`UPDATE mail_migration_jobs SET status='running', started_at=NOW()
		  WHERE id=? AND status='queued'`, job.id)
	cancelClaim()
	if err != nil {
		// The row stays queued. Reporting it as failed would need a reason code,
		// and every code this package has blames the REMOTE server, which did
		// nothing wrong here. CancelMigration clears it now and the startup heal
		// clears it on the next restart.
		// #nosec G706 -- integer id and a database driver error.
		log.Printf("mail migration job=%d: could not be claimed and stays queued: %v", job.id, err)
		return
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return // Cancelled while waiting, or already closed by the startup heal.
	}

	// The budget starts HERE rather than when the job was queued: time spent
	// waiting for a free slot is not time the remote server was given.
	runCtx, cancel := context.WithTimeout(ctx, migrationBudget)
	defer cancel()
	rememberJob(job.id, cancel)
	defer forgetJob(job.id)

	finishJob(db, job.id, copyMailboxFn(runCtx, db, job.id, job.mailboxID, job.remote))
}

func isDuplicateKey(err error) bool {
	// The driver's error is formatted, and matching its text is enough here:
	// the only unique constraint on this table is the active-job one.
	return err != nil && strings.Contains(err.Error(), "Duplicate entry")
}

// finishJob writes the outcome on a context of its own.
//
// The job's own context is cancelled or expired by this point, so reusing it
// would drop the very update that records what happened.
func finishJob(db *sql.DB, id int64, cause error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	status, code := "done", ""
	switch {
	case cause == nil:
	case errors.Is(cause, context.Canceled):
		status, code = "cancelled", ""
	case errors.Is(cause, context.DeadlineExceeded):
		status, code = "failed", "timed_out"
	default:
		status, code = "failed", reasonFor(cause)
		// #nosec G706 -- the job id is an integer and the reason is one of this package's own constants; the wrapped error is the library's or the kernel's, never a raw remote string.
		log.Printf("mail migration job=%d failed: %v", id, cause)
	}
	// The credential is cleared in the SAME statement that closes the job, so the
	// ciphertext exists only while a copy is actually pending or running and a
	// finished row can never be a source of one.
	if _, err := db.ExecContext(ctx,
		`UPDATE mail_migration_jobs
		    SET status=?, error_code=?, finished_at=NOW(),
		        remote_password=NULL, credentials_cleared=1
		  WHERE id=?`,
		status, code, id); err != nil {
		// #nosec G706 -- integer id and a fixed status word.
		log.Printf("mail migration job=%d: could not record %s: %v", id, status, err)
	}
}

// copyMailbox performs the copy, folder by folder.
func copyMailbox(ctx context.Context, db *sql.DB, jobID, mailboxID int64, remote RemoteAccount) error {
	layout, err := layoutFor(ctx, db, mailboxID)
	if err != nil {
		return err
	}

	client, err := dialIMAP(ctx, remote.Host, remote.Port, remote.Security)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	if err := client.Login(remote.Username, remote.Password).Wait(); err != nil {
		if code := providerHint(remote.Host, remote.Username); code != "" {
			return &ReasonError{Code: code, Err: err}
		}
		return &ReasonError{Code: ReasonAuthFailed, Err: err}
	}

	folders, err := client.List("", "*", nil).Collect()
	if err != nil {
		return &ReasonError{Code: ReasonUnreachable, Err: err}
	}

	selectable := make([]*imap.ListData, 0, len(folders))
	for _, folder := range folders {
		if hasAttr(folder.Attrs, imap.MailboxAttrNoSelect) || hasAttr(folder.Attrs, imap.MailboxAttrNonExistent) {
			continue
		}
		selectable = append(selectable, folder)
	}
	setCounter(ctx, db, jobID, "folders_total", len(selectable))

	for index, folder := range selectable {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := copyFolder(ctx, db, client, layout, jobID, folder); err != nil {
			return err
		}
		setCounter(ctx, db, jobID, "folders_done", index+1)
	}
	return nil
}

func hasAttr(attrs []imap.MailboxAttr, want imap.MailboxAttr) bool {
	return slices.Contains(attrs, want)
}

// copyFolder selects one remote folder and writes every message it holds.
func copyFolder(ctx context.Context, db *sql.DB, client *imapclient.Client, layout maildirLayout, jobID int64, folder *imap.ListData) error {
	selected, err := client.Select(folder.Mailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		// A folder that cannot be opened is skipped rather than failing the
		// whole migration: one unreadable folder must not cost the customer
		// every other one.
		// #nosec G706 -- the folder name is not logged; only the job id and the library's error.
		log.Printf("mail migration job=%d: skipping an unreadable folder: %v", jobID, err)
		return nil
	}
	if selected.NumMessages == 0 {
		return nil
	}

	curDir, err := layout.ensureFolder(maildirSubdir(folder.Mailbox, folder.Delim))
	if err != nil {
		return err
	}

	addCounter(ctx, db, jobID, "messages_total", int(selected.NumMessages))

	for start := uint32(1); start <= selected.NumMessages; start += migrationBatch {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := min(start+migrationBatch-1, selected.NumMessages)
		copied, written, err := copyBatch(ctx, client, layout, curDir, jobID, start, end)
		if err != nil {
			return err
		}
		addCounter(ctx, db, jobID, "messages_done", copied)
		addCounter(ctx, db, jobID, "bytes_done", int(written))
	}
	return nil
}

// copyBatch fetches and writes one run of messages.
func copyBatch(ctx context.Context, client *imapclient.Client, layout maildirLayout, curDir string, jobID int64, start, end uint32) (int, int64, error) {
	section := &imap.FetchItemBodySection{Peek: true}
	var window imap.SeqSet
	window.AddRange(start, end)
	fetch := client.Fetch(window, &imap.FetchOptions{
		UID:          true,
		Flags:        true,
		BodySection:  []*imap.FetchItemBodySection{section},
		InternalDate: true,
	})
	defer func() { _ = fetch.Close() }()

	var (
		copied  int
		written int64
	)
	for {
		if err := ctx.Err(); err != nil {
			return copied, written, err
		}
		message := fetch.Next()
		if message == nil {
			break
		}

		var (
			uid   uint32
			flags []string
		)
		for {
			item := message.Next()
			if item == nil {
				break
			}
			switch data := item.(type) {
			case imapclient.FetchItemDataUID:
				uid = uint32(data.UID)
			case imapclient.FetchItemDataFlags:
				flags = flags[:0]
				for _, flag := range data.Flags {
					flags = append(flags, string(flag))
				}
			case imapclient.FetchItemDataBodySection:
				// Streamed rather than buffered: a mailbox can hold messages
				// larger than the panel's whole memory budget.
				size, err := layout.writeMessage(curDir,
					fmt.Sprintf("servika-%d-%d", jobID, uid), flags, data.Literal)
				if err != nil {
					return copied, written, err
				}
				copied++
				written += size
			}
		}
	}
	if err := fetch.Close(); err != nil {
		return copied, written, &ReasonError{Code: ReasonUnreachable, Err: err}
	}
	return copied, written, nil
}

// layoutFor resolves where a mailbox's files belong.
func layoutFor(ctx context.Context, db *sql.DB, mailboxID int64) (maildirLayout, error) {
	var (
		maildir    string
		systemUser string
	)
	err := db.QueryRowContext(ctx,
		`SELECT m.maildir, d.system_user
		   FROM mailboxes m
		   JOIN mail_domains d ON d.id = m.mail_domain_id
		  WHERE m.id = ?`, mailboxID).Scan(&maildir, &systemUser)
	if err != nil {
		return maildirLayout{}, err
	}
	if systemUser == "" || maildir == "" {
		return maildirLayout{}, fmt.Errorf("mailbox %d has no maildir", mailboxID)
	}

	home := "/home/" + systemUser
	rel, inside := strings.CutPrefix(maildir, home+"/")
	if !inside {
		return maildirLayout{}, fmt.Errorf("mailbox %d stores mail outside its home", mailboxID)
	}
	return maildirLayout{home: home, root: rel, systemUser: systemUser}, nil
}

// progressStatements holds the two ways each counter is written, as complete
// literals.
//
// Building the column name into the query would work, but it is dynamic SQL in a
// file that also handles a remote server's output, and a reader has to prove the
// name is safe every time they pass it. There is no query here that was not
// written out in full.
var progressStatements = map[string]struct{ set, add string }{
	"folders_total": {
		set: `UPDATE mail_migration_jobs SET folders_total=? WHERE id=?`,
		add: `UPDATE mail_migration_jobs SET folders_total=folders_total+? WHERE id=?`,
	},
	"folders_done": {
		set: `UPDATE mail_migration_jobs SET folders_done=? WHERE id=?`,
		add: `UPDATE mail_migration_jobs SET folders_done=folders_done+? WHERE id=?`,
	},
	"messages_total": {
		set: `UPDATE mail_migration_jobs SET messages_total=? WHERE id=?`,
		add: `UPDATE mail_migration_jobs SET messages_total=messages_total+? WHERE id=?`,
	},
	"messages_done": {
		set: `UPDATE mail_migration_jobs SET messages_done=? WHERE id=?`,
		add: `UPDATE mail_migration_jobs SET messages_done=messages_done+? WHERE id=?`,
	},
	"bytes_done": {
		set: `UPDATE mail_migration_jobs SET bytes_done=? WHERE id=?`,
		add: `UPDATE mail_migration_jobs SET bytes_done=bytes_done+? WHERE id=?`,
	},
}

func isProgressColumn(column string) bool {
	_, known := progressStatements[column]
	return known
}

// setCounter writes an absolute progress value.
func setCounter(ctx context.Context, db *sql.DB, jobID int64, column string, value int) {
	statement, known := progressStatements[column]
	if !known {
		return
	}
	runProgress(ctx, db, jobID, column, statement.set, value)
}

// addCounter advances a progress value, so a folder's contribution is added to
// what earlier folders already reported.
func addCounter(ctx context.Context, db *sql.DB, jobID int64, column string, value int) {
	statement, known := progressStatements[column]
	if !known || value == 0 {
		return
	}
	runProgress(ctx, db, jobID, column, statement.add, value)
}

// runProgress records a counter. A failure to write progress does not stop the
// copy: the messages are what the customer came for, and the number on screen
// standing still is better than the transfer dying over it.
func runProgress(ctx context.Context, db *sql.DB, jobID int64, column, statement string, value int) {
	if _, err := db.ExecContext(ctx, statement, value, jobID); err != nil {
		// #nosec G706 -- integer id and a key from the fixed map above.
		log.Printf("mail migration job=%d: could not record %s: %v", jobID, column, err)
	}
}

// HealMigrationJobs puts the previous process's unfinished jobs back on the
// queue.
//
// Their goroutines died with it, so without this the rows would say "running"
// for ever and the unique index would keep each mailbox's slot occupied. They
// used to be closed as interrupted, which threw away a copy that may have been
// hours in; now the sealed credential in the row is what lets them be resumed
// instead.
//
// A row that was already RUNNING is put back to queued and copied again from the
// start. That is safe because writeMessage names every message after the job id
// and the remote UID, so the second run of the SAME job overwrites its own
// earlier attempt rather than delivering a duplicate.
//
// This runs before the workers start, so nothing can claim a row while it is
// being requeued.
func HealMigrationJobs(db *sql.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := db.ExecContext(ctx,
		`UPDATE mail_migration_jobs SET status='queued', started_at=NULL WHERE status='running'`); err != nil {
		log.Printf("mail migration resume: unfinished jobs could not be requeued: %v", err)
		return
	}

	rows, err := db.QueryContext(ctx,
		`SELECT id, mailbox_id, remote_host, remote_port, remote_security, remote_user,
		        COALESCE(remote_password, '')
		   FROM mail_migration_jobs
		  WHERE status='queued' ORDER BY id`)
	if err != nil {
		log.Printf("mail migration resume: the queue could not be read: %v", err)
		return
	}
	defer func() { _ = rows.Close() }()

	var resumed, abandoned int
	for rows.Next() {
		var (
			job    pendingMigration
			sealed string
		)
		if err := rows.Scan(&job.id, &job.mailboxID, &job.remote.Host, &job.remote.Port,
			&job.remote.Security, &job.remote.Username, &sealed); err != nil {
			log.Printf("mail migration resume: a row could not be read: %v", err)
			continue
		}
		// A credential that will not open is the end of that job: the key was
		// rotated, the row predates the column, or it was tampered with. It is
		// closed rather than left queued for ever, and the reason code is the one
		// the screen already renders.
		password, err := secret.DecryptWith(sealed, job.remote.Host)
		if sealed == "" || err != nil {
			abandonMigration(ctx, db, job.id)
			abandoned++
			continue
		}
		job.remote.Password = password

		select {
		case migrationQueue <- job:
			resumed++
		default:
			// More unfinished work than the wait list holds. The rest are closed
			// rather than silently dropped, so nothing claims to be queued while
			// no worker will ever reach it.
			abandonMigration(ctx, db, job.id)
			abandoned++
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("mail migration resume: reading the queue ended early: %v", err)
	}
	if resumed > 0 || abandoned > 0 {
		log.Printf("mail migration resume: %d job(s) requeued, %d closed as interrupted", resumed, abandoned)
	}
}

// abandonMigration closes a job that cannot be resumed and clears its
// credential.
func abandonMigration(ctx context.Context, db *sql.DB, id int64) {
	if _, err := db.ExecContext(ctx,
		`UPDATE mail_migration_jobs
		    SET status='failed', error_code='interrupted', finished_at=NOW(),
		        remote_password=NULL, credentials_cleared=1
		  WHERE id=?`, id); err != nil {
		// #nosec G706 -- integer id and a database driver error.
		log.Printf("mail migration job=%d: could not be closed: %v", id, err)
	}
}
