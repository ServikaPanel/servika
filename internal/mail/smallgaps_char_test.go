package mail

import (
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"servika/internal/secret"
)

// repeatReader yields one byte for ever.
type repeatReader byte

func (r repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

// A write that fails stops the split at the next separator instead of carrying
// on into the next message.
func TestMboxSplitStopsWhenAWriteFails(t *testing.T) {
	err := forEachMboxMessage(strings.NewReader("From a\none\nFrom b\ntwo\n"), func([]byte) error { return errScripted })
	if !errors.Is(err, errScripted) {
		t.Fatalf("err = %v, want the write failure", err)
	}
}

// One message larger than the import limit ends the split.
func TestMboxSplitRefusesAMessagePastTheLimit(t *testing.T) {
	source := io.MultiReader(strings.NewReader("From a\n"), io.LimitReader(repeatReader('x'), maxImportMessageBytes+1))
	if err := forEachMboxMessage(source, func([]byte) error { return nil }); !errors.Is(err, errMessageTooLarge) {
		t.Fatalf("err = %v, want errMessageTooLarge", err)
	}
}

// A read that fails is returned rather than read as the end of the file.
func TestMboxSplitReportsAReadError(t *testing.T) {
	source := io.MultiReader(strings.NewReader("From a\nbody"), iotest.ErrReader(errScripted))
	if err := forEachMboxMessage(source, func([]byte) error { return nil }); !errors.Is(err, errScripted) {
		t.Fatalf("err = %v, want the read failure", err)
	}
}

// An action the filter screen does not offer is refused by name.
func TestValidateFilterRefusesAnUnknownAction(t *testing.T) {
	err := validateFilter(MailFilter{Name: "x", MatchField: "from", MatchValue: "x", ActionType: "bounce"})
	if err == nil || err.Error() != "invalid filter action" {
		t.Fatalf("err = %v, want invalid filter action", err)
	}
}

const (
	requeueRunning = "SET status='queued', started_at=NULL WHERE status='running'"
	queuedRead     = "WHERE status='queued' ORDER BY id"
)

// healScript answers the resume's queue read with one job whose credential opens.
func healScript(t *testing.T) *sqlScript {
	t.Helper()
	if err := secret.Init([]byte(strings.Repeat("k", 32))); err != nil {
		t.Fatalf("initialise the encryption: %v", err)
	}
	drainMigrationQueue()
	t.Cleanup(drainMigrationQueue)
	sealed, err := secret.EncryptWith("remote-secret", "imap.example.com")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	s := newScript()
	s.rows[queuedRead] = [][]driver.Value{{int64(5), int64(7), "imap.example.com", int64(993), "ssl", "someone@example.com", sealed}}
	return s
}

// Each way the resume can fail to read its own queue is logged, and none of them
// is mistaken for an empty queue in silence.
func TestHealMigrationJobsReportsAReadFailure(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(*sqlScript)
		logged string
	}{
		{"the requeue fails", func(s *sqlScript) { s.fail[requeueRunning] = errScripted }, "unfinished jobs could not be requeued"},
		{"the queue cannot be read", func(s *sqlScript) { s.fail[queuedRead] = errScripted }, "the queue could not be read"},
		{"a row does not scan", func(s *sqlScript) { s.rows[queuedRead] = [][]driver.Value{{int64(5)}} }, "a row could not be read"},
		{"the read ends early", func(s *sqlScript) { s.endWith[queuedRead] = errScripted }, "reading the queue ended early"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			script := healScript(t)
			c.setup(script)
			logged := captureApplyLog(t)
			HealMigrationJobs(scriptDB(t, script))
			if !strings.Contains(logged.String(), c.logged) {
				t.Fatalf("log = %q, want it to hold %q", logged.String(), c.logged)
			}
		})
	}
}

// More unfinished work than the wait list holds is closed, not left queued with no
// worker to reach it.
func TestHealMigrationJobsClosesWhatTheWaitListCannotHold(t *testing.T) {
	script := healScript(t)
	for i := range maxQueuedMigrations {
		migrationQueue <- pendingMigration{id: int64(i)}
	}
	HealMigrationJobs(scriptDB(t, script))
	if closed := script.onlyExec(t, "error_code='interrupted'"); closed.args[0] != int64(5) {
		t.Fatalf("closed job = %#v, want 5", closed.args[0])
	}
}
