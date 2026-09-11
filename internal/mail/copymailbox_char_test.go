package mail

import (
	"context"
	"database/sql/driver"
	"errors"
	"maps"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

const (
	remoteUser     = "someone@example.com"
	remotePassword = "remote-secret"
)

// remoteFaults decides what the in-memory server refuses.
type remoteFaults struct{ list, fetch bool }

// listingSession wraps the in-memory server's session so a LIST carries a folder
// that cannot be selected, and so a LIST or a FETCH can be refused.
type listingSession struct {
	imapserver.Session
	faults remoteFaults
}

func (s listingSession) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	if s.faults.list {
		return errors.New("list refused")
	}
	archive := &imap.ListData{Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect}, Delim: '/', Mailbox: "Archive"}
	if err := w.WriteList(archive); err != nil {
		return err
	}
	return s.Session.List(w, ref, patterns, options)
}

func (s listingSession) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	if s.faults.fetch {
		return errors.New("fetch refused")
	}
	return s.Session.Fetch(w, numSet, options)
}

type discardLogger struct{}

func (discardLogger) Printf(string, ...any) {}

// remoteMailbox runs an in-memory IMAP server on the loopback holding INBOX with
// two messages, Sent with one and an empty Drafts, and returns the account that
// reaches it.
func remoteMailbox(t *testing.T, faults remoteFaults) RemoteAccount {
	t.Helper()
	t.Setenv("SERVIKA_ALLOW_PRIVATE_TARGETS", "1")
	user := imapmemserver.NewUser(remoteUser, remotePassword)
	for _, name := range []string{"INBOX", "Sent", "Drafts"} {
		if err := user.Create(name, nil); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	appendMessage(t, user, "INBOX", "Subject: one\r\n\r\nfirst\r\n", imap.FlagSeen)
	appendMessage(t, user, "INBOX", "Subject: two\r\n\r\nsecond\r\n")
	appendMessage(t, user, "Sent", "Subject: sent\r\n\r\nthird\r\n")
	memory := imapmemserver.New()
	memory.AddUser(user)
	server := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return listingSession{Session: memory.NewSession(), faults: faults}, nil, nil
		},
		InsecureAuth: true,
		Logger:       discardLogger{},
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return RemoteAccount{
		Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, Security: SecurityPlain,
		Username: remoteUser, Password: remotePassword,
	}
}

func appendMessage(t *testing.T, user *imapmemserver.User, mailbox, body string, flags ...imap.Flag) {
	t.Helper()
	if _, err := user.Append(mailbox, strings.NewReader(body), &imap.AppendOptions{Flags: flags}); err != nil {
		t.Fatalf("append to %s: %v", mailbox, err)
	}
}

// copyRun is one copy against the in-memory server.
type copyRun struct {
	remote RemoteAccount
	script *sqlScript
	fake   *maildirFake
	ctx    context.Context
	cancel context.CancelFunc
}

func newCopyRun(t *testing.T, faults remoteFaults) *copyRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	script := newScript()
	script.rows[layoutRead] = [][]driver.Value{{"/home/c_tenant/mail/example.com/info/", "c_tenant"}}
	return &copyRun{remote: remoteMailbox(t, faults), script: script, fake: withMaildirFake(t), ctx: ctx, cancel: cancel}
}

func (r *copyRun) copy(t *testing.T) error {
	t.Helper()
	return copyMailbox(r.ctx, scriptDB(t, r.script), 5, 7, r.remote)
}

// Every selectable folder with mail is written into its Maildir folder, each
// message named after the job and its UID with its flags, and the progress
// counters follow the copy.
func TestCopyMailboxWritesEverySelectableFolder(t *testing.T) {
	run := newCopyRun(t, remoteFaults{})
	if err := run.copy(t); err != nil {
		t.Fatalf("copyMailbox: %v", err)
	}
	one, two, sent := "Subject: one\r\n\r\nfirst\r\n", "Subject: two\r\n\r\nsecond\r\n", "Subject: sent\r\n\r\nthird\r\n"
	assertCopied(t, run.fake.streamedUnder(mailboxRoot+"/cur/"), map[string]string{
		"1000000000.servika-5-1:2,S": one,
		"1000000000.servika-5-2:2,":  two,
	})
	assertCopied(t, run.fake.streamedUnder(mailboxRoot+"/.Sent/cur/"), map[string]string{
		"1000000000.servika-5-1:2,": sent,
	})
	assertCounter(t, run.script, "SET folders_total=?", 3)
	assertCounter(t, run.script, "SET folders_done=?", 1, 2, 3)
	assertCounter(t, run.script, "messages_total=messages_total+?", 2, 1)
	assertCounter(t, run.script, "messages_done=messages_done+?", 2, 1)
	assertCounter(t, run.script, "bytes_done=bytes_done+?", int64(len(one)+len(two)), int64(len(sent)))
}

func assertCopied(t *testing.T, got, want map[string]string) {
	t.Helper()
	if !maps.Equal(got, want) {
		t.Fatalf("copied %q, want %q", got, want)
	}
}

func assertCounter(t *testing.T, s *sqlScript, fragment string, values ...int64) {
	t.Helper()
	var got []int64
	for _, statement := range s.execsContaining(fragment) {
		value, _ := statement.args[0].(int64)
		got = append(got, value)
	}
	if !slices.Equal(got, values) {
		t.Fatalf("%s wrote %v, want %v", fragment, got, values)
	}
}

func noCopySetup(*testing.T, *copyRun) {}

// Each failure the remote side causes comes back with the reason code the
// migration screen renders.
func TestCopyMailboxReasons(t *testing.T) {
	cases := []struct {
		name   string
		faults remoteFaults
		setup  func(*testing.T, *copyRun)
		reason string
	}{
		{"a loopback host without the opt-out", remoteFaults{}, func(t *testing.T, _ *copyRun) { t.Setenv("SERVIKA_ALLOW_PRIVATE_TARGETS", "") }, ReasonBlockedHost},
		{"a wrong password", remoteFaults{}, func(_ *testing.T, r *copyRun) { r.remote.Password = "wrong" }, ReasonAuthFailed},
		{"a provider that refuses passwords", remoteFaults{}, func(_ *testing.T, r *copyRun) { r.remote.Username = "someone@gmail.com" }, ReasonAppPasswordRequired},
		{"a folder list the server refuses", remoteFaults{list: true}, noCopySetup, ReasonUnreachable},
		{"a fetch the server refuses", remoteFaults{fetch: true}, noCopySetup, ReasonUnreachable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run := newCopyRun(t, c.faults)
			c.setup(t, run)
			err := run.copy(t)
			if _, ok := errors.AsType[*ReasonError](err); !ok || reasonFor(err) != c.reason {
				t.Fatalf("err = %v, want reason %s", err, c.reason)
			}
		})
	}
}

// A local failure or a stop ends the copy with that error.
func TestCopyMailboxStops(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*copyRun)
		want  error
	}{
		{"a layout that cannot be read", func(r *copyRun) { r.script.fail[layoutRead] = errScripted }, errScripted},
		{"a folder that cannot be created", func(r *copyRun) { r.fake.failMkdir = errScripted }, errScripted},
		{"a message that cannot be written", func(r *copyRun) { r.fake.failStream = func(string) error { return errScripted } }, errScripted},
		{"a stop between folders", func(r *copyRun) { r.script.onExec = cancelOn("SET folders_total=?", r.cancel) }, context.Canceled},
		{"a stop inside a batch", func(r *copyRun) { r.fake.failStream = cancelThenWrite(r.cancel) }, context.Canceled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run := newCopyRun(t, remoteFaults{})
			c.setup(run)
			if err := run.copy(t); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func cancelOn(fragment string, cancel context.CancelFunc) func(string) {
	return func(query string) {
		if strings.Contains(query, fragment) {
			cancel()
		}
	}
}

func cancelThenWrite(cancel context.CancelFunc) func(string) error {
	return func(string) error {
		cancel()
		return nil
	}
}
