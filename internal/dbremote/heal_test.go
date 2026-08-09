package dbremote

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// withTempDropIn points the managed file at a temporary directory and stubs the
// process that would restart MariaDB, returning what that process was asked to
// do. The heal must be exercisable without root and without a database server.
func withTempDropIn(t *testing.T) (path string, calls *[]string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "zzz-servika-remote-db.cnf")

	previousPath := dropInPath
	setDropInPath(path)
	t.Cleanup(func() { setDropInPath(previousPath) })

	var mu sync.Mutex
	var seen []string
	previousCommand := healCommand
	healCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		mu.Lock()
		seen = append(seen, name+" "+strings.Join(args, " "))
		mu.Unlock()
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { healCommand = previousCommand })
	return path, &seen
}

// MEASURED on MariaDB 10.11: `0.0.0.0` produces an IPv4 listener only and `::`
// an IPv6 listener only. Only `*` listens on both. The panel is dual stack
// everywhere, so writing the value the MariaDB documentation shows would leave a
// customer on an IPv6-only network unable to reach a feature the screen calls on.
func TestTheBindValueListensOnBothFamilies(t *testing.T) {
	path, _ := withTempDropIn(t)

	if _, err := writeDropIn(true); err != nil {
		t.Fatalf("writeDropIn: %v", err)
	}
	body, err := os.ReadFile(path) // #nosec G304 -- test-owned path under t.TempDir().
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "bind-address = *") {
		t.Errorf("the drop-in does not bind both families:\n%s", body)
	}
	for _, wrong := range []string{"bind-address = 0.0.0.0", "bind-address = ::"} {
		if strings.Contains(string(body), wrong) {
			t.Errorf("the drop-in uses %q, which listens on one family only", wrong)
		}
	}
}

// Turning the feature off REMOVES the file rather than writing 127.0.0.1 into
// it, so the installer's own hardening line is what takes effect again and the
// bind is decided in exactly one place.
func TestTurningItOffRemovesTheFileRatherThanOverwritingIt(t *testing.T) {
	path, _ := withTempDropIn(t)

	if _, err := writeDropIn(true); err != nil {
		t.Fatalf("writeDropIn(true): %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the drop-in was not written: %v", err)
	}
	changed, err := writeDropIn(false)
	if err != nil {
		t.Fatalf("writeDropIn(false): %v", err)
	}
	if !changed {
		t.Error("writeDropIn(false) reported no change while removing the file")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		body, _ := os.ReadFile(path) // #nosec G304 -- test-owned path under t.TempDir().
		t.Errorf("the file survived being turned off:\n%s", body)
	}
}

// A startup heal must not touch the file's mtime when nothing changed, and must
// not restart MariaDB at all: the server that just booted already read the file,
// so a restart would drop every site's connections to change nothing.
func TestTheStartupHealNeverRestartsTheServer(t *testing.T) {
	_, calls := withTempDropIn(t)

	if _, err := writeDropIn(true); err != nil {
		t.Fatalf("writeDropIn: %v", err)
	}
	changed, err := writeDropIn(true)
	if err != nil {
		t.Fatalf("second writeDropIn: %v", err)
	}
	if changed {
		t.Error("an unchanged drop-in was rewritten")
	}
	// HealBind with no database returns before doing anything; the point of the
	// assertion is that nothing in this file's startup path shells out at all.
	HealBind(nil)
	if len(*calls) != 0 {
		t.Errorf("the startup path ran %v", *calls)
	}
}

// "systemctl restart returned 0" is not proof that the panel can use the server.
// A bind address MariaDB accepts but the panel cannot reach would otherwise be
// left in place, taking every site's database with it.
func TestAServerThePanelCannotReachRollsTheChangeBack(t *testing.T) {
	path, calls := withTempDropIn(t)

	// A database whose Ping always fails stands in for a server that came back
	// unusable.
	db := failingPingDB(t)

	err := Apply(context.Background(), db, true)
	if !errors.Is(err, ErrBindVerifyFailed) {
		t.Fatalf("Apply = %v, want ErrBindVerifyFailed", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		body, _ := os.ReadFile(path) // #nosec G304 -- test-owned path under t.TempDir().
		t.Errorf("the drop-in survived a failed apply:\n%s", body)
	}
	// Twice: once to apply, once to put the server back on the previous file.
	if got := len(*calls); got != 2 {
		t.Errorf("systemctl ran %d times (%v), want the apply and the rollback", got, *calls)
	}
}

// The rollback restores the PREVIOUS contents, not merely "no file": turning the
// feature off from a failing state must leave the file that was working.
func TestAFailedApplyRestoresTheFileThatWasThere(t *testing.T) {
	path, _ := withTempDropIn(t)

	if _, err := writeDropIn(true); err != nil {
		t.Fatalf("writeDropIn: %v", err)
	}
	before, err := os.ReadFile(path) // #nosec G304 -- test-owned path under t.TempDir().
	if err != nil {
		t.Fatal(err)
	}

	if err := Apply(context.Background(), failingPingDB(t), false); !errors.Is(err, ErrBindVerifyFailed) {
		t.Fatalf("Apply = %v, want ErrBindVerifyFailed", err)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test-owned path under t.TempDir().
	if err != nil {
		t.Fatalf("the previous drop-in was not restored: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("the restored file differs:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// A restart that fails outright must not be reported as a change that landed.
func TestARestartFailureIsNotReportedAsSuccess(t *testing.T) {
	path, _ := withTempDropIn(t)

	previous := healCommand
	healCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "false")
	}
	t.Cleanup(func() { healCommand = previous })

	if err := Apply(context.Background(), nil, true); err == nil {
		t.Fatal("Apply reported success while the restart failed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the drop-in survived a failed restart")
	}
}

// failingPingDB is a database whose every connection attempt fails, standing in
// for a MariaDB that came back from a restart in a state the panel cannot use.
func failingPingDB(t *testing.T) *sql.DB {
	t.Helper()
	unreachableOnce.Do(func() { sql.Register("dbremote-unreachable", unreachableDriver{}) })

	// The verification retries until its deadline, which is right on a real host
	// and would make this test wait a minute and a half.
	previous := restartTimeout
	restartTimeout = 200 * time.Millisecond
	t.Cleanup(func() { restartTimeout = previous })

	db, err := sql.Open("dbremote-unreachable", "")
	if err != nil {
		t.Fatalf("open unreachable database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

var unreachableOnce sync.Once

type unreachableDriver struct{}

func (unreachableDriver) Open(string) (driver.Conn, error) { return nil, errUnreachable }

var errUnreachable = errors.New("connection refused")
