package appruntime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"servika/internal/config"
)

// The runtime job takes one fixed unit name, and the guard in front of it is a
// `systemctl is-active` probe, so a second request that arrives while one
// operation runs reaches startOp and is refused by systemd-run. Truncating the
// log and overwriting the descriptor before the launch destroyed the running
// job's only record and left the screen naming a runtime that never started.

// opPaths points the job's three files at a temporary directory, so a test
// never touches /opt/servika.
func opPaths(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SERVIKA_RUNTIMEOP_LOG", filepath.Join(dir, "runtime-op.log"))
	t.Setenv("SERVIKA_RUNTIMEOP_STATE", filepath.Join(dir, "runtime-op.json"))
	t.Setenv("SERVIKA_RUNTIMEOP_WRAPPER", filepath.Join(dir, "runtime-op.sh"))
	return dir
}

// stubLaunch captures the script that would have been run, or fails the launch,
// so the job surface works on a host without systemd.
func stubLaunch(t *testing.T, started *string, failure error) {
	t.Helper()
	original := launchOp
	launchOp = func(script string) error {
		if started != nil {
			*started = script
		}
		return failure
	}
	t.Cleanup(func() { launchOp = original })
}

var errRefused = errors.New("systemd-run: refused")

// The unit clears the log itself, so only an operation that really started
// clears it.
func TestTheOperationClearsItsOwnLogRatherThanThePanel(t *testing.T) {
	opPaths(t)
	logPath := config.RuntimeOpLog()
	if err := os.WriteFile(logPath, []byte("output of an older run\n"), 0o640); err != nil {
		t.Fatalf("seed the log: %v", err)
	}
	var script string
	stubLaunch(t, &script, nil)

	if err := startOp(opDescriptor{Kind: "node", Version: "22", Action: "install"},
		nodeInstallScript("22")); err != nil {
		t.Fatalf("startOp: %v", err)
	}

	if !strings.Contains(readOpLog(), "older run") {
		t.Error("the panel cleared the log itself, so a refused launch destroys a running job's record")
	}
	if !strings.HasPrefix(script, "#!/usr/bin/env bash\n: > "+config.ShellQuote(logPath)+"\n") {
		t.Errorf("the operation does not clear its own log first:\n%s", script)
	}
	if !strings.Contains(script, "echo '======== node 22 install ========'") {
		t.Errorf("the operation does not write its own header:\n%s", script)
	}
}

// A launch systemd refuses must leave every file the screen reads exactly as it
// was, or the running operation is reported as the one that never started.
func TestARefusedLaunchLeavesTheRunningOperationAlone(t *testing.T) {
	dir := opPaths(t)
	if err := os.WriteFile(config.RuntimeOpLog(), []byte("the running job's output\n"), 0o640); err != nil {
		t.Fatalf("seed the log: %v", err)
	}
	running := []byte(`{"kind":"python","version":"3.12","action":"install"}`)
	if err := os.WriteFile(config.RuntimeOpState(), running, 0o640); err != nil {
		t.Fatalf("seed the descriptor: %v", err)
	}
	stubLaunch(t, nil, errRefused)

	if err := startOp(opDescriptor{Kind: "node", Version: "22", Action: "remove"},
		nodeRemoveScript("22")); err == nil {
		t.Fatal("startOp reported success for a refused launch")
	}

	if got := readOpLog(); got != "the running job's output\n" {
		t.Errorf("the log now reads %q", got)
	}
	if got := readOpDescriptor(); got.Kind != "python" || got.Version != "3.12" {
		t.Errorf("the descriptor now reads %+v, want the running install of Python 3.12", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "runtime-op.json.tmp")); err == nil {
		t.Error("the staged descriptor was left behind")
	}
}

// The accepted launch is what installs the descriptor, so the screen names the
// operation that is actually running.
func TestAnAcceptedLaunchInstallsTheDescriptor(t *testing.T) {
	opPaths(t)
	stubLaunch(t, nil, nil)

	if err := startOp(opDescriptor{Kind: "node", Version: "22", Action: "install"},
		nodeInstallScript("22")); err != nil {
		t.Fatalf("startOp: %v", err)
	}

	got := readOpDescriptor()
	if got.Kind != "node" || got.Version != "22" || got.Action != "install" {
		t.Errorf("the descriptor reads %+v, want the install of Node 22", got)
	}
}
