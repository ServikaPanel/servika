package backups

import (
	"context"
	"os/exec"
	"slices"
	"strconv"
	"sync"
	"testing"
)

// commandRecorder stands in for every command the package runs through
// commandContext, so a backup, a restore or a transfer can run its whole sequence
// in a test without tar, rsync, mysql, lftp or ssh. Each command is recorded by
// its argv and replaced with a shell that prints the scripted output and exits
// with the scripted code.
type commandRecorder struct {
	mu      sync.Mutex
	calls   [][]string
	respond func(argv []string) (output string, exitCode int)
}

// withCommandScript installs a recorder that answers each argv with respond's
// output and exit code. respond runs before the command is returned, so it may
// also produce the files a real command would have written. It can run on a
// goroutine the test does not own, so it must report a failure through its exit
// code rather than through t.
func withCommandScript(t *testing.T, respond func(argv []string) (output string, exitCode int)) *commandRecorder {
	t.Helper()
	recorder := &commandRecorder{respond: respond}
	previous := commandContext
	commandContext = func(ctx context.Context, name string, arg ...string) *exec.Cmd {
		return recorder.command(ctx, append([]string{name}, arg...))
	}
	t.Cleanup(func() { commandContext = previous })
	return recorder
}

// withCommands installs a recorder under which every command succeeds with no
// output, except an argv that starts with one of fail, which exits 1.
func withCommands(t *testing.T, fail ...[]string) *commandRecorder {
	t.Helper()
	return withCommandScript(t, func(argv []string) (string, int) {
		for _, prefix := range fail {
			if hasArgvPrefix(argv, prefix) {
				return "", 1
			}
		}
		return "", 0
	})
}

func (r *commandRecorder) command(ctx context.Context, argv []string) *exec.Cmd {
	r.mu.Lock()
	r.calls = append(r.calls, argv)
	r.mu.Unlock()
	output, exitCode := r.respond(argv)
	// The output and the code travel as positional arguments, never inside the
	// script text, so nothing a test scripts is parsed by the shell.
	return exec.CommandContext(ctx, "/bin/sh", "-c", `printf '%s' "$1"; exit "$2"`, "sh", output, strconv.Itoa(exitCode))
}

func hasArgvPrefix(argv, prefix []string) bool {
	return len(argv) >= len(prefix) && slices.Equal(argv[:len(prefix)], prefix)
}

// argvs returns a copy of every recorded argv, in order.
func (r *commandRecorder) argvs() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]string, len(r.calls))
	for i, call := range r.calls {
		out[i] = slices.Clone(call)
	}
	return out
}

// ran reports whether an argv starting with prefix was recorded.
func (r *commandRecorder) ran(prefix ...string) bool {
	for _, argv := range r.argvs() {
		if hasArgvPrefix(argv, prefix) {
			return true
		}
	}
	return false
}

// setForTest replaces a package variable for one test.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}
