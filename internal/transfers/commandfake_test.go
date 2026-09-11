package transfers

import (
	"context"
	"os/exec"
	"slices"
	"strconv"
	"sync"
	"testing"
)

// commandAnswer is what one faked command prints and how it exits.
type commandAnswer struct {
	output string
	// file, when set, is printed instead of output, for binary output such as a
	// gzip dump that cannot travel as an argument.
	file   string
	stderr string
	exit   int
}

// commandRecorder stands in for every local process the package starts through
// commandContext, so ssh, rsync, tar, mysql and chown can run their whole
// sequence in a test. Each command is recorded by its argv and replaced with a
// shell that prints the scripted answer.
type commandRecorder struct {
	mu      sync.Mutex
	calls   [][]string
	cmds    []*exec.Cmd
	respond func(argv []string) commandAnswer
}

// withCommandScript installs a recorder that answers each argv with respond.
func withCommandScript(t *testing.T, respond func(argv []string) commandAnswer) *commandRecorder {
	t.Helper()
	recorder := &commandRecorder{respond: respond}
	setForTest(t, &commandContext, recorder.command)
	return recorder
}

// withCommands installs a recorder under which every command succeeds with no
// output, except an argv that starts with one of fail, which exits 1 and prints
// "refused" on stderr.
func withCommands(t *testing.T, fail ...[]string) *commandRecorder {
	t.Helper()
	return withCommandScript(t, func(argv []string) commandAnswer {
		for _, prefix := range fail {
			if hasArgvPrefix(argv, prefix) {
				return commandAnswer{stderr: "refused", exit: 1}
			}
		}
		return commandAnswer{}
	})
}

func (r *commandRecorder) command(ctx context.Context, name string, arg ...string) *exec.Cmd {
	argv := append([]string{name}, arg...)
	answer := r.respond(argv)
	script, payload := `printf '%s' "$1"; printf '%s' "$3" >&2; exit "$2"`, answer.output
	if answer.file != "" {
		script, payload = `cat "$1"; printf '%s' "$3" >&2; exit "$2"`, answer.file
	}
	// The payload, the code and the stderr travel as positional arguments, never
	// inside the script text, so nothing a test scripts is parsed by the shell.
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script, "sh", payload, strconv.Itoa(answer.exit), answer.stderr)
	r.mu.Lock()
	r.calls = append(r.calls, argv)
	r.cmds = append(r.cmds, cmd)
	r.mu.Unlock()
	return cmd
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
