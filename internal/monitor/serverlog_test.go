package monitor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

// The log screen is what an operator opens when the panel is misbehaving. Its
// reader's error was discarded, so a journalctl that never ran answered 200
// with no lines, which is exactly what a unit that logged nothing looks like:
// the one screen that should have shown the failure reported a quiet server.

// stubLogCommand stands in for the host's journalctl and tail.
func stubLogCommand(t *testing.T, run func(ctx context.Context, name string, arg ...string) *exec.Cmd) {
	t.Helper()
	previous := logCommand
	t.Cleanup(func() { logCommand = previous })
	logCommand = run
}

// readLog asks for one source and returns the response.
func readLog(source string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handlers := &Handlers{}
	handlers.ServerLog(recorder, httptest.NewRequest(http.MethodGet, "/system/log?source="+source, nil))
	return recorder
}

// linesOf reads the log lines out of an accepted answer.
func linesOf(t *testing.T, recorder *httptest.ResponseRecorder) []string {
	t.Helper()
	var body struct {
		Lines []string `json:"lines"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("the answer is not JSON: %s", recorder.Body.String())
	}
	return body.Lines
}

// A reader that cannot be started at all is the case an operator cannot guess
// at: no output, no exit status worth showing, and previously no sign of it.
func TestALogReaderThatCannotRunIsReported(t *testing.T) {
	stubLogCommand(t, func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/nonexistent/journalctl")
	})

	recorder := readLog("panel")

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body)
	}
	if !strings.Contains(recorder.Body.String(), "the log could not be read") {
		t.Errorf("the refusal does not say what happened: %s", recorder.Body)
	}
}

// A reader that RAN and complained has told the operator something. Its message
// is worth more than a refusal, so it is served as the log.
func TestAReaderThatComplainedIsStillShown(t *testing.T) {
	stubLogCommand(t, func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "echo 'tail: cannot open the file'; exit 1")
	})

	recorder := readLog("nginx")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}
	if lines := linesOf(t, recorder); len(lines) != 1 || !strings.Contains(lines[0], "cannot open") {
		t.Errorf("the reader's own message was dropped: %v", lines)
	}
}

// A unit that has genuinely logged nothing still answers 200 with no lines,
// which is the fact this endpoint exists to report.
func TestAnEmptyLogIsStillAnEmptyLog(t *testing.T) {
	stubLogCommand(t, func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "true")
	})

	recorder := readLog("panel")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}
	if lines := linesOf(t, recorder); len(lines) != 0 {
		t.Errorf("lines = %v, want none", lines)
	}
}

// A source outside both allowlists is still refused before anything runs.
func TestAnUnknownSourceIsRefusedBeforeTheReaderRuns(t *testing.T) {
	stubLogCommand(t, func(context.Context, string, ...string) *exec.Cmd {
		t.Error("a reader ran for a source that is not allowed")
		return exec.Command("/bin/sh", "-c", "true")
	})

	recorder := readLog("../../etc/passwd")

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body)
	}
}

// The requested line count is folded into the range the readers serve, and the
// bound reaches the command rather than being computed and dropped.
func TestTheRequestedLineCountIsBounded(t *testing.T) {
	for _, tc := range []struct{ asked, want string }{
		{asked: "", want: "200"},
		{asked: "10", want: "200"},
		{asked: "500", want: "500"},
		{asked: "9000", want: "1000"},
	} {
		t.Run("last="+tc.asked, func(t *testing.T) {
			var got string
			stubLogCommand(t, func(ctx context.Context, _ string, arg ...string) *exec.Cmd {
				for i, a := range arg {
					if a == "-n" && i+1 < len(arg) {
						got = arg[i+1]
					}
				}
				return exec.CommandContext(ctx, "/bin/sh", "-c", "true")
			})

			recorder := httptest.NewRecorder()
			handlers := &Handlers{}
			handlers.ServerLog(recorder, httptest.NewRequest(http.MethodGet, "/system/log?source=panel&last="+tc.asked, nil))

			if got != tc.want {
				t.Errorf("the reader was asked for %q lines, want %q", got, tc.want)
			}
		})
	}
}
