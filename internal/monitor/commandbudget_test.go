package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
	"time"
)

// A command that never returns used to hold the handler, its goroutine and the
// connection: the handler timeout cancels r.Context() and does not touch a
// child process, so the client was dropped at the socket write deadline with no
// HTTP response at all. Both readers now hang off the request context with a
// budget of their own, so the handler answers.
//
// Each case runs the handler in a goroutine, because the defect these guard
// against is a handler that does not return.
func TestAHangingReaderStillAnswers(t *testing.T) {
	cases := []struct {
		name    string
		arrange func(t *testing.T)
		call    func() *httptest.ResponseRecorder
		status  int
	}{
		{
			name:    "the process listing",
			arrange: func(t *testing.T) { hangEvery(t, &psCommand, &psBudget) },
			call: func() *httptest.ResponseRecorder {
				recorder := httptest.NewRecorder()
				Processes(recorder, httptest.NewRequest(http.MethodGet, "/system/processes", nil))
				return recorder
			},
			// ps was killed, so there is no table to read.
			status: http.StatusInternalServerError,
		},
		{
			name:    "the server log",
			arrange: func(t *testing.T) { hangEvery(t, &logCommand, &logBudget) },
			call: func() *httptest.ResponseRecorder {
				recorder := httptest.NewRecorder()
				handlers := &Handlers{}
				handlers.ServerLog(recorder, httptest.NewRequest(http.MethodGet, "/system/log?source=panel", nil))
				return recorder
			},
			// The reader's own error is ignored by design; an empty log is the
			// answer, and the point is that one arrives.
			status: http.StatusOK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.arrange(t)
			answered := make(chan *httptest.ResponseRecorder, 1)
			go func() { answered <- tc.call() }()
			select {
			case recorder := <-answered:
				if recorder.Code != tc.status {
					t.Errorf("status = %d, want %d (body %s)", recorder.Code, tc.status, recorder.Body.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the handler did not answer; the command holds it")
			}
		})
	}
}

// hangEvery replaces a reader with a command that never exits, under a budget
// short enough for a test.
func hangEvery(t *testing.T, command *func(ctx context.Context, name string, arg ...string) *exec.Cmd, budget *time.Duration) {
	t.Helper()
	previousCommand, previousBudget := *command, *budget
	t.Cleanup(func() { *command, *budget = previousCommand, previousBudget })
	*budget = 100 * time.Millisecond
	*command = sleepForever
}

func sleepForever(ctx context.Context, _ string, _ ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 30")
}
