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

// The process list is the panel's window onto a busy server. Nothing here was
// reachable in a test, because it shells out to ps, whose table differs on every
// platform. A seam carries that, so these tests pin what the endpoint asks ps
// for and what it does with the answer.

// fakePS stands in for ps and records the argument list it was given.
func fakePS(t *testing.T, output string, fail bool) *[]string {
	t.Helper()
	var asked []string
	previous := psCommand
	t.Cleanup(func() { psCommand = previous })
	psCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		asked = append([]string{name}, args...)
		if fail {
			return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 1")
		}
		return exec.CommandContext(ctx, "/bin/echo", output)
	}
	return &asked
}

// processList calls the endpoint and returns the decoded rows.
func processList(t *testing.T, query string) (int, []Process) {
	t.Helper()
	response := httptest.NewRecorder()
	Processes(response, httptest.NewRequest(http.MethodGet, "/system/processes"+query, nil))
	if response.Code != http.StatusOK {
		return response.Code, nil
	}
	var rows []Process
	if err := json.Unmarshal(response.Body.Bytes(), &rows); err != nil {
		t.Fatalf("the answer is not a process list: %s", response.Body.String())
	}
	return response.Code, rows
}

// A line of ps output, in the column order the endpoint asks for.
func psLine(pid, user, cpu, mem, command string) string {
	return strings.Join([]string{pid, user, cpu, mem, command}, " ")
}

// The endpoint reads the five columns it asked for, in that order.
func TestEachColumnLandsInItsOwnField(t *testing.T) {
	fakePS(t, psLine("4211", "c_shop", "12.5", "3.25", "php-fpm: pool c_shop"), false)

	status, rows := processList(t, "")

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %v, want one", rows)
	}
	got := rows[0]
	if got.PID != 4211 || got.User != "c_shop" || got.CPU != 12.5 || got.Mem != 3.25 {
		t.Errorf("row = %+v", got)
	}
	if got.Command != "php-fpm: pool c_shop" {
		t.Errorf("command = %q, want the whole argument list", got.Command)
	}
}

// The sort is what makes the list useful on a loaded server, so it is asked of
// ps rather than done here, and only the two orders the screen offers exist.
func TestTheSortIsAskedOfPS(t *testing.T) {
	for query, want := range map[string]string{
		"":            "--sort=-pcpu",
		"?sort=cpu":   "--sort=-pcpu",
		"?sort=mem":   "--sort=-pmem",
		"?sort=magic": "--sort=-pcpu",
	} {
		asked := fakePS(t, psLine("1", "root", "0.0", "0.0", "init"), false)

		if status, _ := processList(t, query); status != http.StatusOK {
			t.Fatalf("%q answered %d", query, status)
		}
		if !strings.Contains(strings.Join(*asked, " "), want) {
			t.Errorf("%q asked ps for %v, want %q", query, *asked, want)
		}
	}
}

// The list is bounded, because a server runs thousands of processes and the
// screen shows a handful.
func TestTheListIsBounded(t *testing.T) {
	var lines []string
	for i := range 40 {
		lines = append(lines, psLine(string(rune('0'+i%10)), "root", "1.0", "1.0", "worker"))
	}
	output := strings.Join(lines, "\n")

	for _, tc := range []struct {
		query string
		want  int
	}{
		{query: "", want: 15},
		{query: "?n=3", want: 3},
		{query: "?n=0", want: 15},
		{query: "?n=-5", want: 15},
		{query: "?n=1000", want: 15},
		{query: "?n=many", want: 15},
	} {
		fakePS(t, output, false)

		status, rows := processList(t, tc.query)

		if status != http.StatusOK {
			t.Fatalf("%q answered %d", tc.query, status)
		}
		if len(rows) != tc.want {
			t.Errorf("%q returned %d rows, want %d", tc.query, len(rows), tc.want)
		}
	}
}

// A line the endpoint cannot read is skipped rather than reported as a process
// with no name, and a command longer than the column is cut with a mark that
// says so.
func TestAnUnreadableLineIsSkippedAndALongCommandIsCut(t *testing.T) {
	long := strings.Repeat("a", 200)
	fakePS(t, strings.Join([]string{
		"",
		"4211 c_shop 1.0",
		psLine("4212", "c_shop", "1.0", "1.0", long),
	}, "\n"), false)

	status, rows := processList(t, "")

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %v, want only the readable one", rows)
	}
	if !strings.HasSuffix(rows[0].Command, "…") || len([]rune(rows[0].Command)) != 121 {
		t.Errorf("command is %d runes and ends %q", len([]rune(rows[0].Command)), rows[0].Command)
	}
}

// A ps that fails is reported rather than answered with an empty list, which
// would read as an idle server.
func TestAFailedProcessListIsReported(t *testing.T) {
	fakePS(t, "", true)

	response := httptest.NewRecorder()
	Processes(response, httptest.NewRequest(http.MethodGet, "/system/processes", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", response.Code, response.Body)
	}
	if !strings.Contains(response.Body.String(), "failed to read process list") {
		t.Errorf("message = %s", response.Body.String())
	}
}
