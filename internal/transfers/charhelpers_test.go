package transfers

import (
	"context"
	"database/sql/driver"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// logLines collects what a migration step logs, one formatted line per call.
type logLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *logLines) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logLines) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

func (l *logLines) joined() string { return strings.Join(l.all(), "\n") }

// assertLog fails the test unless the log lines are exactly want.
func assertLog(t *testing.T, log *logLines, want ...string) {
	t.Helper()
	if got := log.all(); !reflect.DeepEqual(got, want) {
		t.Fatalf("log =\n%q\nwant\n%q", got, want)
	}
}

// assertLogHolds fails the test unless some log line holds each fragment.
func assertLogHolds(t *testing.T, log *logLines, fragments ...string) {
	t.Helper()
	joined := log.joined()
	for _, fragment := range fragments {
		if !strings.Contains(joined, fragment) {
			t.Errorf("log %q lacks %q", joined, fragment)
		}
	}
}

// assertErrText fails the test unless err reads want; an empty want means nil.
func assertErrText(t *testing.T, err error, want string) {
	t.Helper()
	got := ""
	if err != nil {
		got = err.Error()
	}
	if got != want {
		t.Fatalf("err = %q, want %q", got, want)
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s =\n%q\nwant\n%q", path, got, want)
	}
}

// assertExecArgs fails the test unless the statements holding fragment ran with
// exactly the argument lists in want, in order.
func assertExecArgs(t *testing.T, s *sqlScript, fragment string, want ...[]driver.Value) {
	t.Helper()
	var got [][]driver.Value
	for _, statement := range s.execsContaining(fragment) {
		got = append(got, statement.args)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statements holding %q ran with\n%v\nwant\n%v", fragment, got, want)
	}
}

// countRow is the single COUNT(*) row a lookup answers: 1 when held, else 0.
func countRow(held bool) [][]driver.Value {
	if held {
		return [][]driver.Value{{int64(1)}}
	}
	return [][]driver.Value{{int64(0)}}
}

// remoteAnswers answers each command by the first fragment its last argument
// holds, which for ssh is the remote command. A command no fragment names exits
// 127. The fragments must not overlap, because a map has no order.
func remoteAnswers(t *testing.T, answers map[string]commandAnswer) *commandRecorder {
	t.Helper()
	return withCommandScript(t, func(argv []string) commandAnswer {
		last := argv[len(argv)-1]
		for fragment, answer := range answers {
			if strings.Contains(last, fragment) {
				return answer
			}
		}
		return commandAnswer{stderr: "unscripted: " + last, exit: 127}
	})
}

// sqlImports records what the SQL import seam received.
type sqlImports struct {
	mu      sync.Mutex
	targets []string
	bodies  []string
	fail    error
}

func withSQLImports(t *testing.T, fail error) *sqlImports {
	t.Helper()
	rec := &sqlImports{fail: fail}
	setForTest(t, &importSQLDump, rec.importDump)
	return rec
}

// importDump reads the whole dump, as the real import does, so the completion
// marker filter sees the end of the stream before the caller checks it.
func (s *sqlImports) importDump(_ context.Context, target string, dump io.Reader) error {
	body, err := io.ReadAll(dump)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targets = append(s.targets, target)
	s.bodies = append(s.bodies, string(body))
	if err != nil {
		return err
	}
	return s.fail
}

// dumpFile writes a gzip dump holding body, for a faked ssh to print.
func dumpFile(t *testing.T, body string) string {
	t.Helper()
	return writeFile(t, "dump.sql.gz", gzipBytes(t, []byte(body)))
}

const completeDump = "CREATE TABLE t(id int);\n-- Dump completed on 2026-09-11\n"
