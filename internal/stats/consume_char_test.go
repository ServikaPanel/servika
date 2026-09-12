package stats

import (
	"fmt"
	"strings"
	"testing"
)

// The three guards the log parser puts between an untrusted access log and the
// panel's memory: a line it does not recognise, the line ceiling, and the path
// length. Each bounds work an attacker controls the size of.

// A line that is not a combined access log line is skipped, and it does not
// count towards the ceiling either.
func TestALineTheParserDoesNotRecogniseIsSkipped(t *testing.T) {
	log := strings.Join([]string{
		"not an access log line",
		`127.0.0.1 - - [17/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 42 "-" "Mozilla/5.0"`,
		"",
		"<html>an error page ended up in the log</html>",
	}, "\n")

	accumulated := newAccumulator()
	if err := accumulated.consume(strings.NewReader(log)); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if accumulated.requests != 1 || accumulated.lines != 1 {
		t.Errorf("requests = %d, lines = %d, want only the one real line",
			accumulated.requests, accumulated.lines)
	}
}

// The ceiling bounds the work one request can cause, no matter how large the
// log a tenant's own traffic grew it to.
func TestTheLineCeilingStopsTheParse(t *testing.T) {
	var log strings.Builder
	for i := range maxLines + 10 {
		fmt.Fprintf(&log, `127.0.0.1 - - [17/Jul/2026:12:00:00 +0000] "GET /%d HTTP/1.1" 200 1 "-" "Mozilla/5.0"`+"\n", i)
	}

	accumulated := newAccumulator()
	if err := accumulated.consume(strings.NewReader(log.String())); err != nil {
		t.Fatalf("consume: %v", err)
	}
	// The line that trips the ceiling is counted and then abandoned, so the
	// requests counter stops one short of it.
	if accumulated.lines != maxLines+1 || accumulated.requests != maxLines {
		t.Errorf("lines = %d, requests = %d, want the parse to stop at %d",
			accumulated.lines, accumulated.requests, maxLines)
	}
}

// A path is a tenant-controlled string that becomes a map key, so it is cut to
// 80 characters. The query string is dropped first, and the cut is applied to
// what is left.
func TestALongPathIsCutBeforeItBecomesAKey(t *testing.T) {
	long := "/" + strings.Repeat("a", 200)
	log := `127.0.0.1 - - [17/Jul/2026:12:00:00 +0000] "GET ` + long +
		`?q=` + strings.Repeat("b", 200) + ` HTTP/1.1" 200 1 "-" "Mozilla/5.0"` + "\n"

	accumulated := newAccumulator()
	if err := accumulated.consume(strings.NewReader(log)); err != nil {
		t.Fatalf("consume: %v", err)
	}
	want := "GET " + long[:80]
	if accumulated.paths[want] != 1 {
		t.Errorf("paths = %v, want the single key %q", accumulated.paths, want)
	}
}

// A byte count that is not a number is skipped rather than failing the line:
// the request still happened and still counts.
func TestARequestWithNoByteCountStillCounts(t *testing.T) {
	log := `127.0.0.1 - - [17/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 304 - "-" "Mozilla/5.0"` + "\n"

	accumulated := newAccumulator()
	if err := accumulated.consume(strings.NewReader(log)); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if accumulated.requests != 1 || accumulated.totalBytes != 0 {
		t.Errorf("requests = %d, bytes = %d, want one request of no bytes",
			accumulated.requests, accumulated.totalBytes)
	}
}

// Only the last 40 requests are kept, because the screen shows 20 of them and
// an unbounded list is the log's own size held in memory.
func TestOnlyTheLastFortyRequestsAreKept(t *testing.T) {
	var log strings.Builder
	for i := range 60 {
		fmt.Fprintf(&log, `127.0.0.1 - - [17/Jul/2026:12:00:00 +0000] "GET /%d HTTP/1.1" 200 1 "-" "Mozilla/5.0"`+"\n", i)
	}

	accumulated := newAccumulator()
	if err := accumulated.consume(strings.NewReader(log.String())); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(accumulated.recent) != 40 {
		t.Errorf("kept %d requests, want 40", len(accumulated.recent))
	}
}
