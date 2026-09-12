package stats

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One aggregation pass reads an access log from where it stopped last time and
// ADDS what it finds to the stored month. Everything here is about that add
// happening exactly once: a pass that recounts inflates the figure a reseller's
// traffic ceiling is measured against, and nothing later corrects it.

// The whole log is counted on the first pass, and the cursor is left where the
// reading stopped so the next pass starts there.
func TestAFirstPassCountsTheWholeLogAndRecordsWhereItStopped(t *testing.T) {
	captureTrafficLog(t)
	script := newTrafficScript()
	script.cursorErr = sql.ErrNoRows
	db := trafficDB(t, script)

	if !aggregateDomain(db, 7, "example.com") {
		t.Fatal("a first pass was refused")
	}
	got := script.argsOf(t, "INSERT INTO domain_traffic(")
	if len(got) != 3 || got[0] != int64(7) || got[1] != "2026-01" || got[2] != int64(4*4096) {
		t.Errorf("traffic row = %v, want four lines of 4096 bytes in 2026-01", got)
	}
	size := int64(4 * len(trafficLine))
	cursor := script.argsOf(t, "INSERT INTO domain_traffic_cursor(")
	if len(cursor) != 3 || cursor[1] != size || cursor[2] != size {
		t.Errorf("cursor row = %v, want the whole log consumed (%d bytes)", cursor, size)
	}
}

// A second pass over an unchanged log counts nothing: the offset already equals
// the size, so there is nothing to add.
func TestASecondPassOverAnUnchangedLogCountsNothing(t *testing.T) {
	captureTrafficLog(t)
	script := newTrafficScript()
	size := int64(4 * len(trafficLine))
	script.offset, script.size = size, size
	db := trafficDB(t, script)

	if !aggregateDomain(db, 7, "example.com") {
		t.Fatal("an unchanged log was reported as a failed pass")
	}
	if script.inserts() != 0 {
		t.Error("an unchanged log was counted again")
	}
	if !script.ran("UPDATE domains SET traffic_kb") {
		t.Error("the stored figure was not refreshed")
	}
}

// Only the new part of a growing log is counted.
func TestOnlyTheNewLinesOfAGrowingLogAreCounted(t *testing.T) {
	captureTrafficLog(t)
	script := newTrafficScript()
	// Two of the four lines were already counted last pass.
	script.offset = int64(2 * len(trafficLine))
	script.size = script.offset
	db := trafficDB(t, script)

	if !aggregateDomain(db, 7, "example.com") {
		t.Fatal("a growing log was reported as a failed pass")
	}
	if got := script.argsOf(t, "INSERT INTO domain_traffic("); got[2] != int64(2*4096) {
		t.Errorf("counted %v bytes, want only the two new lines", got[2])
	}
}

// A log that SHRANK was rotated, so the stored offset points into a different
// file. Counting from there would attribute somebody else's lines; the pass
// restarts at zero instead.
func TestARotatedLogIsReadFromTheStart(t *testing.T) {
	for _, tc := range []struct {
		name           string
		offset, stored int64
	}{
		{name: "the log is shorter than the offset", offset: 1 << 20, stored: 1 << 20},
		// The offset alone still fits this log, so only the recorded size says
		// the file was replaced. Reading from the offset here would count the
		// new file's first lines as if they were already accounted.
		{name: "the log is shorter than the recorded size",
			offset: int64(2 * len(trafficLine)), stored: 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captureTrafficLog(t)
			script := newTrafficScript()
			script.offset, script.size = tc.offset, tc.stored
			db := trafficDB(t, script)

			if !aggregateDomain(db, 7, "example.com") {
				t.Fatal("a rotated log was reported as a failed pass")
			}
			if got := script.argsOf(t, "INSERT INTO domain_traffic("); got[2] != int64(4*4096) {
				t.Errorf("counted %v bytes, want the whole rotated log", got[2])
			}
		})
	}
}

// A domain name that is not a domain name never reaches a path: the log path is
// built by concatenation, so anything else is a way out of the log directory.
func TestAnUnsafeDomainNameIsRefusedBeforeAPathIsBuilt(t *testing.T) {
	logged := captureTrafficLog(t)
	script := newTrafficScript()
	db := trafficDB(t, script)

	for _, name := range []string{"../../etc/passwd", "example.com/../x", "Example.COM", "localhost", ""} {
		if aggregateDomain(db, 7, name) {
			t.Errorf("%q was accepted as a domain name", name)
		}
	}
	if script.ran("INSERT INTO domain_traffic(") {
		t.Error("an unsafe name still wrote traffic")
	}
	if !strings.Contains(logged.String(), "traffic rejected unsafe domain name for domain=7") {
		t.Errorf("the refusal was not logged: %s", logged.String())
	}
}

// A domain with no access log yet is not a failure to report: it has served
// nothing. The stored figure is still refreshed, so a month rollover shows zero
// rather than last month's total.
func TestADomainWithNoLogStillRefreshesTheStoredFigure(t *testing.T) {
	captureTrafficLog(t)
	script := newTrafficScript()
	db := trafficDB(t, script)

	if aggregateDomain(db, 7, "nolog.example") {
		t.Error("a domain with no log was reported as a counted pass")
	}
	if !script.ran("UPDATE domains SET traffic_kb") {
		t.Error("the stored figure was not refreshed")
	}
}

// A write that fails leaves the cursor alone, so the same bytes are counted on
// the next pass rather than lost or doubled.
func TestAFailedWriteLeavesTheCursorWhereItWas(t *testing.T) {
	for _, tc := range []struct {
		name, failing, logged string
		beginErr, commitErr   error
	}{
		{
			name: "the transaction will not start", beginErr: errors.New("too many connections"),
			logged: "begin traffic update domain=7",
		},
		{
			name: "the traffic row will not merge", failing: "INSERT INTO domain_traffic(",
			logged: "traffic upsert domain=7 month=2026-01",
		},
		{
			name: "the cursor row will not merge", failing: "INSERT INTO domain_traffic_cursor(",
			logged: "traffic cursor update domain=7",
		},
		{
			name: "the transaction will not commit", commitErr: errors.New("lost connection"),
			logged: "commit traffic update domain=7",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captured := captureTrafficLog(t)
			script := newTrafficScript()
			script.cursorErr = sql.ErrNoRows
			script.beginErr, script.commitErr = tc.beginErr, tc.commitErr
			if tc.failing != "" {
				script.fail[tc.failing] = errors.New("refused")
			}
			db := trafficDB(t, script)

			if aggregateDomain(db, 7, "example.com") {
				t.Error("a failed write was reported as a completed pass")
			}
			if !strings.Contains(captured.String(), tc.logged) {
				t.Errorf("the failure was not logged as %q: %s", tc.logged, captured.String())
			}
			if script.ran("UPDATE domains SET traffic_kb") {
				t.Error("the stored figure was refreshed from a pass that did not finish")
			}
		})
	}
}

// A log this process cannot open is skipped rather than counted as zero.
func TestALogThatCannotBeOpenedIsSkipped(t *testing.T) {
	captured := captureTrafficLog(t)
	unreadable := filepath.Join(strings.TrimSuffix(trafficLogRoot, "/"), "closed.example.access.log")
	if err := os.WriteFile(unreadable, []byte(trafficLine), 0o000); err != nil {
		t.Fatalf("write the access log: %v", err)
	}
	script := newTrafficScript()
	script.cursorErr = sql.ErrNoRows
	db := trafficDB(t, script)

	if aggregateDomain(db, 7, "closed.example") {
		t.Error("an unreadable log was reported as a counted pass")
	}
	if !strings.Contains(captured.String(), "traffic log open domain=7") {
		t.Errorf("the failure was not logged: %s", captured.String())
	}
}

// A line the parser does not recognise is skipped, and the lines around it are
// still counted: one malformed entry must not throw away a month.
func TestAnUnparsableLineDoesNotThrowAwayTheRest(t *testing.T) {
	captureTrafficLog(t)
	broken := "this is not an access log line\n"
	if err := os.WriteFile(filepath.Join(strings.TrimSuffix(trafficLogRoot, "/"), "example.com.access.log"),
		[]byte(trafficLine+broken+trafficLine), 0o600); err != nil {
		t.Fatalf("write the access log: %v", err)
	}
	script := newTrafficScript()
	script.cursorErr = sql.ErrNoRows
	db := trafficDB(t, script)

	if !aggregateDomain(db, 7, "example.com") {
		t.Fatal("one bad line failed the whole pass")
	}
	if got := script.argsOf(t, "INSERT INTO domain_traffic("); got[2] != int64(2*4096) {
		t.Errorf("counted %v bytes, want the two good lines", got[2])
	}
}

// The stored kilobyte figure is this month's bytes divided by 1024, on the row
// the pass was for.
func TestTheStoredFigureIsThisMonthInKilobytes(t *testing.T) {
	captureTrafficLog(t)
	script := newTrafficScript()
	size := int64(4 * len(trafficLine))
	script.offset, script.size = size, size
	db := trafficDB(t, script)

	aggregateDomain(db, 7, "example.com")

	got := script.argsOf(t, "UPDATE domains SET traffic_kb")
	if len(got) != 2 || got[1] != int64(7) {
		t.Errorf("refresh args = %v, want the figure and domain 7", got)
	}
	if _, ok := got[0].(int64); !ok {
		t.Errorf("the stored figure is %T, want a kilobyte count", got[0])
	}
}

// AggregateAll walks the domain list and reports how many domains it counted.
func TestEveryDomainInTheListIsWalked(t *testing.T) {
	captureTrafficLog(t)
	script := newTrafficScript()
	script.cursorErr = sql.ErrNoRows
	script.domains = [][]driver.Value{
		{int64(7), "example.com"},
		{int64(8), "nolog.example"},
	}
	db := trafficDB(t, script)

	if got := AggregateAll(db); got != 1 {
		t.Errorf("counted %d domains, want only the one with a log", got)
	}
}
