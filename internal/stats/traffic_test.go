package stats

import (
	"testing"
	"time"
)

// The rows are keyed by the log's $time_local and the refresh reads them back by
// the Go clock. Two clocks for one column disagree for the length of the offset
// at every month boundary, and the figure that lands in domains.traffic_kb is
// what the reseller traffic gate refuses on.
func TestTheRefreshReadsTheMonthTheRowsAreWrittenUnder(t *testing.T) {
	previous := time.Local
	time.Local = time.FixedZone("UTC+3", 3*60*60)
	t.Cleanup(func() { time.Local = previous })

	// Half past midnight local on the first of a month is half past nine the
	// previous evening in UTC: exactly where the two clocks name different
	// months.
	instant := time.Date(2026, 4, 1, 0, 30, 0, 0, time.Local)
	if instant.UTC().Format("2006-01") == instant.Format("2006-01") {
		t.Fatal("this instant does not separate the two clocks, so the test proves nothing")
	}

	line := `192.0.2.1 - - [` + instant.Format("02/Jan/2006:15:04:05 -0700") +
		`] "GET / HTTP/1.1" 200 1234 "-" "agent"`
	written, _, ok := parseTrafficLine(line)
	if !ok {
		t.Fatalf("parseTrafficLine rejected %q", line)
	}
	if got := trafficMonth(instant); got != written {
		t.Errorf("the refresh reads %q while the rows are written under %q", got, written)
	}
}

func TestParseTrafficLineUsesRequestMonthAndResponseBytes(t *testing.T) {
	line := `192.0.2.1 - - [17/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "agent"`
	month, bytes, ok := parseTrafficLine(line)
	if !ok {
		t.Fatal("parseTrafficLine() rejected a valid combined access log line")
	}
	if month != "2026-07" || bytes != 1234 {
		t.Fatalf("parseTrafficLine() = (%q, %d), want (%q, %d)", month, bytes, "2026-07", 1234)
	}
}

func TestParseTrafficLineTreatsMissingByteCountAsZero(t *testing.T) {
	line := `192.0.2.1 - - [17/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 304 - "-" "agent"`
	month, bytes, ok := parseTrafficLine(line)
	if !ok || month != "2026-07" || bytes != 0 {
		t.Fatalf("parseTrafficLine() = (%q, %d, %t), want (%q, 0, true)", month, bytes, ok, "2026-07")
	}
}
