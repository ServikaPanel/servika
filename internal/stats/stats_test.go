package stats

import (
	"errors"
	"strings"
	"testing"
)

type failingReader struct {
	data []byte
	err  error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

func TestSummarizeLogReturnsScannerError(t *testing.T) {
	readErr := errors.New("log read failed")
	reader := &failingReader{
		data: []byte(`127.0.0.1 - - [17/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 42 "-" "curl/8.0"` + "\n"),
		err:  readErr,
	}
	summary := Summary{StatusGroup: map[string]int{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}}

	err := summarizeLog(reader, &summary)

	if !errors.Is(err, readErr) {
		t.Fatalf("summarizeLog() error = %v, want %v", err, readErr)
	}
}

func TestSummarizeLogBuildsSummary(t *testing.T) {
	log := strings.Join([]string{
		`127.0.0.1 - - [17/Jul/2026:12:00:00 +0000] "GET /?page=1 HTTP/1.1" 200 1048576 "-" "Mozilla/5.0"`,
		`127.0.0.2 - - [17/Jul/2026:12:01:00 +0000] "POST /login HTTP/1.1" 404 10 "-" "curl/8.0"`,
	}, "\n")
	summary := Summary{StatusGroup: map[string]int{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}}

	if err := summarizeLog(strings.NewReader(log), &summary); err != nil {
		t.Fatalf("summarizeLog() returned an unexpected error: %v", err)
	}
	if summary.TotalRequests != 2 {
		t.Fatalf("TotalRequests = %d, want 2", summary.TotalRequests)
	}
	if summary.UniqueIP != 2 {
		t.Fatalf("UniqueIP = %d, want 2", summary.UniqueIP)
	}
	if summary.BotRatio != 50 {
		t.Fatalf("BotRatio = %d, want 50", summary.BotRatio)
	}
	if summary.StatusGroup["2xx"] != 1 || summary.StatusGroup["4xx"] != 1 {
		t.Fatalf("StatusGroup = %#v, want one 2xx and one 4xx", summary.StatusGroup)
	}
	if len(summary.TopPaths) != 2 || summary.TopPaths[0].Name != "GET /" {
		t.Fatalf("TopPaths = %#v, want normalized GET / first", summary.TopPaths)
	}
}

// A parent domain folds its subdomains' logs into its own totals, so counters must
// sum across consume calls and ratios must be computed once over the combined set.
func TestAccumulatorSumsMultipleLogs(t *testing.T) {
	parentLog := strings.Join([]string{
		`10.0.0.1 - - [17/Jul/2026:12:00:00 +0000] "GET /parent HTTP/1.1" 200 1048576 "-" "Mozilla/5.0"`,
		`10.0.0.1 - - [17/Jul/2026:12:00:01 +0000] "GET /parent HTTP/1.1" 500 10 "-" "Mozilla/5.0"`,
	}, "\n")
	subdomainLog := strings.Join([]string{
		`10.0.0.2 - - [18/Jul/2026:12:00:00 +0000] "GET /sub HTTP/1.1" 404 1048576 "-" "curl/8.0"`,
		`10.0.0.1 - - [18/Jul/2026:12:00:01 +0000] "GET /sub HTTP/1.1" 301 0 "-" "curl/8.0"`,
	}, "\n")

	accumulated := newAccumulator()
	for _, log := range []string{parentLog, subdomainLog} {
		if err := accumulated.consume(strings.NewReader(log)); err != nil {
			t.Fatalf("consume() returned an unexpected error: %v", err)
		}
	}
	var summary Summary
	accumulated.finalize(&summary)

	if summary.TotalRequests != 4 {
		t.Fatalf("TotalRequests = %d, want 4", summary.TotalRequests)
	}
	// Unique IPs must be deduplicated across logs, not added per log.
	if summary.UniqueIP != 2 {
		t.Fatalf("UniqueIP = %d, want 2", summary.UniqueIP)
	}
	// Two of four requests are bots, and the ratio is computed over the combined total.
	if summary.BotRatio != 50 {
		t.Fatalf("BotRatio = %d, want 50", summary.BotRatio)
	}
	// Two 1 MiB responses plus 10 bytes, summed across both logs.
	if wantMB := float64(2*1048576+10) / (1024 * 1024); summary.TotalBandwidthMB != wantMB {
		t.Fatalf("TotalBandwidthMB = %v, want %v", summary.TotalBandwidthMB, wantMB)
	}
	assertOneOfEachStatusGroup(t, summary)
	// Days from both logs survive, so the parent's chart spans subdomain traffic.
	if len(summary.Daily) != 2 {
		t.Fatalf("Daily = %#v, want two days", summary.Daily)
	}
	if len(summary.TopPaths) != 2 {
		t.Fatalf("TopPaths = %#v, want both paths", summary.TopPaths)
	}
}

// assertOneOfEachStatusGroup checks that each of the four charted groups was
// counted once across the combined logs.
func assertOneOfEachStatusGroup(t *testing.T, summary Summary) {
	t.Helper()
	want := map[string]int{"2xx": 1, "3xx": 1, "4xx": 1, "5xx": 1}
	for group, count := range want {
		if summary.StatusGroup[group] != count {
			t.Fatalf("StatusGroup = %#v, want %#v", summary.StatusGroup, want)
		}
	}
}

// A missing subdomain log leaves the parent totals untouched.
func TestAccumulatorFinalizeWithoutRequests(t *testing.T) {
	summary := Summary{}
	newAccumulator().finalize(&summary)

	if summary.TotalRequests != 0 || summary.BotRatio != 0 {
		t.Fatalf("empty accumulator produced TotalRequests=%d BotRatio=%d", summary.TotalRequests, summary.BotRatio)
	}
	if summary.Daily == nil || summary.LastRequests == nil {
		t.Fatal("finalize() must initialize Daily and LastRequests for JSON encoding")
	}
}
