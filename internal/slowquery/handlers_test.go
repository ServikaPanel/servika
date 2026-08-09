package slowquery

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// A list endpoint is secured by its QUERY, never by a row-by-row check after the
// fact. The domain-scoped handler must narrow in SQL.
func TestTheDomainViewIsNarrowedInTheQuery(t *testing.T) {
	source := readSource(t, "handlers.go")
	build := source[strings.Index(source, "func (h *Handlers) query"):]
	build = build[:strings.Index(build, "\n// Status")]

	if !strings.Contains(build, "AND s.domain_id = ?") {
		t.Error("the query does not narrow by domain_id")
	}
	if !strings.Contains(build, "if domainID > 0 {") {
		t.Error("the narrowing is not conditional on a domain being asked for")
	}
	// The value travels as a parameter, never spliced into the statement.
	if strings.Contains(build, `"AND s.domain_id = " +`) || strings.Contains(build, "Sprintf") {
		t.Error("the domain id is interpolated into the statement instead of bound")
	}
}

// Ranking is by TOTAL time. What costs a shared server is the shape that spends
// the most time in total, which is usually a short query running constantly
// rather than one slow one, so ordering by the longest single execution would
// answer a different question.
func TestRankingIsByTotalTime(t *testing.T) {
	source := readSource(t, "handlers.go")
	if !strings.Contains(source, "ORDER BY SUM(s.total_time_ms) DESC") {
		t.Error("the rows are not ranked by total time")
	}
	if strings.Contains(source, "ORDER BY MAX(s.max_time_ms)") {
		t.Error("the rows are ranked by the longest single execution")
	}
}

// The window and the row count are bounded, so a caller cannot ask for the whole
// table in one request.
func TestTheWindowAndTheRowCountAreBounded(t *testing.T) {
	cases := []struct {
		query string
		hours int
		limit int
	}{
		{"", defaultHours, defaultLimit},
		{"?hours=1&limit=5", 1, 5},
		{"?hours=0&limit=0", defaultHours, defaultLimit},
		{"?hours=-3&limit=-3", defaultHours, defaultLimit},
		{"?hours=99999&limit=99999", maxHours, maxLimit},
		{"?hours=abc&limit=abc", defaultHours, defaultLimit},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/admin/slow-queries"+c.query, nil)
		if got := hoursParam(r); got != c.hours {
			t.Errorf("%q: hours = %d, want %d", c.query, got, c.hours)
		}
		if got := limitParam(r); got != c.limit {
			t.Errorf("%q: limit = %d, want %d", c.query, got, c.limit)
		}
	}
}

// The threshold is refused on the WRITE path, not only where the screen draws
// the field: the value is rendered into MariaDB's own configuration file, and a
// file MariaDB refuses stops it from starting on the next restart.
func TestTheWritePathValidatesTheThresholdItself(t *testing.T) {
	source := readSource(t, "handlers.go")
	save := source[strings.Index(source, "func (h *Handlers) Save"):]
	save = save[:strings.Index(save, "\nfunc (h *Handlers) currentSetting")]

	if !strings.Contains(save, "ValidThreshold(") {
		t.Fatal("Save does not validate the threshold")
	}
	// MariaDB is asked BEFORE the row is written. The other order stores a
	// threshold nothing is enforcing and reports it back as if it were live.
	apply := strings.Index(save, "Apply(ctx,")
	store := strings.Index(save, "UPDATE panel_settings SET slow_query_enabled")
	if apply < 0 || store < 0 || apply > store {
		t.Error("the setting is stored before MariaDB is known to have accepted it")
	}
	// Matched on the constant's NAME: the source names the constant, not the
	// string it holds, so searching for the value finds nothing whatever the
	// code does.
	if !strings.Contains(save, "reasonThresholdInvalid") {
		t.Error("the refusal carries no stable reason code")
	}
}

// Every refusal a screen renders carries a stable code, because the API is
// English and the panel renders twelve languages.
func TestEveryReasonCodeIsStable(t *testing.T) {
	for _, code := range []string{reasonThresholdInvalid, reasonApplyFailed} {
		if code == "" || strings.ContainsAny(code, " .") || strings.ToLower(code) != code {
			t.Errorf("%q is not a stable reason code", code)
		}
	}
	if reasonThresholdInvalid == reasonApplyFailed {
		t.Error("two different refusals share one code")
	}
}

// The request body is bounded, so a large POST cannot be read into memory.
func TestTheRequestBodyIsBounded(t *testing.T) {
	source := readSource(t, "handlers.go")
	if !strings.Contains(source, "io.LimitReader(r.Body") {
		t.Error("the settings body is decoded without a ceiling")
	}
}
