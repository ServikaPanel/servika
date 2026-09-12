package logview

import (
	"strings"
	"testing"
)

// The filters come from a query string, so the only thing standing between an
// operator's URL and the statement is that every value is bound. A value that
// reaches the SQL text is an injection.
func TestNoFilterValueReachesTheStatement(t *testing.T) {
	statement, arg, ok := buildRequestQuery(map[string]string{
		"request_id": "abc' OR 1=1 -- ",
		"method":     "POST",
		"module":     "domains",
	}, 50)
	if !ok {
		t.Fatal("the query was refused")
	}
	if strings.Contains(statement, "OR 1=1") {
		t.Fatalf("a filter value reached the statement: %s", statement)
	}
	if strings.Count(statement, "?") != len(arg) {
		t.Errorf("%d placeholder(s) for %d argument(s): %s", strings.Count(statement, "?"), len(arg), statement)
	}
	if arg[0] != "abc' OR 1=1 --" {
		t.Errorf("the value was altered instead of bound: %v", arg[0])
	}
}

// An empty filter must add no predicate, or the screen's default view would
// silently match on "".
func TestAnEmptyFilterAddsNothing(t *testing.T) {
	statement, arg, ok := buildRequestQuery(map[string]string{"method": "  "}, 10)
	if !ok {
		t.Fatal("the query was refused")
	}
	if strings.Contains(statement, "WHERE") {
		t.Errorf("an empty filter produced a predicate: %s", statement)
	}
	if len(arg) != 1 || arg[0] != 10 {
		t.Errorf("the arguments are %v, want just the limit", arg)
	}
}

// A mistyped number must be reported. Dropping it would answer with the
// unfiltered list, which reads as "these are your 404s" when they are not.
func TestAMalformedNumberIsRefused(t *testing.T) {
	if _, _, ok := buildRequestQuery(map[string]string{"status": "abc"}, 10); ok {
		t.Error("a non-numeric status was accepted")
	}
	if _, _, ok := buildRequestQuery(map[string]string{"user_id": "1; DROP"}, 10); ok {
		t.Error("a non-numeric user_id was accepted")
	}
}

// A mistyped level must be reported for the same reason: level is an ENUM, so
// "ERR" matches no row and an empty answer would read as "no errors".
func TestAnUnknownLevelIsRefused(t *testing.T) {
	if _, _, ok := buildAppQuery(map[string]string{"level": "ERR"}, 10); ok {
		t.Error("an unknown level was accepted")
	}
	statement, _, ok := buildAppQuery(map[string]string{"level": "ERROR"}, 10)
	if !ok || !strings.Contains(statement, "level = ?") {
		t.Errorf("a known level was not applied: %s", statement)
	}
}

// The date filter accepts what an operator would type, and reports what it
// cannot read.
func TestTheSinceFilter(t *testing.T) {
	for _, value := range []string{"2026-01-02", "2026-01-02 03:04:05", "2026-01-02T03:04:05Z"} {
		statement, _, ok := buildAppQuery(map[string]string{"since": value}, 10)
		if !ok || !strings.Contains(statement, "ts >= ?") {
			t.Errorf("%q was not accepted as a date", value)
		}
	}
	if _, _, ok := buildAppQuery(map[string]string{"since": "yesterday"}, 10); ok {
		t.Error("an unreadable date was accepted")
	}
}

// The cap is what keeps one careless request from reading a month of traffic
// into memory.
func TestTheLimitIsCapped(t *testing.T) {
	for _, testCase := range []struct {
		raw  string
		want int
	}{
		{"", defaultLimit},
		{"abc", defaultLimit},
		{"0", defaultLimit},
		{"-5", defaultLimit},
		{"50", 50},
		{"5000", maxLimit},
	} {
		if got := parseLimit(testCase.raw); got != testCase.want {
			t.Errorf("parseLimit(%q) is %d, want %d", testCase.raw, got, testCase.want)
		}
	}
}
