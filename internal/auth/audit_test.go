package auth

import (
	"strings"
	"testing"
)

func TestAuditLimit(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int
	}{
		{"empty defaults to 200", "", 200},
		{"valid mid-range value", "150", 150},
		{"exact cap", "1000", 1000},
		{"above cap clamps to 1000", "5000", 1000},
		{"zero falls back to default", "0", 200},
		{"negative falls back to default", "-10", 200},
		{"non-numeric falls back to default", "abc", 200},
		{"one is honored", "1", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := auditLimit(c.raw); got != c.want {
				t.Errorf("auditLimit(%q) = %d, want %d", c.raw, got, c.want)
			}
		})
	}
}

// auditQueryCase is one buildAuditQuery call and what it must produce.
type auditQueryCase struct {
	name       string
	action     string
	onlyFailed bool
	limit      int
	scope      int64
	// contains and absent are checked against the query TEXT.
	contains []string
	absent   []string
	wantArgs []any
}

// runAuditQueryCases checks the query text and the bound arguments of each case.
func runAuditQueryCases(t *testing.T, cases []auditQueryCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q, arg := buildAuditQuery(c.action, c.onlyFailed, c.limit, c.scope)
			for _, want := range c.contains {
				if !strings.Contains(q, want) {
					t.Errorf("query does not carry %q: %q", want, q)
				}
			}
			for _, unwanted := range c.absent {
				if strings.Contains(q, unwanted) {
					t.Errorf("query carries %q: %q", unwanted, q)
				}
			}
			assertAuditArgs(t, arg, c.wantArgs)
		})
	}
}

// assertAuditArgs compares the bound arguments, in order.
func assertAuditArgs(t *testing.T, got []any, want []any) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args = %v, want %v", got, want)
		}
	}
}

// scope = -1 means "all scopes" (admin): no reseller_id predicate is added, so
// these cases exercise the filter logic exactly as before scoping existed.
func TestBuildAuditQueryFilters(t *testing.T) {
	// A SQL-injection-shaped action must appear ONLY as a bound arg; the query
	// text must carry a single `?` placeholder for it, not the value.
	const injected = "auth.login'; DROP TABLE audit_log;--"
	runAuditQueryCases(t, []auditQueryCase{
		{
			name:  "no filters: bare select, only limit bound",
			limit: 200, scope: -1,
			contains: []string{"ORDER BY id DESC LIMIT ?"},
			absent:   []string{"WHERE"},
			wantArgs: []any{200},
		},
		{
			name:   "action filter is bound as placeholder, never interpolated",
			action: injected, limit: 200, scope: -1,
			contains: []string{"action = ?"},
			absent:   []string{"DROP TABLE", injected},
			wantArgs: []any{injected, 200},
		},
		{
			name:       "only_failed adds constant predicate with no arg",
			onlyFailed: true, limit: 500, scope: -1,
			contains: []string{"ok = 0"},
			wantArgs: []any{500},
		},
		{
			name:   "both filters joined with AND, args ordered action then limit",
			action: "auth.2fa", onlyFailed: true, limit: 42, scope: -1,
			contains: []string{"WHERE action = ? AND ok = 0"},
			wantArgs: []any{"auth.2fa", 42},
		},
		{
			name:   "whitespace-only action is treated as absent",
			action: "   ", limit: 200, scope: -1,
			absent:   []string{"WHERE"},
			wantArgs: []any{200},
		},
	})
}

func TestBuildAuditQueryScope(t *testing.T) {
	runAuditQueryCases(t, []auditQueryCase{
		{
			name:  "reseller scope binds reseller_id first, before limit",
			limit: 200, scope: 7,
			contains: []string{"WHERE reseller_id = ?"},
			wantArgs: []any{int64(7), 200},
		},
		{
			name:  "scope zero (root-only view) still filters to reseller_id = 0",
			limit: 200, scope: 0,
			contains: []string{"reseller_id = ?"},
			wantArgs: []any{int64(0), 200},
		},
		{
			name:   "scope combined with action: reseller_id bound before action",
			action: "auth.login", limit: 50, scope: 3,
			contains: []string{"WHERE reseller_id = ? AND action = ?"},
			wantArgs: []any{int64(3), "auth.login", 50},
		},
	})
}
