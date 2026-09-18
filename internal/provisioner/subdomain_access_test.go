package provisioner

import (
	"database/sql/driver"
	"errors"
	"testing"
)

const (
	subAccessQuery   = "FROM subdomain_ip_access"
	subRuleListQuery = "FROM subdomain_ip_rules"
)

// A subdomain carries its own mode and its own rules. The block it renders is
// the same shape as the domain's, because the two go through one renderer.
func TestTheSubdomainBlockFollowsItsOwnStoredMode(t *testing.T) {
	cases := []struct {
		name  string
		mode  string
		rules [][]driver.Value
		want  string
	}{
		{"a deny list", "block", [][]driver.Value{{"203.0.113.7"}, {"198.51.100.0/24"}},
			ipRulesHeader + "    deny 203.0.113.7;\n    deny 198.51.100.0/24;\n"},
		{"an allow list closes with deny all", "allow", [][]driver.Value{{"203.0.113.7"}},
			ipRulesHeader + "    allow 203.0.113.7;\n    deny all;\n"},
		{"mode off renders nothing", "off", [][]driver.Value{{"203.0.113.7"}}, ""},
		{"an empty rule list renders nothing", "block", [][]driver.Value{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := withScript(t, &sqlScript{rows: map[string][][]driver.Value{
				subAccessQuery:   {{tc.mode}},
				subRuleListQuery: tc.rules,
			}})
			if got := SubdomainIPRules(db, 7); got != tc.want {
				t.Errorf("SubdomainIPRules() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A subdomain that was never restricted has no row at all. That is the normal
// state and must render nothing, not the allow list that would shut the site.
func TestASubdomainWithNoStoredRowRendersNothing(t *testing.T) {
	db := withScript(t, &sqlScript{rows: map[string][][]driver.Value{
		subAccessQuery:   {},
		subRuleListQuery: {{"203.0.113.7"}},
	}})
	if got := SubdomainIPRules(db, 7); got != "" {
		t.Errorf("SubdomainIPRules() = %q, want nothing", got)
	}
}

// A read that fails renders nothing rather than a partial block: a half-written
// allow list shuts out addresses the customer admitted.
func TestAnUnreadableSubdomainSettingRendersNothing(t *testing.T) {
	cases := map[string]*sqlScript{
		"the mode lookup fails": {
			fail: map[string]error{subAccessQuery: errors.New(lostConnectionTo)},
		},
		"the rule query fails": {
			rows: map[string][][]driver.Value{subAccessQuery: {{"block"}}},
			fail: map[string]error{subRuleListQuery: errors.New(lostConnectionTo)},
		},
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			db := withScript(t, script)
			if got := SubdomainIPRules(db, 7); got != "" {
				t.Errorf("SubdomainIPRules() = %q, want nothing", got)
			}
		})
	}
}

// Without a database handle, and for a scope that is not a subdomain, there is
// nothing to read and nothing to render.
func TestSubdomainRulesNeedADatabaseAndAnID(t *testing.T) {
	if got := SubdomainIPRules(nil, 7); got != "" {
		t.Errorf("SubdomainIPRules(nil) = %q, want nothing", got)
	}
	db := withScript(t, &sqlScript{rows: map[string][][]driver.Value{
		subAccessQuery: {{"allow"}}, subRuleListQuery: {{"203.0.113.7"}},
	}})
	if got := SubdomainIPRules(db, 0); got != "" {
		t.Errorf("SubdomainIPRules(db, 0) = %q, want nothing", got)
	}
}
