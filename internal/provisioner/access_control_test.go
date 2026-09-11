package provisioner

import (
	"database/sql/driver"
	"errors"
	"testing"
)

// buildIPRules renders the stored access rules into the server block. These
// tests pin what reaches the vhost for each stored state, including the states
// that must render nothing: a rule block nginx cannot parse fails the reload for
// the whole server, and a dropped rule renders the opposite of what was saved.

const (
	ipRulesHeader    = "    # ---- IP access rules, managed by Servika ----\n"
	ipAccessQuery    = "ip_access_mode"
	ipRuleListQuery  = "FROM domain_ip_rules"
	lostConnectionTo = "lost connection to MySQL server during query"
)

func TestTheIPRuleBlockFollowsTheStoredMode(t *testing.T) {
	cases := []struct {
		name  string
		mode  string
		rules [][]driver.Value
		want  string
	}{
		{"a deny list", "deny", [][]driver.Value{{"203.0.113.7"}, {"198.51.100.0/24"}},
			ipRulesHeader + "    deny 203.0.113.7;\n    deny 198.51.100.0/24;\n"},
		{"an allow list closes with deny all", "allow", [][]driver.Value{{"203.0.113.7"}},
			ipRulesHeader + "    allow 203.0.113.7;\n    deny all;\n"},
		{"a mode that is not allow renders as deny", "whitelist", [][]driver.Value{{"203.0.113.7"}},
			ipRulesHeader + "    deny 203.0.113.7;\n"},
		{"mode off renders nothing", "off", [][]driver.Value{{"203.0.113.7"}}, ""},
		{"an empty rule list renders nothing", "deny", [][]driver.Value{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withScript(t, &sqlScript{rows: map[string][][]driver.Value{
				ipAccessQuery:   {{int64(4), tc.mode}},
				ipRuleListQuery: tc.rules,
			}})
			if got := buildIPRules("example.com"); got != tc.want {
				t.Errorf("buildIPRules() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A stored value that is not an nginx address, or one that cannot be read, is
// left out, and the rules around it still render.
func TestAnUnusableStoredRuleIsLeftOut(t *testing.T) {
	withScript(t, &sqlScript{rows: map[string][][]driver.Value{
		ipAccessQuery:   {{int64(4), "deny"}},
		ipRuleListQuery: {{"not-an-address"}, {nil}, {"203.0.113.7"}},
	}})
	want := ipRulesHeader + "    deny 203.0.113.7;\n"
	if got := buildIPRules("example.com"); got != want {
		t.Errorf("buildIPRules() = %q, want %q", got, want)
	}
}

// When every stored rule is unusable there is nothing to render, not an empty
// header and not a lone deny all that would shut the whole site.
func TestOnlyUnusableRulesRenderNothing(t *testing.T) {
	withScript(t, &sqlScript{rows: map[string][][]driver.Value{
		ipAccessQuery:   {{int64(4), "allow"}},
		ipRuleListQuery: {{"not-an-address"}},
	}})
	if got := buildIPRules("example.com"); got != "" {
		t.Errorf("buildIPRules() = %q, want nothing", got)
	}
}

func TestAnUnreadableAccessSettingRendersNothing(t *testing.T) {
	cases := map[string]*sqlScript{
		"the domain lookup fails": {
			fail: map[string]error{ipAccessQuery: errors.New(lostConnectionTo)},
		},
		"the domain is not found": {
			rows: map[string][][]driver.Value{ipAccessQuery: {}},
		},
		"the rule query fails": {
			rows: map[string][][]driver.Value{ipAccessQuery: {{int64(4), "deny"}}},
			fail: map[string]error{ipRuleListQuery: errors.New(lostConnectionTo)},
		},
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			withScript(t, script)
			if got := buildIPRules("example.com"); got != "" {
				t.Errorf("buildIPRules() = %q, want nothing", got)
			}
		})
	}
}

// A rule list cut short renders the rules that arrived; the log line is the only
// sign that the list is incomplete.
func TestARuleListCutShortRendersWhatArrived(t *testing.T) {
	withScript(t, &sqlScript{
		rows: map[string][][]driver.Value{
			ipAccessQuery:   {{int64(4), "deny"}},
			ipRuleListQuery: {{"203.0.113.7"}},
		},
		endWith: map[string]error{ipRuleListQuery: errors.New(lostConnectionTo)},
	})
	want := ipRulesHeader + "    deny 203.0.113.7;\n"
	if got := buildIPRules("example.com"); got != want {
		t.Errorf("buildIPRules() = %q, want %q", got, want)
	}
}

func TestNoDatabaseRendersNoIPRules(t *testing.T) {
	withoutDatabase(t)
	if got := buildIPRules("example.com"); got != "" {
		t.Errorf("buildIPRules() = %q, want nothing", got)
	}
}
