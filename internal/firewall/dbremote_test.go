package firewall

import (
	"strings"
	"testing"
)

// at reports where a fragment first appears in a ruleset, counted in lines, or
// -1. It wraps the package's lineIndex so each test reads as one call.
func at(ruleset, fragment string) int {
	return lineIndex(strings.Split(ruleset, "\n"), fragment)
}

// THE boundary. The chain is `policy accept`, so opening the database bind makes
// 3306 reachable by the whole internet unless this one line exists. It is
// emitted whenever the switch is on, allowlist or not.
func TestTheDatabasePortIsDroppedEvenWithAnEmptyAllowlist(t *testing.T) {
	ruleset := string(buildRuleset(nil, nil, nil, nil, remoteAccess{enabled: true}))
	if !strings.Contains(ruleset, "tcp dport 3306 drop") {
		t.Errorf("the open port has no drop:\n%s", ruleset)
	}
}

// While the switch is off MariaDB binds loopback, so there is nothing to drop.
// Emitting the rule anyway would cut off an operator who configured their own
// remote MariaDB outside the panel, on a server the panel never opened.
func TestNothingIsEmittedWhileTheSwitchIsOff(t *testing.T) {
	ruleset := string(buildRuleset(nil, nil, nil, nil, remoteAccess{
		accepts: []string{"\t\tip saddr 203.0.113.7 tcp dport 3306 accept"},
	}))
	if strings.Contains(ruleset, "3306") {
		t.Errorf("a rule was emitted while the feature was off:\n%s", ruleset)
	}
}

// The first matching rule wins in this chain, so an address the operator blocked
// by country or banned outright must not get back in because a customer allowed
// it to their database. Both drops therefore sit ABOVE the accepts.
func TestACountryOrBanStillWinsOverTheDatabaseAllowlist(t *testing.T) {
	ruleset := string(buildRuleset(
		nil, nil, nil,
		[]string{"\t\tip saddr 203.0.113.7 drop"},
		remoteAccess{
			enabled: true,
			accepts: []string{"\t\tip saddr 203.0.113.7 tcp dport 3306 accept"},
		},
	))

	geo := at(ruleset, "ip saddr @"+geoSetV4+" drop")
	ban := at(ruleset, "ip saddr 203.0.113.7 drop")
	accept := at(ruleset, "tcp dport 3306 accept")
	if geo < 0 || ban < 0 || accept < 0 {
		t.Fatalf("a rule is missing (geo=%d ban=%d accept=%d):\n%s", geo, ban, accept, ruleset)
	}
	if geo > accept {
		t.Errorf("the country drop is below the database accept (%d > %d), so a blocked country reaches 3306", geo, accept)
	}
	if ban > accept {
		t.Errorf("the ban is below the database accept (%d > %d), so a banned address reaches 3306", ban, accept)
	}
}

// The accepts have to come BEFORE the drop that follows them, or the allowlist
// never lets anybody through and the feature is on in name only.
func TestTheAllowlistComesBeforeTheDropItDependsOn(t *testing.T) {
	ruleset := string(buildRuleset(nil, nil, nil, nil, remoteAccess{
		enabled: true,
		accepts: []string{
			"\t\tip saddr 203.0.113.7 tcp dport 3306 accept",
			"\t\tip6 saddr 2001:db8::5 tcp dport 3306 accept",
		},
	}))
	drop := at(ruleset, "tcp dport 3306 drop")
	for _, accept := range []string{"ip saddr 203.0.113.7", "ip6 saddr 2001:db8::5"} {
		line := at(ruleset, accept)
		if line < 0 {
			t.Fatalf("missing %q:\n%s", accept, ruleset)
		}
		if line > drop {
			t.Errorf("%q sits below the drop (%d > %d), so it never matches", accept, line, drop)
		}
	}
}

// The loopback accept stays above everything, so the panel and every site keep
// reaching MariaDB over 127.0.0.1 whatever the allowlist says.
func TestLoopbackStillReachesTheDatabase(t *testing.T) {
	ruleset := string(buildRuleset(nil, nil, nil, nil, remoteAccess{enabled: true}))
	loopback := at(ruleset, `iif "lo" accept`)
	drop := at(ruleset, "tcp dport 3306 drop")
	if loopback < 0 || drop < 0 || loopback > drop {
		t.Errorf("the loopback accept does not precede the database drop (lo=%d drop=%d):\n%s", loopback, drop, ruleset)
	}
}
