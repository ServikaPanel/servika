package firewall

import (
	"strings"
	"testing"

	"servika/internal/apps"
)

// The input chain is `policy accept`. A tenant application listens on a loopback
// port only because its own code says so, and nothing forces that: a Node or
// Python process is free to bind 0.0.0.0. Without an explicit drop such an
// application answers straight from the internet, past nginx, TLS, the WAF and
// the per-domain IP rules.
func TestTheApplicationPortRangeIsDroppedFromOutside(t *testing.T) {
	ruleset := string(buildRuleset(nil, nil, nil, nil, remoteAccess{}, hostAppAccess{}))

	if !strings.Contains(ruleset, "policy accept;") {
		t.Fatal("the chain no longer defaults to accept; this test's premise needs rechecking")
	}
	want := "tcp dport 30000-30999 drop"
	if !strings.Contains(ruleset, want) {
		t.Fatalf("the ruleset does not drop the application range:\n%s", ruleset)
	}
}

// The drop must come AFTER the loopback accept, or nginx loses its own path to
// the application and every published application returns 502.
func TestTheDropComesAfterTheLoopbackAccept(t *testing.T) {
	ruleset := string(buildRuleset(nil, nil, nil, nil, remoteAccess{}, hostAppAccess{}))

	loopback := strings.Index(ruleset, `iif "lo" accept`)
	drop := strings.Index(ruleset, "tcp dport 30000-30999 drop")
	if loopback < 0 || drop < 0 {
		t.Fatalf("a rule is missing (loopback=%d drop=%d):\n%s", loopback, drop, ruleset)
	}
	if drop < loopback {
		t.Errorf("the application drop precedes the loopback accept, so nginx cannot reach an application:\n%s", ruleset)
	}
}

// An operator's own rules still take effect: the drop must not be placed after
// them, where a whitelist accept for one of these ports could never be reached.
func TestTheDropPrecedesTheOperatorsOwnRules(t *testing.T) {
	ruleset := string(buildRuleset(
		[]string{"\t\tip saddr 203.0.113.7 accept"}, nil,
		[]string{"\t\ttcp dport 8080 drop"},
		[]string{"\t\tip saddr 198.51.100.4 drop"},
		remoteAccess{}, hostAppAccess{},
	))

	drop := strings.Index(ruleset, "tcp dport 30000-30999 drop")
	for _, later := range []string{"203.0.113.7", "8080", "198.51.100.4"} {
		if at := strings.Index(ruleset, later); at < drop {
			t.Errorf("%q is emitted before the application drop, at %d against %d:\n%s", later, at, drop, ruleset)
		}
	}
}

// The firewall repeats the range rather than importing it, so the two must be
// checked against each other. A drift would either expose a live application or
// block a port nothing is using.
func TestTheFirewallRangeMatchesWhatTheAllocatorHandsOut(t *testing.T) {
	if appPortMin != apps.PortMin || appPortMax != apps.PortMax {
		t.Errorf("the firewall drops %d-%d but the allocator hands out %d-%d",
			appPortMin, appPortMax, apps.PortMin, apps.PortMax)
	}
}
