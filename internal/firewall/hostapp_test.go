package firewall

import (
	"strconv"
	"strings"
	"testing"

	"servika/internal/hostapps"
)

// The range is repeated in this package rather than imported, so the two have to
// be asserted to agree. If they drift, the drop covers ports nothing is
// allocated from and leaves the allocated ones open, which is silent both ways.
func TestTheServerApplicationRangeMatchesTheAllocator(t *testing.T) {
	if hostAppPortMin != hostapps.PortMin || hostAppPortMax != hostapps.PortMax {
		t.Errorf("the firewall drops %d-%d but hostapps allocates %d-%d",
			hostAppPortMin, hostAppPortMax, hostapps.PortMin, hostapps.PortMax)
	}
}

// The drop is written even with an EMPTY allowlist. That is the state in which
// the applications are most exposed: they are installed and listening, and
// nobody has said which of them should be reachable yet.
func TestTheRangeIsDroppedEvenWithNothingOpened(t *testing.T) {
	ruleset := string(buildRuleset(nil, nil, nil, nil, remoteAccess{},
		hostAppAccess{enabled: true}))
	if !strings.Contains(ruleset, "tcp dport 31000-31999 drop") {
		t.Errorf("installed applications have no range drop:\n%s", ruleset)
	}
}

// On a server with no application installed nothing is emitted, so an operator
// running their own service on a port in this range is not silently cut off by a
// panel update. internal/dbremote follows the same rule for 3306.
func TestNothingIsEmittedWithNoApplicationInstalled(t *testing.T) {
	ruleset := string(buildRuleset(nil, nil, nil, nil, remoteAccess{}, hostAppAccess{
		accepts: []string{"\t\ttcp dport 31000 accept"},
	}))
	if strings.Contains(ruleset, "31000") || strings.Contains(ruleset, "31999") {
		t.Errorf("a rule was emitted with no application installed:\n%s", ruleset)
	}
}

// The accepts have to come BEFORE the drop that follows them, or opening a port
// never lets anybody through and the feature is on in name only.
func TestAnOpenedPortComesBeforeTheRangeDrop(t *testing.T) {
	ruleset := string(buildRuleset(nil, nil, nil, nil, remoteAccess{}, hostAppAccess{
		enabled: true,
		accepts: []string{"\t\ttcp dport 31000 accept", "\t\ttcp dport 31007 accept"},
	}))
	drop := at(ruleset, "tcp dport 31000-31999 drop")
	if drop < 0 {
		t.Fatalf("the range drop is missing:\n%s", ruleset)
	}
	for _, accept := range []string{"tcp dport 31000 accept", "tcp dport 31007 accept"} {
		line := at(ruleset, accept)
		if line < 0 {
			t.Fatalf("missing %q:\n%s", accept, ruleset)
		}
		if line > drop {
			t.Errorf("%q sits after the drop, so it never matches:\n%s", accept, ruleset)
		}
	}
}

// Opening an application's port must not let back in an address the operator
// already refused by country or by ban. The chain is `policy accept`, so first
// match wins and this ORDER is the entire boundary.
func TestOpeningAPortCannotReopenABlockedSource(t *testing.T) {
	ruleset := string(buildRuleset(nil, nil, nil,
		[]string{"\t\tip saddr 203.0.113.7 drop"},
		remoteAccess{},
		hostAppAccess{enabled: true, accepts: []string{"\t\ttcp dport 31000 accept"}},
	))
	loopback := at(ruleset, `iif "lo" accept`)
	country := at(ruleset, "ip saddr @"+geoSetV4+" drop")
	ban := at(ruleset, "ip saddr 203.0.113.7 drop")
	accept := at(ruleset, "tcp dport 31000 accept")
	if loopback < 0 || country < 0 || ban < 0 || accept < 0 {
		t.Fatalf("a rule is missing (lo=%d country=%d ban=%d accept=%d):\n%s",
			loopback, country, ban, accept, ruleset)
	}
	if loopback >= country || country >= ban || ban >= accept {
		t.Errorf("the order is lo=%d country=%d ban=%d accept=%d; the accept must come last:\n%s",
			loopback, country, ban, accept, ruleset)
	}
}

// The tenant range keeps its unconditional drop with no accepts. The two ranges
// get OPPOSITE treatment and merging them would either publish every tenant
// application or make every server one unreachable.
func TestTheTenantRangeStillHasNoWayToBeOpened(t *testing.T) {
	ruleset := string(buildRuleset(nil, nil, nil, nil, remoteAccess{},
		hostAppAccess{enabled: true, accepts: []string{"\t\ttcp dport 31000 accept"}}))
	if !strings.Contains(ruleset, "tcp dport 30000-30999 drop") {
		t.Errorf("the tenant range drop is missing:\n%s", ruleset)
	}
	for line := range strings.SplitSeq(ruleset, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasSuffix(trimmed, "accept") {
			continue
		}
		for port := 30000; port <= 30999; port += 499 {
			if strings.Contains(trimmed, "dport "+strconv.Itoa(port)) {
				t.Errorf("a tenant application port is accepted: %q", trimmed)
			}
		}
	}
}
