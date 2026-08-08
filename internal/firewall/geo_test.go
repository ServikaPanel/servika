package firewall

import (
	"strings"
	"testing"

	"servika/internal/geoip"
)

// lineIndex returns the position of the first line containing want, or -1.
func lineIndex(lines []string, want string) int {
	for index, line := range lines {
		if strings.Contains(line, want) {
			return index
		}
	}
	return -1
}

// The ORDER of the base rules is the whole boundary, because the chain is
// `policy accept` and every restriction is an explicit drop.
//
// The country drop comes after the loopback accept, or nginx would lose its own
// connection to a tenant application; and BEFORE the whitelist accepts, so a
// per-IP permission cannot quietly reopen a country the operator closed. Both
// facts are invisible from the directives alone.
func TestTheCountryDropSitsBetweenLoopbackAndTheWhitelist(t *testing.T) {
	ruleset := string(buildRuleset(
		[]string{"\t\tip saddr 1.2.3.4 accept"},
		[]string{"\t\ttcp dport 3306 drop"},
		[]string{"\t\ttcp dport 21 drop"},
		[]string{"\t\tip saddr 9.9.9.9 drop"},
	))
	lines := strings.Split(ruleset, "\n")

	loopback := lineIndex(lines, `iif "lo" accept`)
	appPorts := lineIndex(lines, "tcp dport 30000-30999 drop")
	geoV4 := lineIndex(lines, "ip saddr @"+geoSetV4+" drop")
	geoV6 := lineIndex(lines, "ip6 saddr @"+geoSetV6+" drop")
	whitelist := lineIndex(lines, "ip saddr 1.2.3.4 accept")
	banned := lineIndex(lines, "ip saddr 9.9.9.9 drop")

	for name, index := range map[string]int{
		"loopback accept": loopback, "application port drop": appPorts,
		"IPv4 country drop": geoV4, "IPv6 country drop": geoV6,
		"whitelist accept": whitelist, "banned drop": banned,
	} {
		if index < 0 {
			t.Fatalf("the %s is missing from the ruleset:\n%s", name, ruleset)
		}
	}
	if loopback >= appPorts || appPorts >= geoV4 || geoV4 >= geoV6 {
		t.Errorf("the country drop is not after the loopback accept:\n%s", ruleset)
	}
	if geoV6 >= whitelist {
		t.Errorf("a whitelist accept comes before the country drop, so it would reopen a blocked country:\n%s", ruleset)
	}
	if whitelist >= banned {
		t.Errorf("the whitelist no longer precedes the banned drops:\n%s", ruleset)
	}
}

// The established-connection accept must stay first, or applying a country
// block would cut the operator's own SSH session.
func TestEstablishedConnectionsStillComeFirst(t *testing.T) {
	ruleset := string(buildRuleset(nil, nil, nil, nil))
	lines := strings.Split(ruleset, "\n")
	established := lineIndex(lines, "ct state established,related accept")
	geoV4 := lineIndex(lines, "@"+geoSetV4)
	if established < 0 || geoV4 < 0 {
		t.Fatalf("a required rule is missing:\n%s", ruleset)
	}
	if established > geoV4 {
		t.Errorf("the country drop precedes the established accept, so it would break live sessions:\n%s", ruleset)
	}
}

// The table body references the sets unconditionally, so the include has to be
// there whatever is blocked.
func TestTheTableIncludesTheCountrySets(t *testing.T) {
	ruleset := string(buildRuleset(nil, nil, nil, nil))
	if !strings.Contains(ruleset, `include "`+geoIncludeFile+`"`) {
		t.Fatalf("the element file is not included:\n%s", ruleset)
	}
	// The include must sit inside the table block: nft resolves set names within
	// the table, and an include outside it would declare sets nothing can use.
	tableStart := strings.Index(ruleset, "table inet "+tableName+" {\n\t")
	includeAt := strings.Index(ruleset, "include ")
	chainAt := strings.Index(ruleset, "chain input")
	if tableStart < 0 || tableStart >= includeAt || includeAt >= chainAt {
		t.Errorf("the include is not inside the table block before the chain:\n%s", ruleset)
	}
}

// An empty set is still DECLARED. nft rejects a rule naming a set that does not
// exist, so omitting the declaration when nothing is blocked would fail the
// whole ruleset rather than block nothing.
func TestBothSetsAreDeclaredWhenNoCountryIsBlocked(t *testing.T) {
	body := string(buildGeoSets(geoip.Ranges{}))
	for _, want := range []string{
		"set " + geoSetV4 + " {", "type ipv4_addr", "flags interval",
		"set " + geoSetV6 + " {", "type ipv6_addr",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "elements") {
		t.Errorf("an empty set declared elements:\n%s", body)
	}
}

// nft needs the elements comma-separated inside one brace pair, and a trailing
// comma is a syntax error that would fail the whole ruleset.
func TestElementsAreRenderedWithoutATrailingComma(t *testing.T) {
	body := string(buildGeoSets(geoip.Ranges{
		V4: []geoip.Network{
			{CIDR: "1.0.1.0/24", Country: "CN"},
			{CIDR: "1.0.2.0/23", Country: "CN"},
		},
		V6: []geoip.Network{{CIDR: "2001:250::/32", Country: "CN"}},
	}))
	if !strings.Contains(body, "1.0.1.0/24,\n") {
		t.Errorf("elements are not comma-separated:\n%s", body)
	}
	if strings.Contains(body, "1.0.2.0/23,\n") {
		t.Errorf("the last IPv4 element carries a trailing comma:\n%s", body)
	}
	if strings.Contains(body, "2001:250::/32,\n") {
		t.Errorf("the last IPv6 element carries a trailing comma:\n%s", body)
	}
	// Families are kept apart: nft refuses an IPv6 prefix in an ipv4_addr set.
	v4Block := body[strings.Index(body, geoSetV4):strings.Index(body, geoSetV6)]
	if strings.Contains(v4Block, "2001:") {
		t.Errorf("an IPv6 range landed in the IPv4 set:\n%s", v4Block)
	}
}

// A country code that is not one never reaches the element file, because the
// value travels from a request into a generated nftables document.
func TestOnlyISOShapedCodesSurviveNormalization(t *testing.T) {
	for _, value := range []string{"cn", " CN ", "Cn"} {
		if geoip.NormalizeCountry(value) != "CN" {
			t.Errorf("%q was not normalized to CN", value)
		}
	}
	for _, value := range []string{"", "C", "CHN", "C1", "C;", "C\n", "*"} {
		if got := geoip.NormalizeCountry(value); got != "" {
			t.Errorf("NormalizeCountry(%q) = %q, want empty", value, got)
		}
	}
}
