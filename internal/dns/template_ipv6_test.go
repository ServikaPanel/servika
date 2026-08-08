package dns

import (
	"strings"
	"testing"

	"servika/internal/datamigrate"
)

// THE fail-closed proof. A record that exists only to carry the IPv6 address is
// not written at all when there is no address.
//
// A AAAA pointing nowhere is worse than no AAAA: an IPv6-preferring client gets
// a dead site, and Let's Encrypt tries the AAAA FIRST when one exists, so
// certificate renewal stops too, silently, weeks later.
func TestNoAAAARecordIsSeededWithoutAnAddress(t *testing.T) {
	for _, row := range builtinDefaults() {
		if !strings.Contains(row.Value, "{IP6}") {
			continue
		}
		if !recordNeedsIPv6(row.Type, row.Value) && row.Type == "AAAA" {
			t.Errorf("the %s %s row would be seeded with no address behind it", row.Name, row.Type)
		}
	}
	// Every AAAA row in the built-in set is recognised.
	seen := 0
	for _, row := range builtinDefaults() {
		if row.Type != "AAAA" {
			continue
		}
		seen++
		if !recordNeedsIPv6(row.Type, row.Value) {
			t.Errorf("the %s AAAA row would be written without an address", row.Name)
		}
	}
	if seen == 0 {
		t.Fatal("the built-in template carries no AAAA row, so this proves nothing")
	}
}

// The SPF term goes away COMPLETELY rather than being left empty.
//
// `ip6:` with no value is not a harmless blank: it is an invalid SPF term, and
// a receiver that cannot parse a policy returns permerror for the WHOLE record
// instead of skipping the bad term. That takes SPF down for the domain, and
// DMARC with it, on a domain that simply has no IPv6.
func TestTheIPv6SPFTermDisappearsRatherThanGoingEmpty(t *testing.T) {
	const template = "v=spf1 a mx ip4:{IP} ip6:{IP6} ~all"

	without := substituteTemplate(template, "example.com", "203.0.113.5", "", "default", "", "ns1.x", "ns2.x")
	if strings.Contains(without, "ip6:") {
		t.Errorf("an ip6 term survived with no address: %q", without)
	}
	if !strings.Contains(without, "ip4:203.0.113.5") {
		t.Errorf("the IPv4 term was lost along with the IPv6 one: %q", without)
	}
	if strings.Contains(without, "  ") {
		t.Errorf("removing the term left a double space a strict parser can trip on: %q", without)
	}
	if !strings.HasSuffix(without, " ~all") {
		t.Errorf("the policy no longer ends in its qualifier: %q", without)
	}

	with := substituteTemplate(template, "example.com", "203.0.113.5", "2001:db8::5", "default", "", "ns1.x", "ns2.x")
	if !strings.Contains(with, "ip6:2001:db8::5") {
		t.Errorf("the IPv6 term is missing when an address exists: %q", with)
	}
	if !strings.Contains(with, "ip4:203.0.113.5") {
		t.Errorf("the IPv4 term is missing: %q", with)
	}
}

// A record that merely MENTIONS the placeholder among other terms is kept and
// rewritten, not dropped. Publishing no SPF at all is worse than publishing one
// without an IPv6 mechanism.
func TestARecordThatOnlyMentionsTheAddressIsKept(t *testing.T) {
	if recordNeedsIPv6("TXT", "v=spf1 a mx ip4:{IP} ip6:{IP6} ~all") {
		t.Error("the SPF record would be dropped entirely when there is no IPv6")
	}
	if !recordNeedsIPv6("AAAA", "{IP6}") {
		t.Error("a bare AAAA row would be written with no address")
	}
	if recordNeedsIPv6("A", "{IP}") {
		t.Error("an IPv4 row was treated as needing IPv6")
	}
	if recordNeedsIPv6("MX", "mail.{DOMAIN}") {
		t.Error("a row with no address placeholder was treated as needing IPv6")
	}
}

// The IPv4 side is byte-for-byte what it was. This feature adds a family; it
// never trades one for the other.
func TestTheIPv4RecordsAreUnchanged(t *testing.T) {
	wanted := map[string]bool{"@": true, "www": true, "mail": true, "smtp": true, "imap": true, "autoconfig": true, "autodiscover": true}
	found := map[string]bool{}
	for _, row := range builtinDefaults() {
		if row.Type == "A" && row.Value == "{IP}" {
			found[row.Name] = true
		}
	}
	for name := range wanted {
		if !found[name] {
			t.Errorf("the %s A record disappeared from the built-in template", name)
		}
	}
}

// The backfill and the built-in template have to name the same records. They
// live in different packages and nothing but this test holds them in step, so a
// row added to one and forgotten in the other would reach new installs only.
func TestTheBackfillCoversEveryBuiltInAAAARow(t *testing.T) {
	builtin := map[string]bool{}
	for _, row := range builtinDefaults() {
		if row.Type == "AAAA" {
			builtin[row.Name] = true
		}
	}
	backfilled := map[string]bool{}
	for _, name := range datamigrate.TemplateRowNames() {
		backfilled[name] = true
	}

	for name := range builtin {
		if !backfilled[name] {
			t.Errorf("the built-in template seeds a %s AAAA row the backfill never adds, so existing installs would never get it", name)
		}
	}
	for name := range backfilled {
		if !builtin[name] {
			t.Errorf("the backfill adds a %s AAAA row the built-in template does not seed, so a new install and an upgraded one would differ", name)
		}
	}
}

// The backfill rewrites the SPF string by exact match, so the text it looks for
// has to be the one the template used to ship and the text it writes has to be
// the one it ships now.
func TestTheBackfillRewritesTheSPFTheTemplateActuallyShips(t *testing.T) {
	_, after := datamigrate.SPFStrings()
	current := ""
	for _, row := range builtinDefaults() {
		if row.Type == "TXT" && strings.HasPrefix(row.Value, "v=spf1") {
			current = row.Value
			break
		}
	}
	if current == "" {
		t.Fatal("the built-in template has no SPF record")
	}
	if after != current {
		t.Errorf("the backfill writes %q but the template ships %q", after, current)
	}
}
