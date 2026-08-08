package dns

import (
	"strings"
	"testing"
)

func TestValidNSHostAcceptsFullyQualifiedNames(t *testing.T) {
	for _, host := range []string{
		"ns1.servika.com",
		"ns2.example.com.tr",
		"a.b.c.example.org",
		"ns1.example-host.net",
	} {
		if !ValidNSHost(host) {
			t.Errorf("ValidNSHost(%q) = false, want true", host)
		}
	}
}

// The value is written into a BIND zone file, so line and directive injection
// and anything that is not fully qualified have to be rejected.
func TestValidNSHostRejectsZoneInjectionAndPartialNames(t *testing.T) {
	for _, host := range []string{
		"",
		"ns1",                      // single label, not an FQDN
		"ns1.com\nIN NS evil.com.", // line injection
		"$INCLUDE /etc/passwd",     // zone directive injection
		"$ORIGIN evil.com.",
		"ns1 .example.com",    // whitespace
		"-ns1.example.com",    // leading hyphen
		"ns1-.example.com",    // trailing hyphen
		"ns1.example.c",       // TLD too short
		"ns1.example.com;x",   // separator/comment
		"ns1.example.com\x00", // NUL
		"192.0.2.10",          // an IP address is not a nameserver hostname
		"ns1.example.123",     // numeric TLD
		strings.Repeat("a", 250) + ".example.com", // over 253 characters
	} {
		if ValidNSHost(host) {
			t.Errorf("ValidNSHost(%q) = true, want false", host)
		}
	}
}

// The SOA primary NS has to match the zone's own NS records. An unusable value
// must fall back to the old vanity name rather than leak into the zone.
func TestDefaultSOAUsesTheSharedNameserver(t *testing.T) {
	soa := defaultSOA("customer.com", "ns1.provider.com")
	if soa.PrimaryNS != "ns1.provider.com" {
		t.Errorf("PrimaryNS = %q, want the shared ns1", soa.PrimaryNS)
	}
	if soa.Hostmaster != "admin@customer.com" {
		t.Errorf("Hostmaster = %q, want it derived from the domain", soa.Hostmaster)
	}

	for _, unusable := range []string{"", "ns1 broken\nvalue", "$INCLUDE /etc/passwd"} {
		if got := defaultSOA("customer.com", unusable).PrimaryNS; got != "ns1.customer.com" {
			t.Errorf("defaultSOA(_, %q).PrimaryNS = %q, want the vanity fallback", unusable, got)
		}
	}
}

// The built-in template must publish the shared pair and must NOT create ns1/ns2
// A records under the customer's own domain: that vanity model needs a glue
// record at the registrar of every single domain (see nameserver.go).
func TestBuiltinTemplateUsesSharedNameservers(t *testing.T) {
	var nsValues []string
	for _, row := range builtinDefaults() {
		if row.Type == "NS" {
			nsValues = append(nsValues, row.Value)
		}
		if row.Type == "A" && (row.Name == "ns1" || row.Name == "ns2") {
			t.Errorf("template still creates a vanity ns A record: %s", row.Name)
		}
	}
	if len(nsValues) != 2 {
		t.Fatalf("template has %d NS records, want 2: %v", len(nsValues), nsValues)
	}
	if nsValues[0] != "{NS1}" || nsValues[1] != "{NS2}" {
		t.Errorf("NS records = %v, want {NS1} and {NS2}", nsValues)
	}
}

func TestSubstituteTemplateResolvesNameserverPlaceholders(t *testing.T) {
	const ns1, ns2 = "ns1.provider.com", "ns2.provider.com"
	if got := substituteTemplate("{NS1}", "customer.com", "192.0.2.10", "", "default", "", ns1, ns2); got != ns1 {
		t.Errorf("{NS1} = %q, want %q", got, ns1)
	}
	if got := substituteTemplate("{NS2}", "customer.com", "192.0.2.10", "", "default", "", ns1, ns2); got != ns2 {
		t.Errorf("{NS2} = %q, want %q", got, ns2)
	}
	// The existing placeholders must keep working.
	if got := substituteTemplate("mail.{DOMAIN}", "customer.com", "192.0.2.10", "", "default", "", ns1, ns2); got != "mail.customer.com" {
		t.Errorf("{DOMAIN} = %q, want mail.customer.com", got)
	}
}

// The panel usually runs on a subdomain (cloud.provider.com). Deriving the pair
// automatically would publish ns1.cloud.provider.com, a nameserver the provider
// does not own, and every customer domain pointed at it would stop resolving.
// So only a SUGGESTION is produced, and it guesses the brand domain.
func TestSuggestedNameserverGuessesTheBrandDomain(t *testing.T) {
	cases := map[string]string{
		"cloud.servika.com":    "ns1.servika.com",
		"panel.example.com.tr": "ns1.example.com.tr",
		// Already a root domain: dropping the first label would leave "com".
		"servika.com": "ns1.servika.com",
	}
	for panelDomain, want := range cases {
		if got := "ns1." + brandDomain(panelDomain); got != want {
			t.Errorf("suggestion for %q = %q, want %q", panelDomain, got, want)
		}
	}
}

// Whether a nameserver sits inside or outside the zone decides the whole glue
// question, and getting it wrong takes a zone offline: BIND refuses to load a
// zone whose in-bailiwick NS has no address record in the zone file.
func TestInZoneLabelSeparatesGlueFromOutOfZoneNameservers(t *testing.T) {
	// The provider's OWN domain: the NS is inside the zone, so glue is required.
	if label, ok := inZoneLabel("ns1.provider.com", "provider.com"); !ok || label != "ns1" {
		t.Errorf(`inZoneLabel("ns1.provider.com", "provider.com") = %q, %v; want "ns1", true`, label, ok)
	}
	if label, ok := inZoneLabel("ns1.dns.provider.com", "provider.com"); !ok || label != "ns1.dns" {
		t.Errorf("a deeper in-zone nameserver = %q, %v; want \"ns1.dns\", true", label, ok)
	}
	// A trailing dot is the zone-file spelling and must not change the answer.
	if label, ok := inZoneLabel("ns1.provider.com.", "provider.com"); !ok || label != "ns1" {
		t.Errorf("a fully qualified nameserver = %q, %v; want \"ns1\", true", label, ok)
	}

	// A CUSTOMER domain: the NS is outside the zone, so glue is neither needed
	// nor meaningful and writing one would pollute the customer's zone.
	if _, ok := inZoneLabel("ns1.provider.com", "customer.example"); ok {
		t.Error("an out-of-zone nameserver was treated as in-zone")
	}
	// A shared suffix must not read as containment.
	if _, ok := inZoneLabel("ns1.xprovider.com", "provider.com"); ok {
		t.Error("a suffix lookalike was treated as in-zone")
	}
	// A nameserver that IS the zone is the apex; its glue is the apex A record.
	if label, ok := inZoneLabel("provider.com", "provider.com"); !ok || label != "@" {
		t.Errorf("an apex nameserver = %q, %v; want \"@\", true", label, ok)
	}
	if _, ok := inZoneLabel("", "provider.com"); ok {
		t.Error("an empty nameserver was treated as in-zone")
	}
}

// brandDomain mirrors the guess inside SuggestedNameservers, which cannot be
// called here because it reads panel_settings from the database.
func brandDomain(panelDomain string) string {
	if parts := strings.SplitN(panelDomain, ".", 2); len(parts) == 2 && strings.Contains(parts[1], ".") {
		return parts[1]
	}
	return panelDomain
}
