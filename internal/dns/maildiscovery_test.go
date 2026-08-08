package dns

import (
	"strings"
	"testing"
)

// A mail client is configured by hand with smtp./imap./pop. more often than not,
// and those names have to resolve before a certificate can even cover them.
func TestTemplateCarriesTheMailClientNames(t *testing.T) {
	have := map[string]TemplateRow{}
	for _, row := range builtinDefaults() {
		have[row.Name+"/"+row.Type] = row
	}
	for _, key := range []string{"smtp/A", "imap/A", "mail/A"} {
		if _, ok := have[key]; !ok {
			t.Errorf("the built-in template has no %s record", key)
		}
	}
	for _, key := range []string{"_imap._tcp/SRV", "_submission._tcp/SRV"} {
		row, ok := have[key]
		if !ok {
			t.Errorf("the built-in template has no %s record", key)
			continue
		}
		// The value is "weight port target"; the priority is a column of its own,
		// and the zone writer emits it separately. Four fields here would render a
		// record with two priorities.
		if fields := strings.Fields(row.Value); len(fields) != 3 {
			t.Errorf("%s value = %q, want three fields (weight port target)", key, row.Value)
		}
		if !strings.HasSuffix(row.Value, "mail.{DOMAIN}") {
			t.Errorf("%s points at %q, want the MX target", key, row.Value)
		}
	}
}

// The two discovery hostnames are published because a vhost now answers them,
// and their address records point at this server like every other host record.
//
// The A record is required. The AAAA is allowed beside it and is seeded only
// when the domain actually has an IPv6 address, so a client that prefers IPv6
// is never sent to an address this server does not answer on.
func TestTemplatePublishesTheDiscoveryHostnames(t *testing.T) {
	foundA := map[string]bool{}
	for _, row := range builtinDefaults() {
		if row.Name != "autoconfig" && row.Name != "autodiscover" {
			continue
		}
		switch {
		case row.Type == "A" && row.Value == "{IP}":
			foundA[row.Name] = true
		case row.Type == "AAAA" && row.Value == "{IP6}":
			// Allowed beside the A record.
		default:
			t.Errorf("%s = %s %q, want an address record pointing at this server", row.Name, row.Type, row.Value)
		}
	}
	for _, name := range []string{"autoconfig", "autodiscover"} {
		if !foundA[name] {
			t.Errorf("the template does not publish an A record for %s", name)
		}
	}
}

// _autodiscover._tcp stays out. It exists only to send Outlook to a DIFFERENT
// host, which makes it show a redirect warning, and the host it would name is
// one Outlook now reaches directly.
func TestTemplateDoesNotAdvertiseTheAutodiscoverSRV(t *testing.T) {
	for _, row := range builtinDefaults() {
		if strings.Contains(row.Name, "_autodiscover") {
			t.Errorf("the template advertises %s, which only produces a redirect warning", row.Name)
		}
	}
}

// The port numbers are the contract with the client: the wrong one produces a
// mail account that is configured automatically and then cannot connect. These
// are the ports the Dovecot drop-in and servika-mail-setup actually serve, not
// the implicit-TLS ports a panel usually advertises.
func TestDiscoveryRecordsUseThePortsTheServerServes(t *testing.T) {
	want := map[string]string{
		"_imap._tcp":       "143",
		"_submission._tcp": "587",
	}
	for _, row := range MailDiscoveryRows() {
		expected, ok := want[row.Name]
		if !ok {
			continue
		}
		if fields := strings.Fields(row.Value); len(fields) < 2 || fields[1] != expected {
			t.Errorf("%s advertises port %q, want %s", row.Name, row.Value, expected)
		}
	}
}

// POP3 is not among Dovecot's enabled protocols and its ports are not opened by
// servika-mail-setup, so a record naming it sends the client at a closed port.
func TestDiscoveryRecordsDoNotAdvertisePOP3(t *testing.T) {
	for _, row := range MailDiscoveryRows() {
		if strings.Contains(row.Name, "pop") {
			t.Errorf("the discovery records advertise %s, but no POP3 service runs", row.Name)
		}
	}
}
