package dbremote

import (
	"errors"
	"strings"
	"testing"
)

// THE rule of this package. Everything a customer types lands in the HOST
// component of a MariaDB account, where `%` and `_` are wildcards, so a value
// that slipped through would not be a bad row: it would be a grant to the whole
// internet on an account the screen still described as restricted.
func TestNothingThatIsNotAnAddressSurvives(t *testing.T) {
	for _, input := range []string{
		"%",
		"_",
		"10.0.0.%",
		"10.0.0._",
		"%.example.com",
		"db.example.com",
		"'; DROP USER 'x'@'%'; --",
		"10.0.0.1'",
		"10.0.0.1`",
		"10.0.0.1\n%",
		"10.0.0.1 %",
		"10.0.0.1:3306",
		"",
		"   ",
		"localhost",
		"10.0.0.1/33",
		"not an address",
	} {
		if _, _, err := ParseHost(input); err == nil {
			t.Errorf("ParseHost(%q) was accepted", input)
		}
	}
}

// The output is rendered from the PARSED address, never from the input, so no
// spelling of a wildcard can be carried through even if it parsed. Surrounding
// whitespace is trimmed rather than refused: a pasted address routinely carries
// it, and it cannot reach the output either way.
func TestTheOutputIsRenderedFromTheParsedAddress(t *testing.T) {
	if cidr, host, err := ParseHost("  203.0.113.9  "); err != nil || cidr != "203.0.113.9" || host != "203.0.113.9" {
		t.Errorf("a padded address gave %q/%q, %v", cidr, host, err)
	}
	cidr, mysqlHost, err := ParseHost(" 010.0.0.1 ")
	if err == nil {
		// Go refuses a leading zero in an IPv4 octet, which is the safer answer.
		t.Fatalf("a leading zero was accepted as %q/%q", cidr, mysqlHost)
	}
	// An IPv6 address written the long way collapses, so one address cannot
	// occupy two rows under the UNIQUE key.
	cidr, mysqlHost, err = ParseHost("2001:0db8:0000:0000:0000:0000:0000:0005")
	if err != nil {
		t.Fatalf("ParseHost: %v", err)
	}
	if cidr != "2001:db8::5" || mysqlHost != "2001:db8::5" {
		t.Errorf("got %q/%q, want the collapsed form", cidr, mysqlHost)
	}
}

// MEASURED on MariaDB 10.11: a host of 10.0.0.0/255.255.255.0 matches a client
// in that range, and 10.0.0.0/24 is accepted by CREATE USER without any error
// and then authenticates nobody. Both failures are silent, so the conversion is
// the only thing standing between a customer and an account that cannot work.
func TestAnIPv4RangeBecomesADottedNetmask(t *testing.T) {
	for _, c := range []struct{ in, cidr, host string }{
		{"10.0.0.0/24", "10.0.0.0/24", "10.0.0.0/255.255.255.0"},
		{"192.0.2.0/25", "192.0.2.0/25", "192.0.2.0/255.255.255.128"},
		{"172.16.0.0/12", "172.16.0.0/12", "172.16.0.0/255.240.0.0"},
		// A /32 is one address; the bare form is what an operator reading
		// mysql.user expects to see.
		{"203.0.113.9/32", "203.0.113.9", "203.0.113.9"},
		{"203.0.113.9", "203.0.113.9", "203.0.113.9"},
	} {
		cidr, host, err := ParseHost(c.in)
		if err != nil {
			t.Errorf("ParseHost(%q): %v", c.in, err)
			continue
		}
		if cidr != c.cidr || host != c.host {
			t.Errorf("ParseHost(%q) = %q/%q, want %q/%q", c.in, cidr, host, c.cidr, c.host)
		}
		if strings.Contains(host, "/") && !strings.Contains(host, ".") {
			t.Errorf("ParseHost(%q) produced a prefix length, which matches nobody: %q", c.in, host)
		}
	}
}

// MEASURED: MariaDB accepts an IPv6 netmask AND an IPv6 prefix length in a host
// component without error, and neither ever matches a connecting client. The
// range is refused rather than stored, because storing it would leave the
// firewall open for addresses the database will never let in.
func TestAnIPv6RangeIsRefusedWithItsOwnReason(t *testing.T) {
	for _, input := range []string{"2001:db8::/64", "2001:db8::/32", "fd00::/8"} {
		_, _, err := ParseHost(input)
		if !errors.Is(err, ErrIPv6RangeUnsupported) {
			t.Errorf("ParseHost(%q) = %v, want ErrIPv6RangeUnsupported", input, err)
		}
	}
	// A single IPv6 address is fine, and that is the whole point of a separate
	// error: the customer is not being told to fix a typo.
	cidr, host, err := ParseHost("2001:db8::5/128")
	if err != nil {
		t.Fatalf("a /128 was refused: %v", err)
	}
	if cidr != "2001:db8::5" || host != "2001:db8::5" {
		t.Errorf("got %q/%q, want the bare address", cidr, host)
	}
}

// The ranges that put `%` back under another name.
func TestARangeThatMeansEverybodyIsRefused(t *testing.T) {
	for _, input := range []string{
		"0.0.0.0/0",
		"0.0.0.0",
		"::/0",
		"::",
		"10.0.0.0/7",
		"1.0.0.0/1",
		"127.0.0.1",
		"::1",
	} {
		if _, _, err := ParseHost(input); err == nil {
			t.Errorf("ParseHost(%q) was accepted", input)
		}
	}
	// The boundary itself is allowed, so the refusal is a bound and not a ban on
	// ranges.
	if _, _, err := ParseHost("10.0.0.0/8"); err != nil {
		t.Errorf("a /8 was refused: %v", err)
	}
}
