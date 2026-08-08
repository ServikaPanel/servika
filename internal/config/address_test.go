package config

import (
	"net"
	"testing"
)

// THE fail-closed proof for the address filter.
//
// Only a globally routable address may become a AAAA record. A link-local, a
// unique local, the loopback or an IPv4-mapped address is unreachable from the
// internet, and publishing one makes the site look dead to every IPv6 client
// while the panel shows a green screen. Nothing later in the chain re-checks
// this, so the filter here is the whole boundary.
func TestOnlyAGloballyRoutableIPv6Qualifies(t *testing.T) {
	rejected := map[string]string{
		"::1":                 "loopback",
		"fe80::1":             "link-local",
		"fe80::dead:beef":     "link-local",
		"fc00::1":             "unique local",
		"fd12:3456:789a:1::1": "unique local",
		"::":                  "unspecified",
		"ff02::1":             "multicast",
		"::ffff:192.0.2.1":    "IPv4-mapped, which is IPv4 on the wire",
		"192.0.2.1":           "IPv4",
		"127.0.0.1":           "IPv4 loopback",
	}
	for value, why := range rejected {
		ip := net.ParseIP(value)
		if ip == nil {
			t.Fatalf("%q did not parse; the fixture is wrong", value)
		}
		if globalUnicastV6(ip) {
			t.Errorf("%s (%s) was accepted as a public IPv6", value, why)
		}
	}

	accepted := []string{
		"2001:db8::1",
		"2a01:4f8:1c1c:1::5",
		"2606:4700:4700::1111",
	}
	for _, value := range accepted {
		ip := net.ParseIP(value)
		if ip == nil {
			t.Fatalf("%q did not parse; the fixture is wrong", value)
		}
		if !globalUnicastV6(ip) {
			t.Errorf("%s is globally routable but was rejected", value)
		}
	}

	if globalUnicastV6(nil) {
		t.Error("a nil address was accepted")
	}
}

// A machine behind NAT cannot learn its public address from its own
// interfaces, so the environment has to win over detection.
func TestTheEnvironmentOverridesDetection(t *testing.T) {
	t.Setenv("SERVIKA_PUBLIC_IPV4", "203.0.113.7")
	t.Setenv("SERVIKA_PUBLIC_IPV6", "2001:db8::7")

	if got := PublicIPv4(); got != "203.0.113.7" {
		t.Errorf("PublicIPv4() = %q, want the environment value", got)
	}
	if got := PublicIPv6(); got != "2001:db8::7" {
		t.Errorf("PublicIPv6() = %q, want the environment value", got)
	}
}

// An empty variable must fall through to detection rather than being returned
// as an address, or every AAAA and every webhook URL would carry an empty host.
func TestAnEmptyOverrideFallsThroughToDetection(t *testing.T) {
	t.Setenv("SERVIKA_PUBLIC_IPV6", "   ")
	// Detection may legitimately find nothing on a v4-only builder, so the
	// assertion is only that the whitespace is never handed back verbatim.
	if got := PublicIPv6(); got == "   " {
		t.Error("the raw environment value was returned instead of being trimmed away")
	}
}

// HasIPv6 asks a DIFFERENT question from PublicIPv6: whether the kernel carries
// the stack at all, not whether a routable address is configured. A host that
// is reachable only over IPv4 today still binds `listen [::]` fine, and one
// booted with ipv6.disable=1 refuses it and takes nginx down. Deriving one from
// the other would make an operator with no global IPv6 lose IPv6 entirely.
func TestKernelSupportIsNotTheSameQuestionAsAPublicAddress(t *testing.T) {
	// Addresses a kernel with IPv6 carries but which are not publishable.
	for _, value := range []string{"fe80::1", "::1", "fd00::1"} {
		ip := net.ParseIP(value)
		if globalUnicastV6(ip) {
			t.Errorf("%s was accepted as a public address", value)
		}
		if !anyIPv6(ip) {
			t.Errorf("%s did not count as kernel IPv6 support, so a host carrying only it would lose its IPv6 listen lines", value)
		}
	}
	// A routable address counts for both.
	if routable := net.ParseIP("2001:db8::1"); !globalUnicastV6(routable) || !anyIPv6(routable) {
		t.Error("a routable address failed one of the two measures")
	}
	// IPv4, mapped or not, is never IPv6 support.
	for _, value := range []string{"127.0.0.1", "192.0.2.1", "::ffff:192.0.2.1"} {
		if anyIPv6(net.ParseIP(value)) {
			t.Errorf("%s counted as IPv6 support", value)
		}
	}
	if anyIPv6(nil) {
		t.Error("a nil address counted as IPv6 support")
	}
}

// The cached answer must not change during a run: roughly thirty call sites
// re-render a vhost independently, and a value that flipped between two of them
// would leave some sites bound to IPv6 and others not inside one nginx reload.
func TestKernelSupportIsStableWithinARun(t *testing.T) {
	first := HasIPv6()
	for range 5 {
		if HasIPv6() != first {
			t.Fatal("HasIPv6 changed answer within a run")
		}
	}
}
