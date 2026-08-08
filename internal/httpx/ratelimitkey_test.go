package httpx

import "testing"

// THE property the whole change exists for: two addresses in one IPv6
// allocation must share a counter.
//
// Without it, anyone holding a routed /64 (which is what a residential or VPS
// IPv6 assignment is) sends every request from a different address and never
// reaches the login lockout, however many passwords they try.
func TestOneIPv6AllocationSharesOneCounter(t *testing.T) {
	first := RateLimitKey("2001:db8:abcd:1234::1")
	second := RateLimitKey("2001:db8:abcd:1234:ffff:ffff:ffff:ffff")

	if first != second {
		t.Errorf("two addresses in the same /64 keyed apart: %q vs %q", first, second)
	}
}

// The other direction, so the test above cannot be satisfied by a function that
// returns a constant.
func TestSeparateIPv6AllocationsAreCountedApart(t *testing.T) {
	if a, b := RateLimitKey("2001:db8:abcd:1234::1"), RateLimitKey("2001:db8:abcd:1235::1"); a == b {
		t.Errorf("two different /64 networks share the key %q", a)
	}
	if a, b := RateLimitKey("2001:db8::1"), RateLimitKey("2001:dead::1"); a == b {
		t.Errorf("two unrelated networks share the key %q", a)
	}
}

// IPv4 is unchanged. There the allocation IS the address, so widening the key
// would put a whole ISP behind one counter and let one abuser lock out
// everybody sharing it.
func TestIPv4IsStillCountedByItsFullAddress(t *testing.T) {
	if got := RateLimitKey("203.0.113.5"); got != "203.0.113.5" {
		t.Errorf("RateLimitKey(%q) = %q, want the address unchanged", "203.0.113.5", got)
	}
	if a, b := RateLimitKey("203.0.113.5"), RateLimitKey("203.0.113.6"); a == b {
		t.Errorf("two IPv4 clients share the key %q", a)
	}
	// Neighbouring /24s must not merge either.
	if a, b := RateLimitKey("203.0.113.5"), RateLimitKey("203.0.114.5"); a == b {
		t.Errorf("two IPv4 networks share the key %q", a)
	}
}

// The ordering trap, measured rather than assumed: netip masks an IPv4-mapped
// address as IPv6 and returns ::/64. Masking before unmapping would give EVERY
// IPv4 client on earth the same key, so five failed logins from anywhere would
// lock out the entire internet.
func TestAnIPv4MappedAddressIsNotMaskedAsIPv6(t *testing.T) {
	mapped := RateLimitKey("::ffff:203.0.113.5")

	if mapped == "::/64" {
		t.Fatal("an IPv4-mapped address was masked as IPv6, merging every IPv4 client into one counter")
	}
	if mapped != RateLimitKey("203.0.113.5") {
		t.Errorf("the mapped form keyed as %q but the plain form as %q; the same client would get two counters",
			mapped, RateLimitKey("203.0.113.5"))
	}
	if a, b := RateLimitKey("::ffff:203.0.113.5"), RateLimitKey("::ffff:198.51.100.5"); a == b {
		t.Errorf("two different IPv4-mapped clients share the key %q", a)
	}
}

// An address the function cannot parse keeps its own bucket. Collapsing every
// unparsable value onto one shared key would let one client's traffic exhaust
// another's allowance.
func TestAnUnparsableAddressIsNotMergedWithAnother(t *testing.T) {
	if a, b := RateLimitKey("not-an-address"), RateLimitKey("also-not-one"); a == b {
		t.Errorf("two unparsable values share the key %q", a)
	}
	if got := RateLimitKey(""); got != "" {
		t.Errorf("RateLimitKey(\"\") = %q, want the value unchanged", got)
	}
}

// Surrounding whitespace must not create a second counter for one client.
func TestWhitespaceDoesNotCreateASecondCounter(t *testing.T) {
	if a, b := RateLimitKey(" 2001:db8::1 "), RateLimitKey("2001:db8::1"); a != b {
		t.Errorf("a padded address keyed as %q but the bare one as %q", a, b)
	}
}
