package netguard

import (
	"net"
	"testing"
)

// The net.IP predicates leave several ranges open. Each one here reaches
// something other than a customer's public host, and two of them (NAT64 and
// 6to4) carry an IPv4 address the predicates never look at.
func TestBlockedCoversTheReservedRanges(t *testing.T) {
	refused := []string{
		"100.64.0.1",       // carrier-grade NAT
		"192.0.0.8",        // IETF protocol assignment
		"198.18.0.1",       // benchmarking
		"240.0.0.1",        // reserved
		"255.255.255.255",  // broadcast
		"100::1",           // discard-only
		"64:ff9b::a00:1",   // NAT64 carrying 10.0.0.1
		"2002:a00:1::",     // 6to4 carrying 10.0.0.1
		"::ffff:127.0.0.1", // IPv4-mapped loopback
	}
	for _, address := range refused {
		if !blocked(net.ParseIP(address)) {
			t.Errorf("blocked(%s) = false, want true", address)
		}
	}
}

// The negative half proves nothing alone: a guard that refused every address
// would pass it while stopping every probe and every clone. The addresses are
// the RFC 5737 and RFC 3849 documentation ranges, which is what this repository
// uses everywhere a test needs a public remote host.
func TestBlockedStillAllowsAPublicAddress(t *testing.T) {
	allowed := []string{"203.0.113.5", "192.0.2.5", "198.51.100.5", "2001:db8::1", "64:ff9b::cb00:7105"}
	for _, address := range allowed {
		if blocked(net.ParseIP(address)) {
			t.Errorf("blocked(%s) = true, want false", address)
		}
	}
}
