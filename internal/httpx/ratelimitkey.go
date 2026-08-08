package httpx

import (
	"net/netip"
	"strings"
)

// RateLimitKey collapses a client address to the unit a rate limit should count.
//
// An IPv6 client is handed a /64 NETWORK, not a single address, and every
// address inside it is theirs to use. Counting per /128 therefore lets one
// allocation present a fresh source address on every request and never reach any
// limit, which silently disables the login brute-force protection and every
// other per-IP counter for anyone with IPv6. Counting per /64 is the IPv6
// equivalent of counting an IPv4 client by its address.
//
// IPv4 keeps its full address, because there the allocation IS the address.
//
// ORDER MATTERS: an IPv4-mapped address (::ffff:203.0.113.5) is unmapped BEFORE
// any masking. Masking it as IPv6 yields ::/64 for every IPv4 client on earth,
// which would merge them all into one counter and lock out the entire internet
// after five failed logins.
func RateLimitKey(ip string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		// Not an address this code can reason about. Counting it verbatim keeps
		// it in its own bucket; collapsing unparsable values into one shared key
		// would let one client's traffic lock out another's.
		return ip
	}
	if addr.Is4() || addr.Is4In6() {
		return addr.Unmap().String()
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		// Unreachable for a 128-bit address, but a masking failure must not
		// silently widen the key to something that merges unrelated clients.
		return addr.String()
	}
	return prefix.String()
}
