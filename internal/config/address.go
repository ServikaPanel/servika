package config

import (
	"net"
	"os"
	"strings"
	"sync"
)

// The server's own public addresses.
//
// This is the ONE place that answers "what address does this machine answer
// on". The IPv4 answer used to be derived in three places at once (the entry
// point, the panel settings handler and the CSP builder), and an IPv6 answer
// alongside it would have made that six. Everything that needs an address now
// asks here.

// PublicIPv4 returns the server's public IPv4 address.
//
// The environment wins because a machine behind NAT cannot discover its own
// public address by looking at its interfaces.
func PublicIPv4() string {
	if value := strings.TrimSpace(os.Getenv("SERVIKA_PUBLIC_IPV4")); value != "" {
		return value
	}
	return firstInterfaceAddress(func(ip net.IP) bool {
		return !ip.IsLoopback() && ip.To4() != nil
	})
}

// PublicIPv6 returns the server's public IPv6 address, or empty when it has
// none.
//
// Only a GLOBAL UNICAST address qualifies. A link-local (fe80::/10), a unique
// local (fc00::/7), the loopback and an IPv4-mapped address are all
// unreachable from the internet, and publishing one as a AAAA record makes the
// site look dead to every IPv6 client while the operator sees a green screen.
// That failure is silent and it is the whole reason this filter is explicit
// rather than "not loopback", which is all the IPv4 side needs.
func PublicIPv6() string {
	if value := strings.TrimSpace(os.Getenv("SERVIKA_PUBLIC_IPV6")); value != "" {
		return value
	}
	return firstInterfaceAddress(globalUnicastV6)
}

// globalUnicastV6 reports whether ip is an IPv6 address the internet can reach.
func globalUnicastV6(ip net.IP) bool {
	if !anyIPv6(ip) {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

// anyIPv6 reports whether ip is an IPv6 address of any kind.
//
// This is what kernel support is measured by, and it is deliberately weaker
// than globalUnicastV6: a host carrying only fe80:: and ::1 still binds the
// IPv6 wildcard, and refusing it there would strip IPv6 from a machine that
// simply has no routable address yet. An IPv4-mapped address does not count,
// because it travels as IPv4 on the wire.
func anyIPv6(ip net.IP) bool {
	return ip != nil && ip.To4() == nil && len(ip) == net.IPv6len
}

var (
	hasIPv6Once sync.Once
	hasIPv6     bool
)

// HasIPv6 reports whether this host's kernel carries the IPv6 stack.
//
// This is a DIFFERENT question from PublicIPv6. What `listen [::]` needs is a
// kernel that can create an AF_INET6 socket, not a globally routable address:
// a host reachable only over IPv4 today still binds the wildcard fine, and one
// booted with ipv6.disable=1 refuses it with EAFNOSUPPORT and takes nginx down
// with it. A kernel with IPv6 always has at least ::1 on the loopback, and one
// without it has no IPv6 address anywhere, which is what this measures.
//
// Measured ONCE and cached for the process's life. It decides whether a vhost
// carries its IPv6 listen lines, and roughly thirty call sites re-render a
// vhost independently: a value that changed between two of them would leave
// some sites bound to IPv6 and others not within a single nginx reload.
func HasIPv6() bool {
	hasIPv6Once.Do(func() {
		hasIPv6 = firstInterfaceAddress(anyIPv6) != ""
	})
	return hasIPv6
}

// firstInterfaceAddress returns the first configured address matching want.
func firstInterfaceAddress(want func(net.IP) bool) string {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		if want(network.IP) {
			return network.IP.String()
		}
	}
	return ""
}
