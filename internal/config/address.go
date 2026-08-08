package config

import (
	"net"
	"os"
	"slices"
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

// GlobalIPv6Addresses returns every globally routable IPv6 address this machine
// carries, so an operator can be shown what is actually assignable rather than
// being asked to type an address from memory.
//
// The SERVIKA_PUBLIC_IPV6 override is included even when no interface carries
// it. An operator who declared the server's public address has already said
// which address the outside world reaches, and a list that omitted it would
// leave them unable to select the one address they know is correct.
func GlobalIPv6Addresses() []string {
	found := interfaceAddresses(globalUnicastV6)
	override := strings.TrimSpace(os.Getenv("SERVIKA_PUBLIC_IPV6"))
	if override != "" && !slices.Contains(found, override) {
		found = append([]string{override}, found...)
	}
	return found
}

// AddressIsLocal reports whether value is one this server may claim as its own.
//
// This is the guard on every address a domain can be pointed at. An address the
// machine does not answer on, published as a AAAA record, makes the site dead
// for every IPv6 client while the panel shows a healthy domain, and it stops
// certificate renewal because Let's Encrypt tries the AAAA first.
//
// The SERVIKA_PUBLIC_IPV6 override counts as local for the reason above: it is
// the operator's own statement of what this server answers on, and it is the
// only correct answer on a host whose public address is not on an interface.
func AddressIsLocal(value string) bool {
	target := net.ParseIP(strings.TrimSpace(value))
	if target == nil {
		return false
	}
	if override := net.ParseIP(strings.TrimSpace(os.Getenv("SERVIKA_PUBLIC_IPV6"))); override != nil && override.Equal(target) {
		return true
	}
	if override := net.ParseIP(strings.TrimSpace(os.Getenv("SERVIKA_PUBLIC_IPV4"))); override != nil && override.Equal(target) {
		return true
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		// Fail CLOSED. An unreadable interface list is not evidence that the
		// address is fine; storing it on a guess is what publishes a dead AAAA.
		return false
	}
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok && network.IP.Equal(target) {
			return true
		}
	}
	return false
}

// firstInterfaceAddress returns the first configured address matching want.
func firstInterfaceAddress(want func(net.IP) bool) string {
	if found := interfaceAddresses(want); len(found) > 0 {
		return found[0]
	}
	return ""
}

// interfaceAddresses returns every configured address matching want.
func interfaceAddresses(want func(net.IP) bool) []string {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var found []string
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		if want(network.IP) {
			found = append(found, network.IP.String())
		}
	}
	return found
}
