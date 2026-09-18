// Package netguard blocks server-side request forgery (SSRF) toward internal
// targets. Customer-controlled hosts (Git deployment, backup destinations,
// domain health probes) must not reach loopback, private, link-local, or cloud
// metadata addresses. Operators who intentionally host Git or backup targets on
// a private network can opt out with SERVIKA_ALLOW_PRIVATE_TARGETS=1, which
// disables every check in this package.
package netguard

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"syscall"
)

// ErrBlockedTarget indicates a resolved address points at an internal network.
var ErrBlockedTarget = errors.New("target address is not permitted (internal network)")

// AllowPrivateTargets reports whether the operator disabled SSRF protection.
func AllowPrivateTargets() bool {
	return strings.TrimSpace(os.Getenv("SERVIKA_ALLOW_PRIVATE_TARGETS")) == "1"
}

// blocked reports whether ip belongs to an internal or otherwise unsafe range.
// Cloud metadata addresses (169.254.169.254, fd00:ec2::254) fall under the
// link-local and private checks respectively, so they are covered here.
func blocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// An IPv6 address that carries an IPv4 one is reduced to that address first.
	// ::ffff:10.0.0.1, a NAT64 address and a 6to4 address all reach an IPv4
	// destination, and none of the predicates below sees the embedded address.
	ip = unwrapEmbeddedIPv4(ip)
	if ip.IsLoopback() ||
		ip.IsUnspecified() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() {
		return true
	}
	return slices.ContainsFunc(reservedRanges, func(network *net.IPNet) bool {
		return network.Contains(ip)
	})
}

// unwrapEmbeddedIPv4 returns the IPv4 address an IPv6 address carries, or the
// address itself when it carries none.
func unwrapEmbeddedIPv4(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	if v16 := ip.To16(); v16 != nil {
		// NAT64 (64:ff9b::/96) holds the IPv4 address in its last four bytes.
		if nat64Prefix.Contains(v16) {
			return net.IPv4(v16[12], v16[13], v16[14], v16[15]).To4()
		}
		// 6to4 (2002::/16) holds it in the two bytes after the prefix.
		if sixToFourPrefix.Contains(v16) {
			return net.IPv4(v16[2], v16[3], v16[4], v16[5]).To4()
		}
	}
	return ip
}

var (
	nat64Prefix     = mustCIDR("64:ff9b::/96")
	sixToFourPrefix = mustCIDR("2002::/16")

	// reservedRanges are the ranges the net.IP predicates do NOT cover. Each one
	// reaches something other than a customer's public host, so a name resolving
	// into any of them is not a target the panel probes or clones from.
	// The RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
	// 203.0.113.0/24) are deliberately NOT here. They reach nothing, so blocking
	// them adds no protection, and this repository's tests use them as the
	// address of a public remote host precisely because they are never real.
	reservedRanges = []*net.IPNet{
		mustCIDR("100.64.0.0/10"), // carrier-grade NAT, and the range Tailscale hands out
		mustCIDR("192.0.0.0/24"),  // IETF protocol assignments
		mustCIDR("198.18.0.0/15"), // benchmarking
		mustCIDR("240.0.0.0/4"),   // reserved, and the broadcast address
		mustCIDR("100::/64"),      // discard-only
	}
)

// mustCIDR parses a range this package declares itself. A failure is a typo in
// the literal above, which a panic reports at startup rather than leaving a
// range silently unguarded.
func mustCIDR(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic("netguard: bad reserved range " + cidr)
	}
	return network
}

// CheckHost resolves host and rejects it when any resolved IP is internal.
// Checking every resolved address defends against DNS records that mix a public
// and a private answer. It is a no-op when the operator opted out.
func CheckHost(host string) error {
	if AllowPrivateTargets() {
		return nil
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("empty host")
	}
	// Accept a bracketed or bare IP literal directly.
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if blocked(ip) {
			return ErrBlockedTarget
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolve host: %w", err)
	}
	if slices.ContainsFunc(ips, blocked) {
		return ErrBlockedTarget
	}
	return nil
}

// ResolveAllowed resolves host ONCE, vets every answer, and returns the concrete
// address a caller should connect to.
//
// CheckHost validates the name and hands the bare name back, which is enough for
// an in-process client whose dialer also carries DialControl. It is not enough
// for an EXTERNAL tool: that tool resolves the name a second time, and between
// the two lookups an attacker's authoritative server can answer with a public
// address for the check and an internal one for the connection. Handing the tool
// the vetted address instead removes the second lookup.
//
// The address comes back BARE, never bracketed: ssh takes an IPv6 address
// without brackets and a URL authority takes it with them, so the caller that
// knows which one it is building adds them.
func ResolveAllowed(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	// The opt-out disables every check in this package, this one included: an
	// operator hosting the destination on a private network needs the name to
	// reach it.
	if AllowPrivateTargets() {
		return host, nil
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if blocked(ip) {
			return "", ErrBlockedTarget
		}
		return ip.String(), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("resolve host: %w", err)
	}
	// Every answer is vetted, not just the one that gets used: a record mixing a
	// public and a private address must be refused outright rather than
	// silently reduced to its public half.
	if slices.ContainsFunc(ips, blocked) {
		return "", ErrBlockedTarget
	}
	if len(ips) == 0 {
		return "", ErrBlockedTarget
	}
	return ips[0].String(), nil
}

// CheckGitURL extracts the host from a Git remote URL and validates it.
// It handles https://, ssh://, and the scp-like git@host:path form.
func CheckGitURL(raw string) error {
	if AllowPrivateTargets() {
		return nil
	}
	host, err := gitHost(raw)
	if err != nil {
		return err
	}
	return CheckHost(host)
}

func gitHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "ssh://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("parse git URL: %w", err)
		}
		if u.Hostname() == "" {
			return "", fmt.Errorf("git URL has no host")
		}
		return u.Hostname(), nil
	}
	// scp-like syntax: [user@]host:path
	rest := raw
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	colon := strings.Index(rest, ":")
	if colon <= 0 {
		return "", fmt.Errorf("invalid git URL")
	}
	return rest[:colon], nil
}

// DialControl is a net.Dialer.Control hook that rejects connections to internal
// addresses. It runs after DNS resolution with the concrete ip:port about to be
// dialed, so it protects HTTP clients across redirects and against DNS
// rebinding. Wire it into a net.Dialer used by an http.Transport.
func DialControl(_, address string, _ syscall.RawConn) error {
	if AllowPrivateTargets() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || blocked(ip) {
		return ErrBlockedTarget
	}
	return nil
}
