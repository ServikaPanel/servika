// Package dbremote manages per-account remote access to MariaDB: which source
// addresses may reach a customer's database account, the server-wide switch that
// opens the listening socket, and the panel's record of both.
//
// Everything a customer types here ends up in the HOST component of a MariaDB
// account, which is a pattern language: `%` and `_` are wildcards there, so a
// value that looks like an address but is not one would silently widen the grant
// to everybody. Nothing in this package filters that text. Addresses are PARSED
// with net.ParseIP and net.ParseCIDR and re-rendered from the parsed value, so a
// wildcard cannot survive the round trip whether or not anyone thought to look
// for it.
package dbremote

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// The refusals a screen has to be able to tell apart.
var (
	// ErrHostInvalid covers everything that is not an address: a hostname, a
	// wildcard, an empty string, a port, whitespace.
	ErrHostInvalid = errors.New("not an IP address or CIDR range")
	// ErrIPv6RangeUnsupported is its own error because the input is a perfectly
	// valid range and the refusal is a MariaDB limitation, not a mistake. A
	// screen that reported it as "invalid" would send the customer looking for a
	// typo that is not there.
	ErrIPv6RangeUnsupported = errors.New("MariaDB cannot match an IPv6 range")
	// ErrHostTooBroad covers the ranges that put the wildcard back by another
	// name, and the addresses that are not a remote client at all.
	ErrHostTooBroad = errors.New("range is too broad to be an allowlist entry")
)

// minIPv4Prefix is the widest IPv4 range that may be stored. A /8 is sixteen
// million addresses; anything wider is `%` with extra steps, and the whole point
// of this feature is that `%` is never created.
const minIPv4Prefix = 8

// ParseHost turns customer input into the two forms the panel needs.
//
// cidr is the canonical spelling of what was entered and is what the firewall
// and the UNIQUE key use. mysqlHost is what CREATE USER receives.
//
// They differ, and the difference is not cosmetic. Measured against MariaDB
// 10.11: a host of `10.0.0.0/255.255.255.0` matches a client in that range,
// while `10.0.0.0/24` is accepted by CREATE USER without any error and then
// matches NOBODY. The failure is silent on both sides, so the conversion happens
// here rather than being left to whatever a caller happens to pass through.
func ParseHost(input string) (cidr, mysqlHost string, err error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", "", ErrHostInvalid
	}

	if address := net.ParseIP(trimmed); address != nil {
		if err := checkAddress(address); err != nil {
			return "", "", err
		}
		// String() on the parsed value, never the input: it drops a leading zero
		// and collapses an IPv6 group, so two spellings of one address cannot
		// occupy two rows.
		canonical := address.String()
		return canonical, canonical, nil
	}

	address, network, parseErr := net.ParseCIDR(trimmed)
	if parseErr != nil {
		return "", "", ErrHostInvalid
	}
	if err := checkAddress(address); err != nil {
		return "", "", err
	}

	ones, bits := network.Mask.Size()
	if bits == 128 {
		// A /128 is one address written the long way; anything wider is a range
		// MariaDB has no way to express.
		if ones != 128 {
			return "", "", ErrIPv6RangeUnsupported
		}
		canonical := network.IP.String()
		return canonical, canonical, nil
	}

	if ones < minIPv4Prefix {
		return "", "", ErrHostTooBroad
	}
	if ones == 32 {
		// A /32 is one address. MariaDB accepts `10.0.0.1/255.255.255.255` too,
		// but the bare address is what an operator reading mysql.user expects.
		canonical := network.IP.String()
		return canonical, canonical, nil
	}
	return network.String(), network.IP.String() + "/" + dottedMask(network.Mask), nil
}

// checkAddress refuses the addresses that cannot be a remote client, whether
// they arrive bare or as the base of a range.
//
// The unspecified address is the important one: `0.0.0.0/0` parses, and storing
// it would hand every account to the whole internet through a field whose entire
// purpose is to prevent that.
func checkAddress(address net.IP) error {
	switch {
	case address.IsUnspecified():
		return ErrHostTooBroad
	case address.IsLoopback():
		// Already reachable over the socket; a grant here would only widen the
		// account without giving anyone access they did not have.
		return ErrHostTooBroad
	case address.IsLinkLocalUnicast(), address.IsLinkLocalMulticast(), address.IsMulticast():
		return ErrHostInvalid
	}
	return nil
}

// dottedMask renders an IPv4 mask the way MariaDB's host component wants it.
func dottedMask(mask net.IPMask) string {
	if len(mask) == 16 {
		mask = mask[12:]
	}
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
