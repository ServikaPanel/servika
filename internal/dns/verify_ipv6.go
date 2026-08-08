package dns

import (
	"context"
	"net"
)

// The AAAA checks.
//
// A published AAAA is not a cosmetic addition to the A record: it OUTRANKS it
// for most clients, and Let's Encrypt tries it FIRST when one exists. So a AAAA
// pointing at an address this server does not answer on does not merely lose
// IPv6 visitors, it stops certificate renewal for the whole domain, silently,
// weeks after the record was added. That is why a mismatch here is an ERROR and
// not the `elsewhere` warning the A record gets: an A record pointing elsewhere
// is a deliberate, working arrangement, while a AAAA pointing elsewhere while
// the panel serves the site is a break in progress.

// lookupIPv6 is a variable so a test can drive every branch of the decision
// below. The production resolver talks to a real public server, so a test that
// used it would measure the internet rather than this code.
var lookupIPv6 = func(ctx context.Context, resolver *net.Resolver, host string) ([]net.IP, error) {
	return resolver.LookupIP(ctx, "ip6", host)
}

// checkAddressIPv6 verifies one hostname's AAAA record.
//
// It returns nil when there is nothing to say: no address configured and no
// AAAA published means the domain simply does not use IPv6, and colouring a row
// yellow for that would make every IPv4-only install look misconfigured.
func checkAddressIPv6(ctx context.Context, resolver *net.Resolver, key, host, ipv6 string) *Check {
	check := Check{Key: key, Host: host, Expected: ipv6}
	addresses, err := lookupIPv6(ctx, resolver, host)

	if err != nil {
		reason := lookupFailureReason(err, "missing")
		if reason == "missing" {
			if ipv6 == "" {
				return nil // no address, no record: nothing to report
			}
			check.Status = StatusWarning
			check.Reason = "aaaa_missing"
			return &check
		}
		// A resolver failure is not a missing record, and saying so would send
		// an operator looking for a record that is already there.
		check.Status = StatusWarning
		check.Reason = reason
		return &check
	}

	if len(addresses) == 0 {
		if ipv6 == "" {
			return nil
		}
		check.Status = StatusWarning
		check.Reason = "aaaa_missing"
		return &check
	}

	check.Found = joinIPs(addresses)
	if ipv6 == "" {
		// A record the panel did not write and cannot judge. It still decides
		// where an IPv6 client and the certificate authority go, so it is
		// reported rather than passed over in silence.
		check.Status = StatusWarning
		check.Reason = "aaaa_unmanaged"
		return &check
	}
	if containsPlainIP(addresses, ipv6) {
		check.Status = StatusOK
		return &check
	}
	check.Status = StatusError
	check.Reason = "aaaa_elsewhere"
	return &check
}

// joinIPs renders a plain address list. LookupIP returns net.IP rather than the
// net.IPAddr that joinAddresses takes.
func joinIPs(addresses []net.IP) string {
	values := make([]net.IPAddr, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, net.IPAddr{IP: address})
	}
	return joinAddresses(values)
}

// containsPlainIP reports whether value is among addresses.
func containsPlainIP(addresses []net.IP, value string) bool {
	target := net.ParseIP(value)
	if target == nil {
		return false
	}
	for _, address := range addresses {
		if address.Equal(target) {
			return true
		}
	}
	return false
}
