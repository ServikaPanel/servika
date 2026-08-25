// Package dnsbl asks a DNS blocklist whether it lists an address or a domain.
//
// It imports NOTHING from this repository, which is what lets both
// internal/mail (outbound addresses) and internal/antivirus (domain reputation)
// use one implementation. The resolver is handed IN rather than built here for
// the same reason: choosing it needs internal/config, and a leaf package is the
// only shape both callers can read.
//
// A blocklist answers over DNS: the queried name resolves when the subject is
// listed and does not resolve when it is not. Two things about that are not
// obvious from the protocol, and each was measured rather than assumed.
//
// A NAME THAT RESOLVES IS NOT NECESSARILY A LISTING. The 127.255.255.0/24 block
// carries ERROR codes, not listings. Spamhaus documents .252 as a typing error,
// .254 as a query sent through an open or public resolver, and .255 as too many
// queries. Measured against the live service through 1.1.1.1 and 8.8.8.8:
// dbltest.com.dbl.spamhaus.org, which IS listed, and example.com.dbl.spamhaus.org,
// which is not, BOTH answer 127.255.255.254, and the TXT record for either reads
// "Error: open resolver". So a caller that treats any successful resolution as a
// hit reports every subject on the server as listed the moment an operator adds
// a Spamhaus zone and the host resolves through a public resolver, which is the
// stock configuration on most of them.
//
// "QUERIED AND CLEAN" AND "NEVER QUERIED" ARE DIFFERENT ANSWERS. An empty hit
// list is returned for both, so the second return value separates them. Folding
// them together turns a subject nothing could check into a subject reported
// clean, which is the one answer a reputation screen must not invent.
package dnsbl

import (
	"context"
	"net"
	"regexp"
	"strings"
)

// HostLookup is the slice of *net.Resolver this package uses. The caller
// supplies one, so the choice of resolver stays where it belongs.
type HostLookup interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// MaxZones bounds how many blocklists one setting may name. Every zone is a
// separate query per subject, so the ceiling bounds the work a scan does as
// much as it bounds the text.
const MaxZones = 8

// ZonePattern is what a blocklist zone may look like.
//
// The value reaches a Postfix parameter and a DNS query, so anything that is not
// a hostname is REFUSED rather than quoted: a stray space or newline in a
// Postfix restriction list rewrites the list.
//
// At least one dot is required. A single label is never a blocklist zone, and
// accepting one would let a typo in a space-separated list pass as an extra
// entry that then silently matches nothing.
var ZonePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// errorPrefix is the 127.255.255.0/24 block. Everything in it is a message from
// the blocklist about the QUERY rather than an answer about the subject.
const errorPrefix = "127.255.255."

// LookupIP reports the zones that list an address, and whether it could be
// queried at all.
//
// Only IPv4 is queried: a blocklist of this kind is asked by reversing the four
// octets under the zone, and an IPv6 address has no such form. Returning "not
// queried" for one is what keeps it from reading as clean.
func LookupIP(ctx context.Context, resolver HostLookup, address string, zones []string) ([]string, bool) {
	reversed := ReverseIPv4(address)
	if reversed == "" {
		return nil, false
	}
	return lookup(ctx, resolver, reversed, zones)
}

// LookupDomain reports the zones that list a domain.
//
// A domain blocklist is queried under the name itself rather than a reversed
// form, and it lists the registered name, so a leading "www." is trimmed: a
// listing recorded against example.com is not found under www.example.com.
func LookupDomain(ctx context.Context, resolver HostLookup, name string, zones []string) ([]string, bool) {
	name = Apex(name)
	if name == "" {
		return nil, false
	}
	return lookup(ctx, resolver, name, zones)
}

// lookup is the shared half: the query shape differs, the reading of the answer
// does not.
func lookup(ctx context.Context, resolver HostLookup, prefix string, zones []string) ([]string, bool) {
	if len(zones) == 0 || resolver == nil {
		// Nothing was asked, so nothing was learned. Reporting this as queried
		// would report every subject as clean on a server where the feature is
		// simply off.
		return nil, false
	}
	var hits []string
	for _, zone := range zones {
		addresses, err := resolver.LookupHost(ctx, prefix+"."+zone)
		if err != nil {
			// A name that does not resolve is the ordinary "not listed" answer,
			// and an unreachable zone is indistinguishable from it here. Neither
			// is a hit: reporting an unreachable blocklist as a listing sends an
			// operator chasing a delisting that was never needed.
			continue
		}
		if Listed(addresses) {
			hits = append(hits, zone)
		}
	}
	return hits, true
}

// Listed reports whether a set of returned addresses is a real listing.
//
// An answer entirely inside 127.255.255.0/24 is the blocklist reporting a
// problem with the QUERY. It is deliberately not reported as "could not be
// queried" either: that would need a third state through every caller, and the
// zone did answer. What matters is that it is not a hit.
func Listed(addresses []string) bool {
	for _, address := range addresses {
		if !strings.HasPrefix(address, errorPrefix) {
			return true
		}
	}
	return false
}

// ReverseIPv4 turns 203.0.113.5 into 5.113.0.203, which is how an address
// blocklist zone is queried. Anything that is not IPv4 returns empty.
func ReverseIPv4(value string) string {
	ip := net.ParseIP(value)
	if ip == nil {
		return ""
	}
	four := ip.To4()
	if four == nil {
		return ""
	}
	parts := strings.Split(four.String(), ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

// Apex lowercases a domain and trims a leading "www.", which is the name a
// domain blocklist records a listing against. A name that is not a hostname
// returns empty rather than being sent as a query that can only fail.
func Apex(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")
	name = strings.TrimPrefix(name, "www.")
	if !ZonePattern.MatchString(name) {
		return ""
	}
	return name
}

// ValidateZones parses a space-separated zone list, lowercasing it and refusing
// anything that is not a hostname or a list longer than MaxZones.
func ValidateZones(raw string) ([]string, error) {
	zones := strings.Fields(strings.ToLower(raw))
	if len(zones) > MaxZones {
		return nil, &ZoneError{TooMany: true}
	}
	for _, zone := range zones {
		if !ZonePattern.MatchString(zone) {
			return nil, &ZoneError{Zone: zone}
		}
	}
	return zones, nil
}

// ZoneError says which of the two ways a zone list can be wrong happened, so
// each caller can word it for its own audience rather than reusing a sentence
// written for another screen.
type ZoneError struct {
	// TooMany is set when the list is longer than MaxZones.
	TooMany bool
	// Zone is the entry that is not a hostname.
	Zone string
}

func (e *ZoneError) Error() string {
	if e.TooMany {
		return "too many blocklist zones"
	}
	return "invalid blocklist zone name: " + e.Zone
}
