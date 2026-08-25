package dnsbl

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// stub answers from a fixed table. A name that is absent answers the way a
// resolver answers an unlisted subject: an error.
type stub struct {
	hosts map[string][]string
	asked []string
}

func (s *stub) LookupHost(_ context.Context, host string) ([]string, error) {
	s.asked = append(s.asked, host)
	if addresses, ok := s.hosts[host]; ok {
		return addresses, nil
	}
	return nil, errors.New("no such host")
}

// A blocklist answers by resolving the reversed address under its zone.
func TestReverseIPv4(t *testing.T) {
	if got := ReverseIPv4("203.0.113.5"); got != "5.113.0.203" {
		t.Errorf("ReverseIPv4 = %q, want 5.113.0.203", got)
	}
	// IPv6 is not queried this way, and producing a nonsense name would send a
	// query that can only ever fail.
	if got := ReverseIPv4("2001:db8::1"); got != "" {
		t.Errorf("ReverseIPv4 of an IPv6 address = %q, want empty", got)
	}
	if got := ReverseIPv4("not-an-ip"); got != "" {
		t.Errorf("ReverseIPv4 of a non-address = %q, want empty", got)
	}
}

// MEASURED against the live service through 1.1.1.1 and 8.8.8.8: Spamhaus DBL
// answers 127.255.255.254 for dbltest.com, which IS listed, AND for a domain
// that is not, with the TXT record reading "Error: open resolver". A caller
// that counts any successful resolution as a hit therefore reports every
// subject on the server as listed, which is the stock outcome on a host that
// resolves through a public resolver.
func TestAnOpenResolverErrorIsNotAListing(t *testing.T) {
	resolver := &stub{hosts: map[string][]string{
		"example.com.dbl.test": {"127.255.255.254"},
	}}
	hits, queried := LookupDomain(context.Background(), resolver, "example.com", []string{"dbl.test"})
	if len(hits) != 0 {
		t.Fatalf("an open-resolver error was read as a listing: %v", hits)
	}
	if !queried {
		t.Error("the zone answered, so the subject was queried")
	}
}

func TestEveryErrorCodeInTheBlockIsRefused(t *testing.T) {
	// .252 typing error, .254 open or public resolver, .255 too many queries.
	for _, code := range []string{"127.255.255.252", "127.255.255.254", "127.255.255.255"} {
		if Listed([]string{code}) {
			t.Errorf("%s was read as a listing", code)
		}
	}
}

func TestARealListingIsStillAListing(t *testing.T) {
	// DBL lists under 127.0.1.x and address blocklists under 127.0.0.x. Neither
	// may be swallowed by the error rule.
	for _, code := range []string{"127.0.1.2", "127.0.0.2", "127.0.0.10"} {
		if !Listed([]string{code}) {
			t.Errorf("%s was not read as a listing", code)
		}
	}
	// A mixed answer counts: one real code among error codes is a listing.
	if !Listed([]string{"127.255.255.254", "127.0.1.2"}) {
		t.Error("a real listing beside an error code was dropped")
	}
}

func TestAListedAddressIsFound(t *testing.T) {
	resolver := &stub{hosts: map[string][]string{
		"5.113.0.203.listed.test": {"127.0.0.2"},
	}}
	hits, queried := LookupIP(context.Background(), resolver, "203.0.113.5",
		[]string{"listed.test", "unreachable.test"})
	if len(hits) != 1 || hits[0] != "listed.test" {
		t.Errorf("hits = %v, want only listed.test", hits)
	}
	if !queried {
		t.Error("an IPv4 address with zones configured was reported as not queried")
	}
}

// "Queried and clean" and "never queried" are different answers. Folding them
// together turns a subject nothing could check into one reported clean.
func TestASubjectThatCannotBeQueriedIsNotReportedClean(t *testing.T) {
	resolver := &stub{}
	if _, queried := LookupIP(context.Background(), resolver, "2001:db8::1", []string{"listed.test"}); queried {
		t.Error("an IPv6 address was reported as queried")
	}
	if _, queried := LookupIP(context.Background(), resolver, "203.0.113.5", []string{"listed.test"}); !queried {
		t.Error("an IPv4 address was reported as not queried")
	}
	if _, queried := LookupDomain(context.Background(), resolver, "not a hostname", []string{"listed.test"}); queried {
		t.Error("a name that is not a hostname was reported as queried")
	}
}

// With no zones configured there is nothing to ask, and asking anyway would be
// queries for a feature the operator has not turned on.
func TestNoZonesMeansNoQueries(t *testing.T) {
	resolver := &stub{}
	if hits, queried := LookupIP(context.Background(), resolver, "203.0.113.5", nil); len(hits) != 0 || queried {
		t.Errorf("hits = %v queried = %v, want none and not queried", hits, queried)
	}
	if len(resolver.asked) != 0 {
		t.Errorf("a query was sent with no zone configured: %v", resolver.asked)
	}
}

// A domain blocklist records a listing against the registered name, so a query
// under www. finds nothing and reads as clean.
func TestTheWWWPrefixIsTrimmed(t *testing.T) {
	resolver := &stub{hosts: map[string][]string{
		"example.com.dbl.test": {"127.0.1.2"},
	}}
	hits, _ := LookupDomain(context.Background(), resolver, "WWW.Example.Com.", []string{"dbl.test"})
	if len(hits) != 1 {
		t.Fatalf("the apex was not queried: asked %v", resolver.asked)
	}
	if resolver.asked[0] != "example.com.dbl.test" {
		t.Errorf("queried %q, want example.com.dbl.test", resolver.asked[0])
	}
}

func TestZoneValidation(t *testing.T) {
	if _, err := ValidateZones("zen.spamhaus.org bl.spamcop.net"); err != nil {
		t.Fatalf("a valid pair was refused: %v", err)
	}
	// The value reaches a Postfix restriction list, so anything that is not a
	// hostname is refused rather than quoted.
	for _, raw := range []string{
		"zen.spamhaus.org,permit",
		"reject_unauth_destination",
		"-leading.hyphen.test",
		"singlelabel",
	} {
		if _, err := ValidateZones(raw); err == nil {
			t.Errorf("%q was accepted", raw)
		}
	}
	_, err := ValidateZones(strings.Repeat("a.test ", MaxZones+1))
	var zoneErr *ZoneError
	if !errors.As(err, &zoneErr) || !zoneErr.TooMany {
		t.Errorf("a list over the cap answered %v, want TooMany", err)
	}
}
