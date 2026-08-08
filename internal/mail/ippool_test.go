package mail

import (
	"context"
	"net"
	"strings"
	"testing"
)

// master.cf defines every Postfix service on the machine. The panel must own
// only its own block, so an operator's own services survive an apply.
func TestManagedBlockReplacesOnlyItself(t *testing.T) {
	before := "smtp      inet  n - n - - smtpd\n"
	after := "\npickup    unix  n - n 60 1 pickup\n"
	original := before + blockBegin + "\nold_service unix - - n - - smtp\n" + blockEnd + "\n" + after

	updated := replaceManagedBlock(original, renderTransportServices([]string{"203.0.113.5"}))
	if !strings.HasPrefix(updated, before) {
		t.Errorf("the lines above the block were lost:\n%s", updated)
	}
	if !strings.HasSuffix(updated, after) {
		t.Errorf("the lines below the block were lost:\n%s", updated)
	}
	if strings.Contains(updated, "old_service") {
		t.Errorf("the previous managed block survived:\n%s", updated)
	}
	if !strings.Contains(updated, "smtp_bind_address=203.0.113.5") {
		t.Errorf("the new service is missing:\n%s", updated)
	}
}

// An empty pool has to remove the services rather than leave dead ones that
// Postfix starts and nothing routes to.
func TestEmptyPoolRemovesTheBlockEntirely(t *testing.T) {
	original := "smtp inet n - n - - smtpd\n" + blockBegin + "\nservika_out_1 unix - - n - - smtp\n" + blockEnd + "\n"
	updated := replaceManagedBlock(original, renderTransportServices(nil))
	if strings.Contains(updated, blockBegin) || strings.Contains(updated, "servika_out_") {
		t.Errorf("the block survived an empty pool:\n%s", updated)
	}
	if !strings.Contains(updated, "smtp inet n - n - - smtpd") {
		t.Errorf("the operator's own service was removed:\n%s", updated)
	}
}

// A write interrupted part way leaves a begin marker with no end. Everything
// from the marker on is the panel's, so replacing it is the repair; treating it
// as operator content would append a second block on every apply.
func TestTruncatedBlockIsRepairedRatherThanDuplicated(t *testing.T) {
	original := "smtp inet n - n - - smtpd\n" + blockBegin + "\nservika_out_half"
	updated := replaceManagedBlock(original, renderTransportServices([]string{"203.0.113.5"}))
	if strings.Count(updated, blockBegin) != 1 {
		t.Errorf("the block appears %d times:\n%s", strings.Count(updated, blockBegin), updated)
	}
	if strings.Contains(updated, "servika_out_half") {
		t.Errorf("the truncated remnant survived:\n%s", updated)
	}
}

// Applying twice with the same pool has to produce the same file, or every apply
// looks like a change and reloads Postfix for nothing.
func TestApplyingTwiceIsStable(t *testing.T) {
	base := "smtp inet n - n - - smtpd\n"
	block := renderTransportServices([]string{"203.0.113.5", "203.0.113.6"})
	once := replaceManagedBlock(base, block)
	twice := replaceManagedBlock(once, block)
	if once != twice {
		t.Errorf("a second apply changed the file:\n%q\nvs\n%q", once, twice)
	}
}

// The service name goes into master.cf, where a dot or a colon is not part of a
// name. An address that produced one would make Postfix refuse to start.
func TestTransportNameIsAValidServiceName(t *testing.T) {
	for _, value := range []string{"203.0.113.5", "2001:db8::1"} {
		name := transportName(value)
		if strings.ContainsAny(name, ". :") {
			t.Errorf("transportName(%q) = %q, which master.cf cannot use", value, name)
		}
	}
	if transportName("203.0.113.5") == transportName("203.0.113.6") {
		t.Error("two addresses produced the same transport name")
	}
}

// The table key is "@domain", which is how Postfix looks up a sender-dependent
// transport by domain. Writing the bare domain produces a table that loads and
// never matches.
func TestSenderTransportKeysAreDomainScoped(t *testing.T) {
	body := string(renderSenderTransport(map[string]string{"example.com": "203.0.113.5"}))
	if !strings.Contains(body, "@example.com\t"+transportName("203.0.113.5")) {
		t.Errorf("the transport table line is wrong:\n%s", body)
	}
}

// The file is rewritten on every change, and a changed file means a reload.
func TestSenderTransportDoesNotDependOnMapOrder(t *testing.T) {
	assignments := map[string]string{
		"b.test": "203.0.113.5",
		"a.test": "203.0.113.6",
		"c.test": "203.0.113.5",
	}
	first := string(renderSenderTransport(assignments))
	for range 10 {
		if string(renderSenderTransport(assignments)) != first {
			t.Fatal("the transport table depends on map iteration order")
		}
	}
	if strings.Index(first, "a.test") > strings.Index(first, "b.test") {
		t.Errorf("the table is not sorted:\n%s", first)
	}
}

// A blocklist answers by resolving the reversed address under its zone.
func TestReverseIPv4(t *testing.T) {
	if got := reverseIPv4("203.0.113.5"); got != "5.113.0.203" {
		t.Errorf("reverseIPv4 = %q, want 5.113.0.203", got)
	}
	// IPv6 is not queried this way, and producing a nonsense name would send a
	// query that can only ever fail.
	if got := reverseIPv4("2001:db8::1"); got != "" {
		t.Errorf("reverseIPv4 of an IPv6 address = %q, want empty", got)
	}
	if got := reverseIPv4("not-an-ip"); got != "" {
		t.Errorf("reverseIPv4 of a non-address = %q, want empty", got)
	}
}

// A lookup that fails for any reason other than a listing must not count as a
// hit: reporting an unreachable blocklist as a listing sends an operator
// chasing a delisting that was never needed.
func TestUnreachableBlocklistIsNotAHit(t *testing.T) {
	original := poolResolver
	t.Cleanup(func() { poolResolver = original })
	poolResolver = func() addrLookup {
		return scanResolver{hosts: map[string][]string{
			"5.113.0.203.listed.test": {"127.0.0.2"},
		}}
	}
	hits, queried := dnsblHits(context.Background(), "203.0.113.5",
		[]string{"listed.test", "unreachable.test"})
	if len(hits) != 1 || hits[0] != "listed.test" {
		t.Errorf("hits = %v, want only listed.test", hits)
	}
	if !queried {
		t.Error("an IPv4 address with zones configured was reported as not queried")
	}
}

// "Queried and clean" and "never queried" are different answers. They used to
// be the same one: an IPv6 address has no reversed IPv4 form, so it returned no
// hits and read as clean, which is a false assurance about an address nothing
// ever checked.
func TestAnAddressThatCannotBeQueriedIsNotReportedClean(t *testing.T) {
	original := poolResolver
	t.Cleanup(func() { poolResolver = original })
	poolResolver = func() addrLookup { return scanResolver{} }

	if hits, queried := dnsblHits(context.Background(), "2001:db8::1", []string{"listed.test"}); queried {
		t.Errorf("an IPv6 address was reported as queried (hits = %v)", hits)
	}
	if _, queried := dnsblHits(context.Background(), "203.0.113.5", []string{"listed.test"}); !queried {
		t.Error("an IPv4 address was reported as not queried")
	}
}

// With no zones configured there is nothing to ask, and asking anyway would be
// queries for a feature the operator has not turned on.
func TestNoZonesMeansNoQueries(t *testing.T) {
	original := poolResolver
	t.Cleanup(func() { poolResolver = original })
	queried := false
	poolResolver = func() addrLookup {
		queried = true
		return scanResolver{}
	}
	if hits, queried := dnsblHits(context.Background(), "203.0.113.5", nil); len(hits) != 0 || queried {
		t.Errorf("hits = %v queried = %v, want none and not queried", hits, queried)
	}
	if queried {
		t.Error("a resolver was built even though no zone is configured")
	}
}

// An address that does not forward-confirm is refused by most large providers,
// so recording it as fine would hide the reason mail stops being delivered.
func TestPTRIsOnlyOKWhenItForwardConfirms(t *testing.T) {
	original := poolResolver
	t.Cleanup(func() { poolResolver = original })
	poolResolver = func() addrLookup {
		return scanResolver{
			addrs: map[string][]string{"203.0.113.5": {"mail.example.com."}},
			ips:   map[string][]string{"mail.example.com": {"198.51.100.9"}},
		}
	}
	name, ok := lookupPTR(context.Background(), "203.0.113.5")
	if ok {
		t.Error("a PTR that does not resolve back was reported as fine")
	}
	if name != "mail.example.com" {
		t.Errorf("name = %q, want the PTR without its trailing dot", name)
	}
}

// scanResolver answers from fixed tables so the scanner can be exercised
// without network access.
type scanResolver struct {
	hosts map[string][]string
	addrs map[string][]string
	ips   map[string][]string
}

func (r scanResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	values, ok := r.hosts[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return values, nil
}

func (r scanResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	values, ok := r.addrs[addr]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}
	return values, nil
}

func (r scanResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	values, ok := r.ips[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IPAddr, 0, len(values))
	for _, value := range values {
		out = append(out, net.IPAddr{IP: net.ParseIP(value)})
	}
	return out, nil
}
