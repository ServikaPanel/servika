package dns

import (
	"context"
	"net"
	"testing"
)

// ipv6Answer is what the resolver is made to return for one case.
//
// The production resolver talks to a real public server, so a test that used it
// would measure the internet rather than this code. The lookup is one call, so
// replacing it is the smallest seam that still leaves the whole decision table
// under test.
type ipv6Answer struct {
	addresses []net.IP
	err       error
}

// runIPv6Check drives one case through the real decision code.
func runIPv6Check(t *testing.T, answer ipv6Answer, ipv6 string) *Check {
	t.Helper()
	previous := lookupIPv6
	lookupIPv6 = func(context.Context, *net.Resolver, string) ([]net.IP, error) {
		return answer.addresses, answer.err
	}
	t.Cleanup(func() { lookupIPv6 = previous })
	return checkAddressIPv6(context.Background(), nil, "aaaa", "example.com", ipv6)
}

// notFound is what a resolver returns for a name with no AAAA record.
var notFound = &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true}

// An IPv4-only install must not read as misconfigured. No address and no record
// means the domain simply does not use IPv6, and a yellow row for that would
// train an operator to ignore the screen.
func TestNoIPv6AndNoRecordReportsNothing(t *testing.T) {
	if check := runIPv6Check(t, ipv6Answer{err: notFound}, ""); check != nil {
		t.Errorf("an IPv4-only domain produced a %s row with reason %q", check.Status, check.Reason)
	}
	if check := runIPv6Check(t, ipv6Answer{}, ""); check != nil {
		t.Errorf("an empty answer produced a %s row with reason %q", check.Status, check.Reason)
	}
}

// THE proof that this check earns its place. A AAAA outranks the A record for
// most clients, and Let's Encrypt tries it FIRST, so a AAAA pointing at an
// address this server does not answer on stops certificate renewal for the
// whole domain. That cannot be shown at the same weight as an A record pointing
// elsewhere, which is a deliberate, working arrangement.
func TestAMisdirectedAAAAIsAnErrorNotAWarning(t *testing.T) {
	check := runIPv6Check(t, ipv6Answer{addresses: []net.IP{net.ParseIP("2001:db8::99")}}, "2001:db8::5")
	if check == nil {
		t.Fatal("a mismatched AAAA reported nothing")
	}
	if check.Status != StatusError {
		t.Errorf("status = %q, want %q: a AAAA pointing elsewhere breaks certificate renewal", check.Status, StatusError)
	}
	if check.Reason != "aaaa_elsewhere" {
		t.Errorf("reason = %q, want aaaa_elsewhere", check.Reason)
	}
	if check.Found == "" {
		t.Error("the address actually published was not reported, so the operator cannot see what to fix")
	}
}

// The matching case, so the test above cannot be satisfied by a check that
// always errors.
func TestAMatchingAAAAIsOK(t *testing.T) {
	check := runIPv6Check(t, ipv6Answer{addresses: []net.IP{
		net.ParseIP("2001:db8::5"),
		net.ParseIP("2001:db8::99"),
	}}, "2001:db8::5")
	if check == nil {
		t.Fatal("a matching AAAA reported nothing")
	}
	if check.Status != StatusOK {
		t.Errorf("status = %q reason = %q, want ok", check.Status, check.Reason)
	}
}

// An address is configured but nothing is published: the operator has work to
// do, and it is not urgent enough to be an error, because the site still serves
// over IPv4.
func TestAConfiguredAddressWithNoRecordWarns(t *testing.T) {
	check := runIPv6Check(t, ipv6Answer{err: notFound}, "2001:db8::5")
	if check == nil {
		t.Fatal("a missing AAAA reported nothing")
	}
	if check.Status != StatusWarning || check.Reason != "aaaa_missing" {
		t.Errorf("status = %q reason = %q, want warning/aaaa_missing", check.Status, check.Reason)
	}
}

// A AAAA the panel did not write still decides where an IPv6 client and the
// certificate authority go, so it is reported rather than passed over.
func TestAnUnmanagedAAAAIsReported(t *testing.T) {
	check := runIPv6Check(t, ipv6Answer{addresses: []net.IP{net.ParseIP("2001:db8::99")}}, "")
	if check == nil {
		t.Fatal("a AAAA the panel does not manage was passed over in silence")
	}
	if check.Status != StatusWarning || check.Reason != "aaaa_unmanaged" {
		t.Errorf("status = %q reason = %q, want warning/aaaa_unmanaged", check.Status, check.Reason)
	}
}

// A broken resolver is never reported as a missing record, or an operator goes
// looking for a record that is already there.
func TestAResolverFailureIsNotAMissingRecord(t *testing.T) {
	broken := &net.DNSError{Err: "server misbehaving", Name: "example.com"}
	check := runIPv6Check(t, ipv6Answer{err: broken}, "2001:db8::5")
	if check == nil {
		t.Fatal("a resolver failure reported nothing")
	}
	if check.Reason == "aaaa_missing" {
		t.Error("a resolver failure was reported as a missing record")
	}
	if check.Reason != "unreadable" {
		t.Errorf("reason = %q, want unreadable", check.Reason)
	}
}
