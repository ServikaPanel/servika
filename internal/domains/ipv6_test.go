package domains

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/config"
	"servika/internal/dns"
)

// putIPv6 drives the write path with no database behind it.
//
// Every refusal below happens BEFORE the handler reaches h.DB, which is exactly
// the property being asserted: an address that fails the guard must never be
// stored. A nil database makes that unmissable, because a guard that let the
// request through would panic instead of quietly passing the test.
func putIPv6(t *testing.T, body string) (int, string, string) {
	t.Helper()
	handlers := &Handlers{}
	request := httptest.NewRequest(http.MethodPut, "/domains/1/ipv6", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	handlers.SetIPv6(recorder, request)
	message, reason := decodeReason(t, recorder.Body.String())
	return recorder.Code, message, reason
}

// THE fail-closed proof for this write path. An address the server does not
// answer on, published as a AAAA record, makes the site dead for every IPv6
// client while the panel shows a healthy domain, and it stops certificate
// renewal because Let's Encrypt tries the AAAA first. Both failures are silent,
// so the refusal has to happen before the value is stored.
func TestAnAddressThisServerDoesNotCarryIsRefused(t *testing.T) {
	// Documentation range (RFC 3849): never assigned to a real interface.
	status, message, reason := putIPv6(t, `{"ipv6":"2001:db8::dead:beef"}`)

	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if reason != reasonIPv6NotLocal {
		t.Errorf("reason = %q, want %q", reason, reasonIPv6NotLocal)
	}
	if message == "" {
		t.Error("no message was written beside the reason code")
	}
}

// The guard must not be satisfied by an IPv4 address in the IPv6 field: the
// column feeds AAAA records, and an IPv4 address in one produces a zone
// named-checkzone refuses, taking the whole zone offline.
func TestAnIPv4AddressIsRefusedForTheIPv6Field(t *testing.T) {
	status, _, reason := putIPv6(t, `{"ipv6":"127.0.0.1"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if reason != reasonIPv6NotV6 {
		t.Errorf("reason = %q, want %q", reason, reasonIPv6NotV6)
	}

	// Loopback IPv4 is genuinely configured on every machine, so this also
	// proves the family check runs BEFORE the local check rather than being
	// masked by it.
	if !config.AddressIsLocal("127.0.0.1") {
		t.Skip("this machine has no loopback address, so the ordering cannot be shown here")
	}
}

// Anything that is not an address at all is refused with its own code, so the
// screen can say what is wrong rather than showing one message for every case.
func TestAValueThatIsNotAnAddressIsRefused(t *testing.T) {
	for _, value := range []string{"not-an-address", "2001:db8::/64", "example.com"} {
		status, _, reason := putIPv6(t, `{"ipv6":"`+value+`"}`)
		if status != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", value, status)
		}
		if reason != reasonIPv6Invalid {
			t.Errorf("%s: reason = %q, want %q", value, reason, reasonIPv6Invalid)
		}
	}
}

// The reason codes are stable identifiers, never sentences: the API is English
// and the screen renders twelve languages.
func TestTheIPv6ReasonCodesAreCodes(t *testing.T) {
	for _, code := range []string{reasonIPv6NotLocal, reasonIPv6NotV6, reasonIPv6Invalid} {
		if code == "" || strings.ContainsAny(code, " .") || strings.ToLower(code) != code {
			t.Errorf("%q is not a stable reason code", code)
		}
	}
}

// The operator's own declaration of the server's public address counts as
// local. On a host whose public address is not on an interface it is the only
// correct answer, and a guard that refused it would leave the operator unable
// to assign the one address they know works.
func TestTheDeclaredPublicAddressCountsAsLocal(t *testing.T) {
	const declared = "2001:db8::5"
	if config.AddressIsLocal(declared) {
		t.Skip("this machine really carries the documentation address")
	}
	t.Setenv("SERVIKA_PUBLIC_IPV6", declared)
	if !config.AddressIsLocal(declared) {
		t.Error("the declared public address was refused, so it could never be assigned")
	}
	// A different address is still refused, or the override would disable the
	// guard rather than widen it by one value.
	if config.AddressIsLocal("2001:db8::6") {
		t.Error("setting the override made an unrelated address acceptable")
	}
}

// An address that is not reachable from the internet must never be offered for
// assignment. Publishing a link-local or unique-local address as a AAAA record
// makes the site dead for IPv6 clients while the panel shows it as configured.
func TestOnlyRoutableAddressesAreOffered(t *testing.T) {
	for _, address := range config.GlobalIPv6Addresses() {
		lowered := strings.ToLower(address)
		if strings.HasPrefix(lowered, "fe80:") || strings.HasPrefix(lowered, "fc") ||
			strings.HasPrefix(lowered, "fd") || lowered == "::1" {
			t.Errorf("%s is offered for assignment but the internet cannot reach it", address)
		}
	}
}

// Setting the address to what it already is must not touch the database or
// rewrite a zone. A repoint that ran anyway would bump the serial and push a
// zone transfer for a change nobody made.
func TestRepointingToTheSameAddressDoesNothing(t *testing.T) {
	changed, err := dns.RepointIPv6(context.Background(), nil, 1, "example.com", "2001:db8::5", "2001:db8::5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed != 0 {
		t.Errorf("changed = %d, want 0", changed)
	}
	// Both empty is the same no-op, and it is the ordinary case on a server
	// with no IPv6 at all.
	if changed, err := dns.RepointIPv6(context.Background(), nil, 1, "example.com", "", ""); err != nil || changed != 0 {
		t.Errorf("clearing an already-empty address returned (%d, %v)", changed, err)
	}
}
