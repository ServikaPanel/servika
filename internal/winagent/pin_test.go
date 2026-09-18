package winagent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveAgent starts a TLS server running handler and returns its address plus
// the SHA-256 of the certificate it serves. That digest is exactly what the
// panel pins, so a test can pin to it or deliberately not.
func serveAgent(t *testing.T, handler http.HandlerFunc) (address, fingerprint string) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return strings.TrimPrefix(srv.URL, "https://"), hex.EncodeToString(sum[:])
}

// fakeAgent answers body with status on every path.
func fakeAgent(t *testing.T, status int, body string) (address, fingerprint string) {
	t.Helper()
	return serveAgent(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

const healthyBody = `{"platform":"windows","version":"1.2.3","channel":"stable","capabilities":7,"env_error":""}`

func TestAnAddressMustCarryAHostAndAPort(t *testing.T) {
	for _, address := range []string{"", "127.0.0.1", ":8443", "127.0.0.1:"} {
		if err := validAddress(address); err == nil {
			t.Fatalf("address %q was accepted without a host and a port", address)
		}
	}
}

func TestAHostnameIsRefusedBecauseItCanResolveElsewhere(t *testing.T) {
	err := validAddress("agent.example.com:8443")
	if err == nil {
		t.Fatal("a hostname was accepted; DNS can move it to a public address after the check")
	}
	if !strings.Contains(err.Error(), "literal IP") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

func TestALoopbackOrPrivateAddressIsAccepted(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8443", "10.0.0.5:8443", "192.168.1.9:8443", "172.16.0.1:8443"} {
		if err := validAddress(address); err != nil {
			t.Fatalf("address %q was refused: %v", address, err)
		}
	}
}

func TestAPublicAddressIsRefusedUnlessTheOperatorOpensIt(t *testing.T) {
	if err := validAddress("203.0.113.10:8443"); err == nil {
		t.Fatal("a public address was accepted with the gate closed")
	}
	t.Setenv(allowPublicEnv, "1")
	if err := validAddress("203.0.113.10:8443"); err != nil {
		t.Fatalf("the gate did not open with %s=1: %v", allowPublicEnv, err)
	}
}

func TestTheGateOnlyOpensForTheExactValueOne(t *testing.T) {
	t.Setenv(allowPublicEnv, "true")
	if err := validAddress("203.0.113.10:8443"); err == nil {
		t.Fatal(`a value other than "1" opened the gate`)
	}
}

func TestTheFingerprintIsTheDigestOfTheServedCertificate(t *testing.T) {
	address, want := fakeAgent(t, http.StatusOK, healthyBody)
	got, err := readFingerprint(address)
	if err != nil {
		t.Fatalf("could not read the fingerprint: %v", err)
	}
	if got != want {
		t.Fatalf("fingerprint %q does not match the served certificate %q", got, want)
	}
}

func TestAProbeSucceedsWhenThePinMatches(t *testing.T) {
	address, fingerprint := fakeAgent(t, http.StatusOK, healthyBody)
	h, err := probe(address, "s3cret", fingerprint)
	if err != nil {
		t.Fatalf("the probe failed against a matching pin: %v", err)
	}
	if h.Version != "1.2.3" || h.Capabilities != 7 {
		t.Fatalf("the health answer was not read: %+v", h)
	}
}

func TestTheTokenTravelsInTheHeader(t *testing.T) {
	var seen string
	address, fingerprint := serveAgent(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get(tokenHeader)
		_, _ = w.Write([]byte(healthyBody))
	})
	if _, err := probe(address, "s3cret", fingerprint); err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	if seen != "s3cret" {
		t.Fatalf("the agent saw token %q, want %q", seen, "s3cret")
	}
}

func TestAWrongPinStopsTheCallBeforeTheTokenIsSent(t *testing.T) {
	var seen bool
	address, fingerprint := serveAgent(t, func(w http.ResponseWriter, _ *http.Request) {
		seen = true
		_, _ = w.Write([]byte(healthyBody))
	})
	wrong := strings.Repeat("0", len(fingerprint))
	_, err := probe(address, "s3cret", wrong)
	if err == nil {
		t.Fatal("a call with the wrong pin succeeded")
	}
	if !errors.Is(err, ErrFingerprint) {
		t.Fatalf("the failure is not reported as a pin mismatch: %v", err)
	}
	if seen {
		t.Fatal("the request reached the agent; the pin must break the handshake before the token is written")
	}
}

func TestARejectedTokenIsReportedAsSuch(t *testing.T) {
	address, fingerprint := fakeAgent(t, http.StatusUnauthorized, `{}`)
	_, err := probe(address, "wrong", fingerprint)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a 401 was not reported as a rejected token: %v", err)
	}
}

func TestANonWindowsAgentIsRefused(t *testing.T) {
	address, fingerprint := fakeAgent(t, http.StatusOK, `{"platform":"linux","version":"1.0.0"}`)
	_, err := probe(address, "s3cret", fingerprint)
	if err == nil || !strings.Contains(err.Error(), "windows") {
		t.Fatalf("a non-windows agent was accepted: %v", err)
	}
}

func TestAPinMismatchIsRecognisedThroughTheClientWrappers(t *testing.T) {
	if !isFingerprintError(errors.New(`Get "https://x": tls: ` + ErrFingerprint.Error())) {
		t.Fatal("a wrapped pin mismatch was not recognised")
	}
	if isFingerprintError(errors.New("connection refused")) {
		t.Fatal("an unrelated error was read as a pin mismatch")
	}
}

func TestTheShownFingerprintIsAPrefix(t *testing.T) {
	full := strings.Repeat("ab", 32)
	if got := shortFingerprint(full); got != full[:16] {
		t.Fatalf("shortFingerprint returned %q", got)
	}
	if got := shortFingerprint("abc"); got != "abc" {
		t.Fatalf("a short value was truncated: %q", got)
	}
}

func TestOnlyDigitsPassTheCountCheck(t *testing.T) {
	for _, value := range []string{"", "50a", "-1", " 5", "1 2"} {
		if digitsOnly(value) {
			t.Fatalf("%q passed the count check", value)
		}
	}
	if !digitsOnly("250") {
		t.Fatal("a plain number failed the count check")
	}
}
