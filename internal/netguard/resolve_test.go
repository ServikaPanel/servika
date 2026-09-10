package netguard

import (
	"errors"
	"strings"
	"testing"
)

// CheckHost validates a name and hands the bare name back, which is enough for
// an in-process client whose dialer also carries DialControl. It is not enough
// for an external tool: that tool resolves the name a SECOND time, and a
// low-TTL record under the caller's control can answer with a public address
// for the check and an internal one for the connection.
func TestResolveAllowedReturnsAVettedLiteralUnchanged(t *testing.T) {
	for _, host := range []string{"203.0.113.5", "[2001:db8::1]", "2001:db8::1"} {
		address, err := ResolveAllowed(host)
		if err != nil {
			t.Fatalf("ResolveAllowed(%q) = %v, want the address", host, err)
		}
		// Bare, never bracketed: ssh takes an IPv6 address without brackets and a
		// URL authority takes it with them, so the caller adds them.
		if strings.ContainsAny(address, "[]") {
			t.Errorf("ResolveAllowed(%q) = %q, want a bare address", host, address)
		}
	}
}

func TestResolveAllowedRefusesAnInternalLiteral(t *testing.T) {
	for _, host := range []string{
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.1",
		"169.254.169.254", // the cloud metadata address
		"0.0.0.0",
		"[::1]",
		"[fd00:ec2::254]",
	} {
		if _, err := ResolveAllowed(host); !errors.Is(err, ErrBlockedTarget) {
			t.Errorf("ResolveAllowed(%q) = %v, want ErrBlockedTarget", host, err)
		}
	}
}

func TestResolveAllowedRefusesAnEmptyHost(t *testing.T) {
	if _, err := ResolveAllowed("   "); err == nil {
		t.Error("ResolveAllowed(\"\") = nil, want a refusal")
	}
}

// The opt-out disables every check in this package, and an operator who set it
// is hosting the destination on a private network: the NAME has to survive, or
// the connection goes nowhere.
func TestResolveAllowedHandsBackTheHostWhenPrivateTargetsAreAllowed(t *testing.T) {
	t.Setenv("SERVIKA_ALLOW_PRIVATE_TARGETS", "1")

	for _, host := range []string{"backup.internal", "10.0.0.1"} {
		address, err := ResolveAllowed(host)
		if err != nil {
			t.Fatalf("ResolveAllowed(%q) = %v with the opt-out on", host, err)
		}
		if address != host {
			t.Errorf("ResolveAllowed(%q) = %q, want the host unchanged", host, address)
		}
	}
}

// A name that resolves to nothing usable must refuse rather than hand back the
// name, which would put the caller straight back on the second-resolution path.
func TestResolveAllowedRefusesAnUnresolvableName(t *testing.T) {
	address, err := ResolveAllowed("host.invalid")
	if err == nil {
		t.Fatalf("ResolveAllowed() = %q, want a refusal for an unresolvable name", address)
	}
	if address != "" {
		t.Errorf("ResolveAllowed() returned %q alongside an error", address)
	}
}
