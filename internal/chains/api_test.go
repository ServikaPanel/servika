package chains

import (
	"strings"
	"testing"
)

// A client can inject X-Forwarded-For, so the IP is validated before it reaches
// the operator; an invalid one reads as "unknown".
func TestSafeIP(t *testing.T) {
	if got := safeIP("203.0.113.7"); got != "203.0.113.7" {
		t.Fatalf("a valid IP was rejected: %q", got)
	}
	if got := safeIP("2001:db8::1"); got != "2001:db8::1" {
		t.Fatalf("a valid IPv6 was rejected: %q", got)
	}
	for _, bad := range []string{"", "not-an-ip", "1.2.3", "<script>"} {
		if got := safeIP(bad); got != "unknown" {
			t.Fatalf("safeIP(%q) = %q, want unknown", bad, got)
		}
	}
}

func TestEntrySummary(t *testing.T) {
	one := entrySummary(loginBurst{fails: 7, ip: "203.0.113.7", distinct: 1})
	if !strings.Contains(one, "7 failed logins") || !strings.Contains(one, "203.0.113.7") || strings.Contains(one, "more IPs") {
		t.Fatalf("single-IP summary = %q", one)
	}
	many := entrySummary(loginBurst{fails: 20, ip: "203.0.113.7", distinct: 4})
	if !strings.Contains(many, "+3 more IPs") {
		t.Fatalf("distributed summary should name the extra IPs: %q", many)
	}
	bad := entrySummary(loginBurst{fails: 5, ip: "garbage", distinct: 1})
	if !strings.Contains(bad, "unknown") {
		t.Fatalf("an invalid IP should read as unknown: %q", bad)
	}
}
