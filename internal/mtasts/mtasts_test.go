package mtasts

import (
	"strings"
	"testing"
)

// RFC 8461 section 3.2 requires CRLF. A sender that parses strictly rejects a
// policy with bare newlines, which reads to it as no policy at all.
func TestThePolicyUsesCRLFLineEndings(t *testing.T) {
	body, err := PolicyFile(ModeTesting, []string{"mail.example.com"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, line := range strings.SplitAfter(body, "\r\n") {
		if line == "" {
			continue
		}
		if !strings.HasSuffix(line, "\r\n") {
			t.Fatalf("a line does not end with CRLF: %q", line)
		}
		if strings.Count(line, "\n") != 1 {
			t.Fatalf("a bare newline is present: %q", line)
		}
	}
}

// Testing publishes the short max_age so a mistake ages out of sender caches in
// a day; enforce publishes the week RFC 8461 asks for.
func TestTheMaxAgeMatchesTheMode(t *testing.T) {
	testing_, err := PolicyFile(ModeTesting, []string{"mail.example.com"})
	if err != nil {
		t.Fatalf("render testing: %v", err)
	}
	if !strings.Contains(testing_, "max_age: 86400\r\n") {
		t.Errorf("testing does not publish the one-day max_age:\n%s", testing_)
	}
	enforce, err := PolicyFile(ModeEnforce, []string{"mail.example.com"})
	if err != nil {
		t.Fatalf("render enforce: %v", err)
	}
	if !strings.Contains(enforce, "max_age: 604800\r\n") {
		t.Errorf("enforce does not publish the one-week max_age:\n%s", enforce)
	}
}

// A policy with no mx line matches no server, so in enforce mode it rejects
// every message. Rendering it at all would be the mail loss this package exists
// to prevent.
func TestAnEnforceablePolicyWithoutAnMXHostIsRefused(t *testing.T) {
	for _, mode := range []Mode{ModeTesting, ModeEnforce} {
		if _, err := PolicyFile(mode, nil); err == nil {
			t.Errorf("%s rendered a policy that names no MX host", mode)
		}
	}
}

// Withdrawal is a publication, not a deletion. `mode: none` has to render even
// with no MX host, because by then the domain may have stopped hosting mail and
// the withdrawal is exactly what tells senders to drop the cached policy.
func TestWithdrawalRendersWithoutAnMXHost(t *testing.T) {
	body, err := PolicyFile(ModeWithdrawing, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(body, "mode: none\r\n") {
		t.Errorf("the withdrawal does not publish mode: none:\n%s", body)
	}
	if strings.Contains(body, "withdrawing") {
		t.Errorf("the internal state name leaked into the published policy:\n%s", body)
	}
}

// Nothing is served for a domain that has not published.
func TestNoPolicyIsRenderedWhenNoneIsPublished(t *testing.T) {
	for _, mode := range []Mode{ModeOff, ModePendingDNS, ModePendingCert} {
		if _, err := PolicyFile(mode, []string{"mail.example.com"}); err == nil {
			t.Errorf("%s rendered a policy", mode)
		}
	}
}

// The intermediate states are reached by the panel, never chosen by an operator.
// Accepting one over the API would publish a policy the sequence has not proved.
func TestOnlyTestingAndEnforceMayBeSelected(t *testing.T) {
	for _, value := range []string{"testing", "enforce"} {
		if !ValidMode(value) {
			t.Errorf("%s was refused", value)
		}
	}
	for _, value := range []string{"", "off", "none", "pending_dns", "pending_cert", "withdrawing", "ENFORCE", "x"} {
		if ValidMode(value) {
			t.Errorf("%q was accepted as a selectable mode", value)
		}
	}
}

// Only the exact policy host maps to a domain. Answering for any other name
// would serve one domain's policy under another domain's identity.
func TestOnlyTheExactPolicyHostResolvesToADomain(t *testing.T) {
	cases := map[string]string{
		"mta-sts.example.com":      "example.com",
		"MTA-STS.Example.Com":      "example.com",
		"mta-sts.example.com:443":  "example.com",
		"mta-sts.example.com.":     "example.com",
		"mta-sts.mail.example.com": "mail.example.com",

		"example.com":              "",
		"www.mta-sts.example.com":  "",
		"mta-sts.":                 "",
		"mta-sts.com":              "",
		"autoconfig.example.com":   "",
		"mta-sts.exam ple.com":     "",
		"mta-sts.example.com/evil": "",
		"":                         "",
	}
	for host, want := range cases {
		if got := policyHostDomain(host); got != want {
			t.Errorf("policyHostDomain(%q) = %q, want %q", host, got, want)
		}
	}
}

// The TXT records are what senders actually read; a shape change silently
// un-publishes the policy.
func TestTheTXTRecordsHaveTheRequiredShape(t *testing.T) {
	if got := PolicyTXT("abc123"); got != "v=STSv1; id=abc123" {
		t.Errorf("policy TXT = %q", got)
	}
	if got := ReportTXT("postmaster@example.com"); got != "v=TLSRPTv1; rua=mailto:postmaster@example.com" {
		t.Errorf("report TXT = %q", got)
	}
}

// A fresh id per change is what makes a sender refetch instead of keeping the
// cached policy (K4).
func TestEachPolicyIDIsDistinct(t *testing.T) {
	seen := make(map[string]bool, 32)
	for range 32 {
		id, err := newPolicyID()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if id == "" {
			t.Fatal("an empty id was generated")
		}
		if seen[id] {
			t.Fatalf("the id %q was generated twice", id)
		}
		seen[id] = true
	}
}
