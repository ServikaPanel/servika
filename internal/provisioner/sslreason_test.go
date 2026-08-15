package provisioner

import (
	"strings"
	"testing"
)

// The reason has to reach the user. Without it the panel reports a certificate
// was installed while the browser reports the site is not secure, and nothing on
// screen connects the two.
func TestSummarizeSSLReasonPicksTheValidationFailure(t *testing.T) {
	// A real acme.sh transcript buries the cause under progress output.
	const transcript = `[Mon 04 Aug 2026 11:02:03 AM UTC] Using CA: https://acme-v02.api.letsencrypt.org/directory
[Mon 04 Aug 2026 11:02:03 AM UTC] Creating domain key
[Mon 04 Aug 2026 11:02:04 AM UTC] Verifying: www.example.com
[Mon 04 Aug 2026 11:02:06 AM UTC] www.example.com: Invalid status. DNS problem: NXDOMAIN looking up A for www.example.com
[Mon 04 Aug 2026 11:02:06 AM UTC] Please check log file for more details.`

	got := summarizeSSLReason(transcript)
	if !strings.Contains(got, "NXDOMAIN looking up A for www.example.com") {
		t.Errorf("summarizeSSLReason() = %q, which does not name the cause", got)
	}
	if strings.Contains(got, "Creating domain key") {
		t.Errorf("summarizeSSLReason() returned progress output: %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Errorf("summarizeSSLReason() returned several lines: %q", got)
	}
}

// A rate-limit refusal is the other cause a user must be able to act on, and it
// is worded differently from a validation failure.
func TestSummarizeSSLReasonPicksARateLimit(t *testing.T) {
	const transcript = `[Mon] Getting webroot for domain='example.com'
[Mon] Error creating new order :: too many certificates (5) already issued for this exact set of domains in the last 168 hours
[Mon] Please add '--debug' or '--log' to check more details.`

	if got := summarizeSSLReason(transcript); !strings.Contains(got, "too many certificates") {
		t.Errorf("summarizeSSLReason() = %q, which does not name the rate limit", got)
	}
}

// acme.sh output is unbounded, and this string ends up in an API response.
func TestSummarizeSSLReasonIsBounded(t *testing.T) {
	got := summarizeSSLReason("DNS problem: " + strings.Repeat("x", 5000))
	if len(got) > 320 {
		t.Errorf("summarizeSSLReason() returned %d characters; the transcript sizes the response", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("a truncated reason does not say it was truncated: %q", got)
	}
}

// Falling back with nothing to say is worse than saying the generic thing, but
// an empty transcript must not produce a stray blank warning either.
func TestSummarizeSSLReasonHandlesAnEmptyTranscript(t *testing.T) {
	for _, transcript := range []string{"", "\n\n   \n"} {
		if got := summarizeSSLReason(transcript); got != "" {
			t.Errorf("summarizeSSLReason(%q) = %q, want empty", transcript, got)
		}
	}
}

// An apex that does not resolve cannot pass http-01, and calling acme.sh anyway
// spends one of the five failed validations Let's Encrypt allows per hostname
// per hour. .invalid is reserved by RFC 2606 and must never resolve.
func TestDomainResolvesRefusesAReservedInvalidName(t *testing.T) {
	if domainResolves("this-host-does-not-exist.invalid") {
		t.Error("domainResolves() accepted a reserved .invalid name")
	}
}

// The screen gets a code, never the CA's English sentence.
//
// This is what lets the twelve interface languages say something useful about a
// failure. It also keeps raw acme.sh output off a customer's screen: the
// transcript still reaches the panel log, which is where an operator reads it.
func TestSSLFailureIsClassifiedIntoAStableCode(t *testing.T) {
	cases := []struct {
		name       string
		transcript string
		want       string
	}{
		{
			name:       "rate limit",
			transcript: "[Wed] Create new order error. Le_OrderFinalize not found. too many certificates already issued for exact set of domains",
			want:       sslReasonRateLimited,
		},
		{
			name:       "explicit rate limit wording",
			transcript: "Error creating new order :: too many failed authorizations recently: see https://letsencrypt.org/docs/rate-limits/",
			want:       sslReasonRateLimited,
		},
		{
			name:       "dns problem",
			transcript: "Detail: DNS problem: NXDOMAIN looking up A for example.com - check that a DNS record exists",
			want:       sslReasonDNSProblem,
		},
		{
			name:       "anything else",
			transcript: "Please add '--debug' or '--log' to check more details.",
			want:       sslReasonACMEFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifySSLFailure(tc.transcript)
			if got.Code != tc.want {
				t.Errorf("code = %q, want %q", got.Code, tc.want)
			}
			// The detail is the operator's half. Losing it would leave the log
			// with a code and no way to tell two orders apart.
			if got.Detail == "" {
				t.Error("the transcript detail was dropped")
			}
		})
	}
}

// A code is an identifier, not a sentence. Anything with a space in it would be
// looked up as a translation key and rendered raw by the fallback.
func TestSSLFailureCodesAreLookupKeys(t *testing.T) {
	for _, code := range []string{
		sslReasonDNSUnresolved, sslReasonRateLimited, sslReasonDNSProblem,
		sslReasonACMEFailed, sslReasonInstallFailed,
	} {
		if code == "" || strings.ContainsAny(code, " :\n") {
			t.Errorf("%q is not usable as a translation key", code)
		}
	}
}

// A dropped name is reported as a code the interface can translate, keyed by the
// host it belongs to, and the apex is never in that map: when the apex fails
// there is no certificate to report partial coverage for, only a failure.
//
// The apex is fed to the function here rather than left out of the fixture. A
// map the test itself wrote can only be missing a key the test never typed, so
// asserting on that proves nothing about what the panel does.
func TestSkippedNamesAreCodesKeyedByHost(t *testing.T) {
	const apex = "example.com"
	dropped := map[string]challengeReason{
		apex:                       reasonWrongStatus,
		"www.example.com":          reasonWebrootUnwrite,
		"autoconfig.example.com":   reasonUnreachable,
		"autodiscover.example.com": reasonWrongContent,
	}

	skipped := skippedSANNames(dropped, apex)

	if _, present := skipped[apex]; present {
		t.Error("the apex appears in the skipped map instead of as the failure reason")
	}
	if len(skipped) != len(dropped)-1 {
		t.Errorf("skipped holds %d names, want the %d that are not the apex", len(skipped), len(dropped)-1)
	}
	for host, code := range skipped {
		if code == "" || strings.ContainsAny(code, " :\n") {
			t.Errorf("%s carries %q, which is not usable as a translation key", host, code)
		}
		if code != string(dropped[host]) {
			t.Errorf("%s carries %q, want the probe's own code %q", host, code, dropped[host])
		}
	}
}
