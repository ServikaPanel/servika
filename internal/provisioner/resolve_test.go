package provisioner

import (
	"errors"
	"testing"
	"time"
)

// stubResolver installs a resolver the test drives, and removes the retry delay
// so a failing case does not spend seconds sleeping.
func stubResolver(t *testing.T, answer func(host string) ([]string, error)) {
	t.Helper()
	previousResolver, previousDelay := resolveHost, resolveRetryDelay
	resolveHost = answer
	resolveRetryDelay = 0
	t.Cleanup(func() {
		resolveHost = previousResolver
		resolveRetryDelay = previousDelay
	})
}

// The case this exists for: the name is configured correctly, one lookup fails,
// and without a retry www silently drops out of the certificate.
func TestLookupRetriesUntilTheResolverAnswers(t *testing.T) {
	calls := 0
	stubResolver(t, func(string) ([]string, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("server misbehaving")
		}
		return []string{"203.0.113.10"}, nil
	})

	got := lookupHostRetrying("example.com")
	if len(got) != 1 || got[0] != "203.0.113.10" {
		t.Fatalf("addresses = %v, want the address the third attempt returned", got)
	}
	if calls != 3 {
		t.Errorf("resolver called %d times, want 3", calls)
	}
}

// A resolver that stays down is still a "no": the caller must not be handed an
// empty answer that reads as success.
func TestLookupGivesUpAfterTheAttempts(t *testing.T) {
	calls := 0
	stubResolver(t, func(string) ([]string, error) {
		calls++
		return nil, errors.New("server misbehaving")
	})

	if got := lookupHostRetrying("example.com"); got != nil {
		t.Fatalf("addresses = %v, want nil", got)
	}
	if calls != resolveAttempts {
		t.Errorf("resolver called %d times, want %d", calls, resolveAttempts)
	}
}

// An answer is not retried, however unwelcome it is. www pointing at another
// server is a fact about the configuration, and asking again only delays the
// decision.
func TestWWWPointingElsewhereIsNotRetried(t *testing.T) {
	calls := 0
	stubResolver(t, func(host string) ([]string, error) {
		calls++
		if host == "example.com" {
			return []string{"203.0.113.10"}, nil
		}
		return []string{"198.51.100.7"}, nil
	})

	if wwwSANEligible("example.com") {
		t.Error("www resolving to a different server was accepted into the SAN")
	}
	if calls != 2 {
		t.Errorf("resolver called %d times, want 2 (one answer each)", calls)
	}
}

// The retry must not turn a name that genuinely does not exist into an eligible
// one, and matching addresses must still pass.
func TestWWWEligibilityStillFollowsTheAddresses(t *testing.T) {
	stubResolver(t, func(host string) ([]string, error) {
		if host == "example.com" {
			return []string{"203.0.113.10"}, nil
		}
		return nil, errors.New("no such host")
	})
	if wwwSANEligible("example.com") {
		t.Error("www that never resolves was accepted into the SAN")
	}

	stubResolver(t, func(string) ([]string, error) { return []string{"203.0.113.10"}, nil })
	if !wwwSANEligible("example.com") {
		t.Error("www sharing the apex address was refused")
	}
}

// A failing resolver must not make issuance wait on the request path longer than
// the retries themselves.
func TestLookupRetryDelayIsBounded(t *testing.T) {
	if resolveRetryDelay*time.Duration(resolveAttempts-1) > 5*time.Second {
		t.Errorf("retries can block for %v, which is too long on a request path",
			resolveRetryDelay*time.Duration(resolveAttempts-1))
	}
}

// The discovery names ride the same DNS gate as www.
//
// This is the property that keeps issuance stable: certSANHosts produces both
// the set that is ORDERED and the set a stored certificate must cover before it
// is reused, so a name that goes in unconditionally would make every reuse check
// fail and turn each attempt into a fresh order.
func TestDiscoveryNamesJoinTheSANOnlyWhenTheyPointHere(t *testing.T) {
	const apexAddress = "203.0.113.10"
	cases := []struct {
		name    string
		answer  func(host string) ([]string, error)
		want    []string
		wantNot []string
	}{
		{
			name: "all names point at the apex",
			answer: func(string) ([]string, error) {
				return []string{apexAddress}, nil
			},
			want: []string{
				"example.com", "www.example.com",
				"autoconfig.example.com", "autodiscover.example.com",
				"mta-sts.example.com",
			},
		},
		{
			// The real-world shape for a domain that has NOT enabled MTA-STS:
			// mta-sts.<domain> has no A record until the panel writes one, so
			// the SAN set has to come back byte for byte what it always was.
			// Otherwise every stored certificate fails the reuse check in
			// ssl_heal.bestCertificate at once and each attempt orders a fresh
			// one, against Let's Encrypt's weekly per-registered-domain limit.
			name: "MTA-STS has not been enabled",
			answer: func(host string) ([]string, error) {
				if host == "mta-sts.example.com" {
					return nil, errors.New("no such host")
				}
				return []string{apexAddress}, nil
			},
			want: []string{
				"example.com", "www.example.com",
				"autoconfig.example.com", "autodiscover.example.com",
			},
			wantNot: []string{"mta-sts.example.com"},
		},
		{
			name: "discovery names do not exist",
			answer: func(host string) ([]string, error) {
				if host == "example.com" || host == "www.example.com" {
					return []string{apexAddress}, nil
				}
				return nil, errors.New("no such host")
			},
			want:    []string{"example.com", "www.example.com"},
			wantNot: []string{"autoconfig.example.com", "autodiscover.example.com", "mta-sts.example.com"},
		},
		{
			name: "a discovery name points at another server",
			answer: func(host string) ([]string, error) {
				if host == "autodiscover.example.com" {
					return []string{"198.51.100.7"}, nil
				}
				return []string{apexAddress}, nil
			},
			want: []string{"example.com", "www.example.com",
				"autoconfig.example.com", "mta-sts.example.com"},
			wantNot: []string{"autodiscover.example.com"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubResolver(t, tc.answer)
			got := certSANHosts("example.com")
			if len(got) != len(tc.want) {
				t.Fatalf("SAN = %v, want %v", got, tc.want)
			}
			for i, host := range tc.want {
				if got[i] != host {
					t.Fatalf("SAN = %v, want %v", got, tc.want)
				}
			}
			for _, host := range tc.wantNot {
				for _, present := range got {
					if present == host {
						t.Errorf("%s was accepted into the SAN", host)
					}
				}
			}
		})
	}
}

// The apex is resolved once per call, not once per candidate name.
//
// certSANHosts runs for every SSL domain in the startup heal, and each lookup
// retries, so re-resolving the apex three times multiplies that walk by the
// resolver's worst case.
func TestCertSANHostsResolvesTheApexOnce(t *testing.T) {
	apexLookups := 0
	stubResolver(t, func(host string) ([]string, error) {
		if host == "example.com" {
			apexLookups++
		}
		return []string{"203.0.113.10"}, nil
	})

	certSANHosts("example.com")
	if apexLookups != 1 {
		t.Errorf("apex resolved %d times, want 1", apexLookups)
	}
}

// A www host has no www, autoconfig or autodiscover of its own to add.
func TestCertSANHostsLeavesAWWWHostAlone(t *testing.T) {
	stubResolver(t, func(string) ([]string, error) { return []string{"203.0.113.10"}, nil })
	got := certSANHosts("www.example.com")
	if len(got) != 1 || got[0] != "www.example.com" {
		t.Errorf("SAN = %v, want [www.example.com]", got)
	}
}
