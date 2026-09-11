package provisioner

import (
	"database/sql/driver"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestBuildSecurityHeadersProtectsPreviewViaCSP verifies clickjacking protection
// moved off X-Frame-Options onto an enforced CSP frame-ancestors directive, so the
// panel origin can iframe-preview the tenant site.
func TestBuildSecurityHeadersProtectsPreviewViaCSP(t *testing.T) {
	got := buildSecurityHeaders(VhostOpts{})
	if strings.Contains(got, "X-Frame-Options") {
		t.Error("security headers must not emit X-Frame-Options")
	}
	if !strings.Contains(got, `add_header Content-Security-Policy "frame-ancestors 'self'`) {
		t.Errorf("security headers must enforce frame-ancestors CSP, got:\n%s", got)
	}
}

// TestFramePolicyHeaderFoldsUpgrade confirms upgrade-insecure-requests is folded
// into the enforced frame policy only when HTTPS upgrade is requested.
func TestFramePolicyHeaderFoldsUpgrade(t *testing.T) {
	if strings.Contains(framePolicyHeader("    ", false), "upgrade-insecure-requests") {
		t.Error("frame policy must not upgrade when HTTPS upgrade is disabled")
	}
	if !strings.Contains(framePolicyHeader("    ", true), "upgrade-insecure-requests") {
		t.Error("frame policy must fold in upgrade-insecure-requests when requested")
	}
}

// TestPanelFrameAncestorsAlwaysAllowsSelf ensures the allowlist degrades safely to
// 'self' when no DB handle or public IP is configured.
func TestPanelFrameAncestorsAlwaysAllowsSelf(t *testing.T) {
	t.Setenv("SERVIKA_PUBLIC_IPV4", "")
	if got := panelFrameAncestors(); !strings.HasPrefix(got, "'self'") {
		t.Errorf("frame-ancestors allowlist must start with 'self', got %q", got)
	}
}

const (
	firstDomainIPv4Query = "COALESCE(ipv4,'')"
	panelDomainQuery     = "FROM panel_settings"
)

// The panel's own address comes from the environment first. The first domain's
// stored IPv4 is asked for only when the environment holds no IPv4 address, and
// only an IPv4 answer is used.
func TestTheFrameAllowlistNamesThePanelAddress(t *testing.T) {
	cases := []struct {
		name      string
		env       string
		script    *sqlScript
		want      string
		withoutDB bool
	}{
		{name: "from the environment", env: "203.0.113.10", withoutDB: true,
			want: "'self' https://203.0.113.10:8443"},
		{name: "from the first domain when the environment has none", env: "not-an-address",
			script: &sqlScript{rows: map[string][][]driver.Value{
				firstDomainIPv4Query: {{" 198.51.100.20 "}},
				panelDomainQuery:     {},
			}},
			want: "'self' https://198.51.100.20:8443"},
		{name: "a stored address that is not IPv4 is not used", env: "not-an-address",
			script: &sqlScript{rows: map[string][][]driver.Value{
				firstDomainIPv4Query: {{"2001:db8::1"}},
				panelDomainQuery:     {},
			}},
			want: "'self'"},
		{name: "an unreadable domain address is not used", env: "not-an-address",
			script: &sqlScript{
				fail: map[string]error{firstDomainIPv4Query: errors.New(lostConnectionTo)},
				rows: map[string][][]driver.Value{panelDomainQuery: {}},
			},
			want: "'self'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SERVIKA_PUBLIC_IPV4", tc.env)
			if tc.withoutDB {
				withoutDatabase(t)
			} else {
				withScript(t, tc.script)
			}
			if got := panelFrameAncestors(); got != tc.want {
				t.Errorf("panelFrameAncestors() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A custom panel domain is allowed to frame the preview only while its TLS is
// active and its name is a valid domain.
func TestTheFrameAllowlistNamesAnActivePanelDomain(t *testing.T) {
	cases := []struct {
		name, domain, status, want string
	}{
		{"active TLS", " Panel.Example.COM ", "active",
			"'self' https://panel.example.com https://panel.example.com:8443"},
		{"TLS not active", "panel.example.com", "pending", "'self'"},
		{"an invalid name", "bad name!", "active", "'self'"},
		{"no custom domain", "", "active", "'self'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SERVIKA_PUBLIC_IPV4", "not-an-address")
			withScript(t, &sqlScript{rows: map[string][][]driver.Value{
				firstDomainIPv4Query: {},
				panelDomainQuery:     {{tc.domain, tc.status}},
			}})
			if got := panelFrameAncestors(); got != tc.want {
				t.Errorf("panelFrameAncestors() = %q, want %q", got, tc.want)
			}
		})
	}
}

// object-src falls back to default-src, which is 'self', so without this a
// same-origin upload served back to the browser could still be embedded as a
// plugin object. Nothing the panel, phpMyAdmin or Roundcube serves needs one.
func TestPanelCSPForbidsPluginObjects(t *testing.T) {
	body, err := os.ReadFile("../../assets/nginx/_panel.conf")
	if err != nil {
		t.Fatalf("read the panel vhost: %v", err)
	}
	// The header name is matched with the space and quote that follow it.
	// Counting the bare prefix also counts Content-Security-Policy-Report-Only,
	// which is a different header with a different meaning: demanding the same
	// directives of it, or rewriting it, turns a policy that only reports into
	// one that enforces.
	policies := strings.Count(string(body), `add_header Content-Security-Policy "`)
	forbidden := strings.Count(string(body), "object-src 'none'")
	if policies == 0 {
		t.Fatal("the panel vhost declares no Content-Security-Policy")
	}
	if forbidden != policies {
		t.Errorf("%d of %d policies forbid plugin objects; every copy must", forbidden, policies)
	}
}

// The retrofit consumes its own anchor, so a second run has nothing to do. A
// repair that kept matching would rewrite and reload nginx on every boot.
func TestObjectSrcRetrofitIsIdempotent(t *testing.T) {
	const before = `add_header Content-Security-Policy "default-src 'self'; script-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'" always;`
	const anchor = "frame-ancestors 'self'; base-uri 'self'"
	const replacement = "frame-ancestors 'self'; object-src 'none'; base-uri 'self'"

	once := strings.ReplaceAll(before, anchor, replacement)
	if once == before {
		t.Fatal("the retrofit did not match a policy that lacks object-src")
	}
	if twice := strings.ReplaceAll(once, anchor, replacement); twice != once {
		t.Error("the retrofit matched again and would rewrite the vhost on every boot")
	}
}
