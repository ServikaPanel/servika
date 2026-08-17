package provisioner

import (
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
