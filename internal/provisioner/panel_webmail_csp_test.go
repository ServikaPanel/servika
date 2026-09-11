package provisioner

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The webmail location exists TWICE: in the shipped panel vhost, and as a
// generator inside servika-mail-setup that deletes whatever block the file
// carries and emits its own. The installer runs that script after installing
// the vhost, and both the updater and the restore tool run it again, so the
// generated block is what an installation actually serves.
//
// It had drifted. The generated `.php` location carried no add_header at all,
// and nginx inherits add_header from the enclosing level ONLY when the current
// level declares none, so Roundcube was served under the SPA's strict
// script-src 'self'. Roundcube emits its bootstrap environment as inline
// script, so the interface did not initialise. Measured against nginx: an inner
// location with no add_header answered the server-level policy, and the same
// location with its own add_header answered the relaxed one.
//
// Nothing else holds the two copies in step: no heal repairs the webmail block.
func TestTheGeneratedWebmailBlockServesTheRelaxedPolicy(t *testing.T) {
	generated := webmailPHPLocation(t, readPanelSource(t, "../../assets/ops/servika-mail-setup"))
	for _, header := range []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Content-Security-Policy",
		"Strict-Transport-Security",
	} {
		if !strings.Contains(generated, header) {
			t.Errorf("the generated webmail PHP location does not set %s, so it inherits the SPA policy", header)
		}
	}
	if !strings.Contains(generated, "'unsafe-inline' 'unsafe-eval'") {
		t.Error("the generated webmail PHP location does not carry the relaxed script-src Roundcube needs")
	}
}

// And the two copies must agree, or the block an installation serves differs
// from the block the repository ships and only one of them is ever reviewed.
func TestTheGeneratedAndShippedWebmailPoliciesAgree(t *testing.T) {
	generated := policyOf(t, webmailPHPLocation(t, readPanelSource(t, "../../assets/ops/servika-mail-setup")))
	shipped := policyOf(t, webmailPHPLocation(t, readPanelSource(t, "../../assets/nginx/_panel.conf")))
	if generated != shipped {
		t.Errorf("the webmail policy has drifted between the generator and the vhost\ngenerated: %s\nshipped:   %s",
			generated, shipped)
	}
}

func readPanelSource(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- a repository asset.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

// webmailPHPLocation returns the text of the `^/webmail/(.+\.php)$` location,
// from either the vhost or the awk generator that prints it line by line.
func webmailPHPLocation(t *testing.T, body string) string {
	t.Helper()
	const marker = `^/webmail/(.+\.php)$`
	at := strings.Index(body, marker)
	if at < 0 {
		// The generator escapes the dot for awk's own string literal.
		at = strings.Index(body, `^/webmail/(.+\\.php)$`)
	}
	if at < 0 {
		t.Fatal("the webmail PHP location is gone; this test is out of date")
	}
	rest := unshell(body[at:])
	// The static-asset location is the next one, and it is where this block ends
	// in both files.
	if end := strings.Index(rest, "(jpg|jpeg"); end > 0 {
		rest = rest[:end]
	}
	return rest
}

// unshell undoes the two layers of escaping the generator needs and the vhost
// does not: `'"'"'` is how a single quote is spliced into a single-quoted shell
// string, and `\"` is how a double quote is written inside an awk string
// literal. After this the two sources are directly comparable.
func unshell(body string) string {
	body = strings.ReplaceAll(body, `'"'"'`, "'")
	return strings.ReplaceAll(body, `\"`, `"`)
}

var policyPattern = regexp.MustCompile(`Content-Security-Policy "([^"]+)"`)

// policyOf extracts the policy text from a location block.
func policyOf(t *testing.T, location string) string {
	t.Helper()
	match := policyPattern.FindStringSubmatch(location)
	if match == nil {
		t.Fatalf("no Content-Security-Policy in:\n%s", location)
	}
	return strings.TrimSpace(match[1])
}
