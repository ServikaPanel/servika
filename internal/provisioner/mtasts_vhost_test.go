package provisioner

import (
	"bytes"
	"strings"
	"testing"
)

// mtaSTSMarker is the location an MTA-STS policy is fetched from. RFC 8461
// fixes the path, so this is not a choice the panel gets to make.
const mtaSTSMarker = "location = /.well-known/mta-sts.txt"

// A certificate issued before MTA-STS existed names only the two
// auto-configuration hosts. If mta-sts. had been appended to the required set,
// every such certificate would fail discoveryEligible at once and the
// auto-configuration vhost would silently stop rendering, breaking working mail
// client setup on every domain that already had one.
func TestAnOlderCertificateStillGetsTheAutoConfigurationVhost(t *testing.T) {
	opts := discoveryOpts(t, "example.com", "autoconfig.example.com", "autodiscover.example.com")

	if !opts.discoveryEligible() {
		t.Fatal("a certificate naming both auto-configuration hosts was refused")
	}
	if opts.mtaSTSEligible() {
		t.Error("a certificate that does not name mta-sts. was treated as covering it")
	}

	var rendered bytes.Buffer
	if err := discoveryVhostTmpl.Execute(&rendered, opts); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := rendered.String()
	if !strings.Contains(body, autoconfigMarker) {
		t.Error("the auto-configuration path is no longer answered")
	}
	if strings.Contains(body, mtaSTSMarker) {
		t.Error("the MTA-STS path is served from a certificate that does not name its host")
	}
	if strings.Contains(body, "mta-sts.example.com") {
		t.Errorf("an uncovered host reached server_name:\n%s", body)
	}
}

// The two capabilities are independent. A domain whose apex points elsewhere
// may cover mta-sts. and not the auto-configuration names, and it still has to
// get its policy served.
func TestMTASTSIsServedWithoutTheAutoConfigurationNames(t *testing.T) {
	opts := discoveryOpts(t, "example.com", "mta-sts.example.com")

	if opts.discoveryEligible() {
		t.Error("a certificate without the auto-configuration hosts was treated as covering them")
	}
	if !opts.mtaSTSEligible() {
		t.Fatal("a certificate naming mta-sts. was refused")
	}

	var rendered bytes.Buffer
	if err := discoveryVhostTmpl.Execute(&rendered, opts); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := rendered.String()
	if !strings.Contains(body, "server_name mta-sts.example.com;") {
		t.Errorf("the vhost does not name the MTA-STS host:\n%s", body)
	}
	if !strings.Contains(body, mtaSTSMarker) {
		t.Error("the MTA-STS path is not answered")
	}
	if strings.Contains(body, autoconfigMarker) {
		t.Error("an auto-configuration path is served from a certificate that omits its host")
	}
}

// A certificate covering everything serves both, on one vhost.
func TestACertificateCoveringEverythingServesBoth(t *testing.T) {
	opts := discoveryOpts(t, "example.com",
		"autoconfig.example.com", "autodiscover.example.com", "mta-sts.example.com")

	var rendered bytes.Buffer
	if err := discoveryVhostTmpl.Execute(&rendered, opts); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := rendered.String()
	if !strings.Contains(body,
		"server_name autoconfig.example.com autodiscover.example.com mta-sts.example.com;") {
		t.Errorf("server_name does not carry all three hosts:\n%s", body)
	}
	if !strings.Contains(body, autoconfigMarker) || !strings.Contains(body, mtaSTSMarker) {
		t.Error("both blocks were expected")
	}
	// The site must still not answer on these names.
	if !strings.Contains(body, "location / { return 404; }") {
		t.Error("the vhost falls through to the site")
	}
}

// The rendered block is appended to a live vhost file, so a syntax error takes
// the whole host down at the next reload.
func TestTheMTASTSBlockIsValidNginxSyntax(t *testing.T) {
	opts := discoveryOpts(t, "example.com", "mta-sts.example.com")
	var rendered bytes.Buffer
	if err := discoveryVhostTmpl.Execute(&rendered, opts); err != nil {
		t.Fatalf("render: %v", err)
	}
	prefix := t.TempDir()
	body := "events {}\nhttp {\n" +
		strings.ReplaceAll(rendered.String(), "listen 443 ssl;", "listen 8443 ssl;") + "}\n"
	body = strings.ReplaceAll(body, "listen [::]:443 ssl;", "")
	body = strings.ReplaceAll(body, "/var/log/nginx/", prefix+"/")
	checkNginxSyntax(t, prefix, body, "the MTA-STS vhost is not valid nginx syntax")
}
