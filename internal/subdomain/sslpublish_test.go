package subdomain

import (
	"os"
	"strings"
	"testing"
)

// ~/ssl is created inside the tenant home and chowned to the tenant, so the
// tenant can replace it with a symlink or plant <fqdn>.key and <fqdn>.crt inside
// it as links. openssl and acme.sh write BY PATH and dereference every
// component, and so did the os.MkdirAll and os.Chmod around them, so a link
// redirected a root-privileged write to any file on the host.
//
// The fix is the staging rule the rest of the tree already follows for an
// external tool that writes by path: issue into a root-owned temporary
// directory, then publish through the safeio primitives, which resolve every
// component beneath the home and refuse a symlink.
func TestTheCertificateIsIssuedIntoAStagingDirectory(t *testing.T) {
	publish := sslFunction(t, readSubdomainSource(t, "sslpublish.go"), "func issueAndPublish(")

	if !strings.Contains(publish, "os.MkdirTemp(") {
		t.Error("the certificate is not issued into a root-owned staging directory")
	}
	// The issuing tools must be handed the STAGED paths, never the tenant ones.
	for _, staged := range []string{"stagedCert", "stagedKey"} {
		if !strings.Contains(publish, "issueSelfSigned(fqdn, stagedCert, stagedKey)") ||
			!strings.Contains(publish, "issueLetsEncrypt(fqdn, stagedCert, stagedKey)") {
			t.Errorf("an issuing tool is not pointed at %s", staged)
		}
	}
	// And the staging directory is cleaned up, or a private key is left in /tmp.
	if !strings.Contains(publish, "os.RemoveAll(stage)") {
		t.Error("the staged private key is left behind")
	}
}

// The publish half must go through the beneath-primitives. A plain os.WriteFile
// to the same path would follow exactly the symlink this change closes.
func TestTheCertificateIsPublishedBeneathTheHome(t *testing.T) {
	publish := sslFunction(t, readSubdomainSource(t, "sslpublish.go"), "func issueAndPublish(")

	for _, call := range []string{
		"files.MkdirAllBeneath(home, sslRelDir, systemUser)",
		`files.WriteFileBeneath(home, sslRelPath(fqdn, ".crt")`,
		`files.WriteFileBeneath(home, sslRelPath(fqdn, ".key")`,
	} {
		if !strings.Contains(publish, call) {
			t.Errorf("the publish step does not use %s", call)
		}
	}
	for _, unsafe := range []string{"os.WriteFile(", "os.MkdirAll(", "os.Chmod("} {
		if strings.Contains(publish, unsafe) {
			t.Errorf("the publish step still writes by path with %s", unsafe)
		}
	}
	// The key is not world-readable: nginx reads it through the tenant group.
	if !strings.Contains(publish, "0o640, systemUser)") {
		t.Error("the private key is not published 0640")
	}
}

// The issue handler must not write to the tenant paths itself any more, or the
// staging helper is decorative.
func TestTheIssueHandlerWritesNothingByPath(t *testing.T) {
	issue := sslFunction(t, readSubdomainSource(t, "ssl.go"), "func (h *Handlers) SSLIssue(")

	for _, unsafe := range []string{"os.MkdirAll(", "os.Chmod(", `exec.Command("chown"`} {
		if strings.Contains(issue, unsafe) {
			t.Errorf("SSLIssue still reaches the tenant certificate directory by path with %s", unsafe)
		}
	}
	if !strings.Contains(issue, "issueAndPublish(systemUser, fqdn, certificateType)") {
		t.Error("SSLIssue does not go through the staging helper")
	}
}

// Removal followed an intermediate `ssl` symlink even though os.Remove does not
// follow one at the final component, so a tenant who made that a link had root
// delete files under whatever it pointed at.
func TestRemovalResolvesBeneathTheHome(t *testing.T) {
	remove := sslFunction(t, readSubdomainSource(t, "ssl.go"), "func (h *Handlers) SSLRemove(")

	if strings.Contains(remove, "os.Remove(") {
		t.Error("SSLRemove still deletes by path")
	}
	if !strings.Contains(remove, "files.RemoveAllBeneath(home,") {
		t.Error("SSLRemove does not resolve beneath the home")
	}
}

func readSubdomainSource(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name) // #nosec G304 -- a file of this package.
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}

// sslFunction returns one function's body, from its signature to the closing
// brace in the first column.
func sslFunction(t *testing.T, source, signature string) string {
	t.Helper()
	at := strings.Index(source, signature)
	if at < 0 {
		t.Fatalf("%q is not defined", signature)
	}
	body, _, found := strings.Cut(source[at:], "\n}\n")
	if !found {
		t.Fatalf("%q has no closing brace", signature)
	}
	return body
}
