package provisioner

import (
	"os"
	"path/filepath"
	"testing"
)

// mailChainIsStale is what decides whether a certificate was renewed, so it is
// tested on its own: it needs no root, unlike writeMailChain, which chowns the
// file it produces.

// acme.sh renews a mail certificate by rewriting mail.crt and mail.key. It knows
// nothing about mail-chain.pem, which this package assembles, so a chain built
// from the previous certificate must be reported as stale. Postmap -F embeds the
// chain's CONTENT into the SNI table, so a chain nobody rebuilds is a certificate
// Postfix keeps serving after it expired.
func TestARenewedCertificateMakesTheChainStale(t *testing.T) {
	certPath, keyPath, chainPath := mailFixture(t, "example.com", "first-cert")
	writeFixtureFile(t, chainPath, string(mailChainBytes([]byte("key\n"), []byte("first-cert\n"))))

	stale, err := mailChainIsStale(chainPath, certPath, keyPath)
	if err != nil {
		t.Fatalf("compare the current chain: %v", err)
	}
	if stale {
		t.Fatal("a chain matching its certificate was reported as stale")
	}

	writeFixtureFile(t, certPath, "renewed-cert\n")
	stale, err = mailChainIsStale(chainPath, certPath, keyPath)
	if err != nil {
		t.Fatalf("compare the renewed chain: %v", err)
	}
	if !stale {
		t.Fatal("a chain built from the previous certificate was not reported as stale")
	}
}

// A domain that has a certificate but no chain yet has never had one built.
func TestAMissingChainIsStale(t *testing.T) {
	certPath, keyPath, chainPath := mailFixture(t, "example.com", "cert")

	stale, err := mailChainIsStale(chainPath, certPath, keyPath)
	if err != nil {
		t.Fatalf("compare a missing chain: %v", err)
	}
	if !stale {
		t.Fatal("a missing chain was not reported as stale")
	}
}

// A domain with no mail certificate is not a mail domain. Reporting a change for
// it would reload the mail stack on a host that has never issued one.
func TestADomainWithoutAMailCertificateIsSkipped(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SERVIKA_CERT_ROOT", root)
	if err := os.MkdirAll(filepath.Join(root, "example.com"), 0o750); err != nil {
		t.Fatalf("create the domain directory: %v", err)
	}

	if RefreshMailChains() {
		t.Fatal("a domain with no mail certificate reported a change")
	}
	if _, err := os.Stat(filepath.Join(root, "example.com", mailChainFile)); !os.IsNotExist(err) {
		t.Fatalf("a chain was written for a domain with no certificate: %v", err)
	}
}

// The whole pass, end to end. writeMailChain chowns to root, so this can only be
// measured as root; the container run in CLAUDE.md is that environment.
func TestRefreshRewritesTheChainAndThenReportsNoChange(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("writeMailChain chowns the chain to root; run this as root")
	}
	certPath, _, chainPath := mailFixture(t, "example.com", "first-cert")

	if !RefreshMailChains() {
		t.Fatal("the first pass reported no change although no chain existed")
	}
	if got, want := readFixtureFile(t, chainPath), string(mailChainBytes([]byte("key\n"), []byte("first-cert\n"))); got != want {
		t.Fatalf("chain = %q, want %q", got, want)
	}
	if RefreshMailChains() {
		t.Fatal("a second pass over unchanged certificates reported a change")
	}

	writeFixtureFile(t, certPath, "renewed-cert\n")
	if !RefreshMailChains() {
		t.Fatal("a renewed certificate reported no change")
	}
	if got, want := readFixtureFile(t, chainPath), string(mailChainBytes([]byte("key\n"), []byte("renewed-cert\n"))); got != want {
		t.Fatalf("renewed chain = %q, want %q", got, want)
	}
}

// mailFixture puts a certificate and key for one domain under a temporary
// certificate root and returns their paths.
func mailFixture(t *testing.T, domain, cert string) (certPath, keyPath, chainPath string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("SERVIKA_CERT_ROOT", root)
	if err := os.MkdirAll(filepath.Join(root, domain), 0o750); err != nil {
		t.Fatalf("create the domain directory: %v", err)
	}
	certPath, keyPath, chainPath = MailCertificatePaths(domain)
	writeFixtureFile(t, certPath, cert+"\n")
	writeFixtureFile(t, keyPath, "key\n")
	return certPath, keyPath, chainPath
}

func writeFixtureFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFixtureFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}
