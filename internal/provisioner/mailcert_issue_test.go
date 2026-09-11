package provisioner

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// IssueMailCertificate orders a certificate for the mail hostnames that can
// answer the challenge, installs it beside the web certificate and writes the
// chain Postfix reads. These tests pin what is ordered, what is reported as
// skipped, and where each failure stops.

func TestAnInvalidMailDomainIsRefused(t *testing.T) {
	f := withIssuance(t, newACMEScript(t, "mail.example.com"))

	if _, err := IssueMailCertificate("bad name"); err == nil {
		t.Fatal("IssueMailCertificate() accepted an invalid domain")
	}
	if len(f.commands.argvs()) != 0 {
		t.Errorf("an invalid domain ran commands: %q", f.commands.argvs())
	}
}

// When no mail hostname can answer, nothing is ordered: a failed order spends
// the CA's per-hostname failure budget.
func TestNoMailHostnameAnsweringOrdersNothing(t *testing.T) {
	f := withIssuance(t, newACMEScript(t, "mail.example.com"))
	answerChallenges(t, MailHostNames("example.com")...)

	result, err := IssueMailCertificate("example.com")

	if err == nil || !strings.Contains(err.Error(), "could answer the ACME challenge") {
		t.Fatalf("IssueMailCertificate() error = %v, want the challenge refusal", err)
	}
	want := map[string]string{}
	for _, host := range MailHostNames("example.com") {
		want[host] = string(reasonWrongStatus)
	}
	if !reflect.DeepEqual(result.Skipped, want) {
		t.Errorf("skipped = %v, want %v", result.Skipped, want)
	}
	if f.commands.ranWith("--issue") {
		t.Error("an order was placed although no name could answer")
	}
}

func TestAMailCertificateIsIssuedForTheNamesThatAnswer(t *testing.T) {
	acme := newACMEScript(t, "mail.example.com", "imap.example.com")
	f := withIssuance(t, acme)
	answerChallenges(t, "smtp.example.com")

	result, err := IssueMailCertificate("example.com")

	if err != nil {
		t.Fatalf("IssueMailCertificate() error = %v", err)
	}
	if want := [][]string{{"mail.example.com", "imap.example.com"}}; !reflect.DeepEqual(acme.issuedFor, want) {
		t.Errorf("ordered for %v, want %v", acme.issuedFor, want)
	}
	assertMailFiles(t, result, filepath.Join(f.certRoot, "example.com"))
	if !slices.Equal(result.Hosts, []string{"mail.example.com", "imap.example.com"}) {
		t.Errorf("hosts = %v, want the names the installed certificate covers", result.Hosts)
	}
	if result.ExpiresAt == "" {
		t.Error("the expiry date was not read from the installed certificate")
	}
	if want := map[string]string{"smtp.example.com": string(reasonWrongStatus)}; !reflect.DeepEqual(result.Skipped, want) {
		t.Errorf("skipped = %v, want %v", result.Skipped, want)
	}
}

// assertMailFiles checks that the result names the three mail files under dir
// and that the chain Postfix reads is private.
func assertMailFiles(t *testing.T, result MailCertificate, dir string) {
	t.Helper()
	if result.CertPath != filepath.Join(dir, mailCertFile) || result.KeyPath != filepath.Join(dir, mailKeyFile) ||
		result.ChainPath != filepath.Join(dir, mailChainFile) {
		t.Errorf("paths = %q, %q, %q; want them under %s", result.CertPath, result.KeyPath, result.ChainPath, dir)
	}
	if info, err := os.Stat(result.ChainPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the chain file is missing or not 0600: %v, %v", info, err)
	}
}

// acme.sh exits 2 when it already holds a valid certificate for the names, which
// is not a failure: the stored certificate is installed.
func TestARenewSkipStillInstallsTheMailCertificate(t *testing.T) {
	acme := newACMEScript(t, "mail.example.com")
	acme.issue = func([]string) (string, int) { return "Skipping. Next renewal time is ...", 2 }
	withIssuance(t, acme)
	answerChallenges(t)

	if _, err := IssueMailCertificate("example.com"); err != nil {
		t.Fatalf("IssueMailCertificate() error = %v, want the stored certificate installed", err)
	}
	if len(acme.installedWith) != 1 {
		t.Errorf("install-cert ran %d times, want once", len(acme.installedWith))
	}
}

func TestAMailIssuanceThatFailsSaysWhere(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, acme *acmeScript)
		reason  string
	}{
		{"the certificate root cannot be created", func(t *testing.T, _ *acmeScript) {
			blocker := filepath.Join(t.TempDir(), "a-file")
			writeFixture(t, blocker, "not a directory")
			t.Setenv("SERVIKA_CERT_ROOT", filepath.Join(blocker, "certs"))
		}, "create certificate directory"},
		{"the order fails", func(_ *testing.T, acme *acmeScript) {
			acme.issue = func([]string) (string, int) { return "urn:ietf:params:acme:error:unauthorized", 1 }
		}, "acme issue for the mail hostnames: urn:ietf:params:acme:error:unauthorized"},
		{"install-cert fails", func(_ *testing.T, acme *acmeScript) {
			acme.installExit = 1
		}, "acme install-cert for the mail hostnames"},
		{"install-cert writes nothing", func(_ *testing.T, acme *acmeScript) {
			acme.installSkips = true
		}, "was not written"},
		{"the certificate cannot be handed to root", func(t *testing.T, _ *acmeScript) {
			chown = func(path string, _, _ int) error {
				if strings.HasSuffix(path, mailCertFile) {
					return errors.New("operation not permitted")
				}
				return nil
			}
		}, "set certificate ownership"},
		{"the chain cannot be handed to root", func(t *testing.T, _ *acmeScript) {
			chown = func(path string, _, _ int) error {
				if strings.HasSuffix(path, ".tmp") {
					return errors.New("operation not permitted")
				}
				return nil
			}
		}, "set the mail chain ownership"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			acme := newACMEScript(t, "mail.example.com")
			withIssuance(t, acme)
			answerChallenges(t)
			tc.prepare(t, acme)

			_, err := IssueMailCertificate("example.com")

			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("IssueMailCertificate() error = %v, want one naming %q", err, tc.reason)
			}
		})
	}
}
