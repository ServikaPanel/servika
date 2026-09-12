package subdomain

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The certificate is issued into a ROOT-OWNED staging directory and only then
// published beneath the tenant home, because openssl and acme.sh write BY PATH
// and the tenant owns ~/ssl. These cases pin what reaches the tenant home and
// what never does. They build against Linux, because the publish half goes
// through the safeio primitives.

// issuerWriting returns an issuer that writes the two files the caller staged.
func issuerWriting(t *testing.T, certificate, key string) func(string, string, string) error {
	t.Helper()
	return func(_, certPath, keyPath string) error {
		writeFileAt(t, certPath, certificate)
		writeFileAt(t, keyPath, key)
		return nil
	}
}

func TestTheIssuedPairIsPublishedBeneathTheTenantHome(t *testing.T) {
	home, _ := hostTree(t)
	if err := os.MkdirAll(filepath.Join(home, "c_acme"), 0o750); err != nil {
		t.Fatalf("create the tenant home: %v", err)
	}
	setForTest(t, &issueSelfSignedCertificate, issuerWriting(t, "the certificate", "the key"))

	if err := issueAndPublish("c_acme", "shop.acme.test", "self-signed"); err != nil {
		t.Fatalf("issueAndPublish: %v", err)
	}

	sslDir := filepath.Join(home, "c_acme", "ssl")
	certPath := filepath.Join(sslDir, "shop.acme.test.crt")
	keyPath := filepath.Join(sslDir, "shop.acme.test.key")
	if body := readFileAt(t, certPath); body != "the certificate" {
		t.Errorf("certificate = %q", body)
	}
	if body := readFileAt(t, keyPath); body != "the key" {
		t.Errorf("key = %q", body)
	}
	// The certificate is public; the key is not, and nginx reads it through the
	// tenant group.
	assertMode(t, certPath, 0o644)
	assertMode(t, keyPath, 0o640)
}

// The type chooses the tool, and only one of them runs.
func TestTheCertificateTypeChoosesTheTool(t *testing.T) {
	home, _ := hostTree(t)
	if err := os.MkdirAll(filepath.Join(home, "c_acme"), 0o750); err != nil {
		t.Fatalf("create the tenant home: %v", err)
	}
	selfSigned := false
	setForTest(t, &issueSelfSignedCertificate, func(fqdn, certPath, keyPath string) error {
		selfSigned = true
		return issuerWriting(t, "self", "self")(fqdn, certPath, keyPath)
	})
	setForTest(t, &issueLetsEncryptCertificate, issuerWriting(t, "trusted", "trusted key"))

	if err := issueAndPublish("c_acme", "shop.acme.test", "letsencrypt"); err != nil {
		t.Fatalf("issueAndPublish: %v", err)
	}
	if selfSigned {
		t.Error("the self-signed tool ran for a letsencrypt request")
	}
	body := readFileAt(t, filepath.Join(home, "c_acme", "ssl", "shop.acme.test.crt"))
	if body != "trusted" {
		t.Errorf("certificate = %q, want the one acme.sh issued", body)
	}
}

// Material the tool did not produce, produced empty, or produced far too much
// of is refused before anything reaches the tenant home.
func TestUnusableMaterialNeverReachesTheTenantHome(t *testing.T) {
	cases := []struct {
		name    string
		issuer  func(*testing.T) func(string, string, string) error
		message string
	}{
		{
			name: "a tool that failed",
			issuer: func(*testing.T) func(string, string, string) error {
				return func(string, string, string) error { return errors.New("openssl: exit status 1") }
			},
			message: "exit status 1",
		},
		{
			name: "a tool that wrote nothing",
			issuer: func(*testing.T) func(string, string, string) error {
				return func(string, string, string) error { return nil }
			},
			message: "read the staged certificate",
		},
		{
			name: "a tool that wrote only the certificate",
			issuer: func(t *testing.T) func(string, string, string) error {
				return func(_, certPath, _ string) error {
					writeFileAt(t, certPath, "the certificate")
					return nil
				}
			},
			message: "read the staged key",
		},
		{
			name: "an empty certificate",
			issuer: func(t *testing.T) func(string, string, string) error {
				return issuerWriting(t, "", "the key")
			},
			message: "not usable",
		},
		{
			name: "material far larger than a certificate",
			issuer: func(t *testing.T) func(string, string, string) error {
				return issuerWriting(t, strings.Repeat("x", certMaxBytes+1), "the key")
			},
			message: "not usable",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			home, _ := hostTree(t)
			if err := os.MkdirAll(filepath.Join(home, "c_acme"), 0o750); err != nil {
				t.Fatalf("create the tenant home: %v", err)
			}
			setForTest(t, &issueSelfSignedCertificate, testCase.issuer(t))

			err := issueAndPublish("c_acme", "shop.acme.test", "self-signed")
			if err == nil {
				t.Fatal("the material was published")
			}
			if !strings.Contains(err.Error(), testCase.message) {
				t.Errorf("error is %q, want it to carry %q", err, testCase.message)
			}
			if _, statErr := os.Stat(filepath.Join(home, "c_acme", "ssl")); !os.IsNotExist(statErr) {
				t.Errorf("the certificate directory was created anyway: %v", statErr)
			}
		})
	}
}

// A tenant home openat2 cannot resolve stops the publish, and the material
// stays in the staging directory it was issued into.
func TestACertificateDirectoryThatCannotBePreparedIsReported(t *testing.T) {
	hostTree(t)
	// No tenant home is created.
	setForTest(t, &issueSelfSignedCertificate, issuerWriting(t, "the certificate", "the key"))

	err := issueAndPublish("c_acme", "shop.acme.test", "self-signed")
	if err == nil {
		t.Fatal("the certificate was published with no home to publish it into")
	}
	if !strings.Contains(err.Error(), "prepare the certificate directory") {
		t.Errorf("error is %q", err)
	}
}

// Either half of the pair failing to install is reported: a certificate
// without its key, or a key without its certificate, is not a certificate the
// site can be served with.
func TestAHalfInstalledPairIsReported(t *testing.T) {
	cases := []struct {
		name    string
		blocked string
		message string
	}{
		{name: "the certificate", blocked: "shop.acme.test.crt", message: "install the certificate"},
		{name: "the key", blocked: "shop.acme.test.key", message: "install the key"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			home, _ := hostTree(t)
			// A DIRECTORY where the file must go, so the write refuses.
			if err := os.MkdirAll(filepath.Join(home, "c_acme", "ssl", testCase.blocked), 0o750); err != nil {
				t.Fatalf("block the target: %v", err)
			}
			setForTest(t, &issueSelfSignedCertificate, issuerWriting(t, "the certificate", "the key"))

			err := issueAndPublish("c_acme", "shop.acme.test", "self-signed")
			if err == nil {
				t.Fatal("a half-installed pair was reported as issued")
			}
			if !strings.Contains(err.Error(), testCase.message) {
				t.Errorf("error is %q, want it to carry %q", err, testCase.message)
			}
		})
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode().Perm() != want {
		t.Errorf("%s is %o, want %o", path, info.Mode().Perm(), want)
	}
}
