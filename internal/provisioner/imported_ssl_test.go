package provisioner

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInstallImportedSSLRejectsWrongHostname(t *testing.T) {
	certPEM, keyPEM := testCertificate(t, "source.example", time.Now().Add(24*time.Hour))
	_, _, _, err := InstallImportedSSL("target.example", certPEM, keyPEM)
	if !errors.Is(err, ErrImportedSSLInvalid) {
		t.Fatalf("want ErrImportedSSLInvalid, got %v", err)
	}
}

func TestInstallImportedSSLRejectsExpiredCertificate(t *testing.T) {
	certPEM, keyPEM := testCertificate(t, "expired.example", time.Now().Add(-time.Hour))
	_, _, _, err := InstallImportedSSL("expired.example", certPEM, keyPEM)
	if !errors.Is(err, ErrImportedSSLInvalid) {
		t.Fatalf("want ErrImportedSSLInvalid, got %v", err)
	}
}

// Every refusal before the write names ErrImportedSSLInvalid, so a transfer
// reports an unusable source certificate rather than a server fault, and nothing
// is left under the certificate root.
func TestAnUnusableSourceCertificateIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SERVIKA_CERT_ROOT", root)
	now := time.Now()
	serverAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	validCert, validKey := certificateFor(t, "import.example", now.Add(-time.Hour), now.Add(24*time.Hour), serverAuth)
	futureCert, futureKey := certificateFor(t, "future.example", now.Add(time.Hour), now.Add(48*time.Hour), serverAuth)
	clientCert, clientKey := certificateFor(t, "client.example", now.Add(-time.Hour), now.Add(24*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	cases := []struct {
		name, domain, reason string
		cert, key            []byte
	}{
		{"an invalid domain name", "bad name", "invalid domain name format", validCert, validKey},
		{"a certificate that is not yet valid", "future.example", "not yet valid", futureCert, futureKey},
		{"a certificate only for client authentication", "client.example", "not valid for server authentication", clientCert, clientKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := InstallImportedSSL(tc.domain, tc.cert, tc.key)
			if !errors.Is(err, ErrImportedSSLInvalid) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("InstallImportedSSL() error = %v, want ErrImportedSSLInvalid naming %q", err, tc.reason)
			}
			if entries, _ := os.ReadDir(root); len(entries) != 0 {
				t.Fatalf("a refused certificate left %d entries under the certificate root", len(entries))
			}
		})
	}
}

// A usable pair is written into the system certificate directory, the key with
// owner-only permissions, and then handed to root. A test that is not root
// cannot hand files to root, so the install stops at the ownership step; the
// files already written are the ones a root process would keep. A certificate
// with no extended key usage at all is accepted.
func TestAUsableCertificateIsWrittenIntoTheSystemDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SERVIKA_CERT_ROOT", root)
	notAfter := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	certPEM, keyPEM := certificateFor(t, "import.example", time.Now().Add(-time.Hour), notAfter, nil)

	certPath, keyPath, expires, err := InstallImportedSSL("import.example", certPEM, keyPEM)

	wantCert := filepath.Join(root, "import.example", "import.example.crt")
	wantKey := filepath.Join(root, "import.example", "import.example.key")
	if os.Geteuid() == 0 {
		if err != nil {
			t.Fatalf("InstallImportedSSL() error = %v", err)
		}
		if certPath != wantCert || keyPath != wantKey || !expires.Equal(notAfter) {
			t.Fatalf("InstallImportedSSL() = %q, %q, %v; want %q, %q, %v", certPath, keyPath, expires, wantCert, wantKey, notAfter)
		}
	} else if err == nil || !strings.Contains(err.Error(), "set certificate ownership") {
		t.Fatalf("as a non-root user InstallImportedSSL() error = %v, want the ownership step to refuse", err)
	}

	assertImportedFile(t, wantCert, certPEM, 0o644)
	assertImportedFile(t, wantKey, keyPEM, 0o600)
}

// assertImportedFile checks that path holds exactly data with mode.
func assertImportedFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("%s was not written: %v", filepath.Base(path), err)
	}
	if info.Mode().Perm() != mode {
		t.Errorf("%s has mode %v, want %v", filepath.Base(path), info.Mode().Perm(), mode)
	}
	if written, readErr := os.ReadFile(path); readErr != nil || !bytes.Equal(written, data) {
		t.Errorf("%s does not hold what was imported: %v", filepath.Base(path), readErr)
	}
}

// A certificate directory that cannot be created is a filesystem fault, not a
// refusal of the certificate, so it is not reported as ErrImportedSSLInvalid.
func TestACertificateDirectoryThatCannotBeCreatedIsAFault(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write the blocking file: %v", err)
	}
	t.Setenv("SERVIKA_CERT_ROOT", filepath.Join(blocker, "certs"))
	certPEM, keyPEM := certificateFor(t, "import.example", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), nil)

	_, _, _, err := InstallImportedSSL("import.example", certPEM, keyPEM)

	if err == nil || errors.Is(err, ErrImportedSSLInvalid) {
		t.Fatalf("InstallImportedSSL() error = %v, want a filesystem error that is not a certificate refusal", err)
	}
}

// A certificate directory that cannot take the files is a filesystem fault too.
// When the key cannot be written, the certificate already written is taken back
// out, so the directory never holds a certificate without its key.
func TestAnImportThatCannotBeWrittenLeavesNoCertificateBehind(t *testing.T) {
	for _, blocked := range []string{"import.example.crt", "import.example.key"} {
		t.Run(blocked, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("SERVIKA_CERT_ROOT", root)
			dir := filepath.Join(root, "import.example")
			plantDirectory(t, filepath.Join(dir, blocked))
			certPEM, keyPEM := testCertificate(t, "import.example", time.Now().Add(24*time.Hour))

			_, _, _, err := InstallImportedSSL("import.example", certPEM, keyPEM)

			if err == nil || errors.Is(err, ErrImportedSSLInvalid) {
				t.Fatalf("InstallImportedSSL() error = %v, want a filesystem error", err)
			}
			if blocked == "import.example.key" {
				assertPathsGone(t, filepath.Join(dir, "import.example.crt"))
			}
		})
	}
}

func TestAnImportedPairIsInstalledAndItsExpiryReported(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SERVIKA_CERT_ROOT", root)
	setForTest(t, &chown, func(string, int, int) error { return nil })
	withCommands(t)
	notAfter := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	certPEM, keyPEM := testCertificate(t, "import.example", notAfter)

	certPath, keyPath, expires, err := InstallImportedSSL("import.example", certPEM, keyPEM)

	dir := filepath.Join(root, "import.example")
	if err != nil || certPath != filepath.Join(dir, "import.example.crt") ||
		keyPath != filepath.Join(dir, "import.example.key") || !expires.Equal(notAfter) {
		t.Fatalf("InstallImportedSSL() = %q, %q, %v, %v; want the installed paths expiring %v", certPath, keyPath, expires, err, notAfter)
	}
}

func testCertificate(t *testing.T, domain string, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	return certificateFor(t, domain, time.Now().Add(-time.Hour), notAfter,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

// certificateFor builds a self-signed pair for one name, valid from notBefore to
// notAfter, carrying the given extended key usages (none when nil).
func certificateFor(t *testing.T, domain string, notBefore, notAfter time.Time, usages []x509.ExtKeyUsage) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  usages,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
