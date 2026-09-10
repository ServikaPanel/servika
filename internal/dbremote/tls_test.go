package dbremote

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// certRoot redirects the panel's certificate root at a temporary directory, so a
// test never writes under /etc/pki.
func certRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("SERVIKA_CERT_ROOT", root)
	return root
}

// MariaDB, unlike MySQL 8, generates no server certificate of its own, so
// without this the server could not offer TLS at all: a client asking for an
// encrypted connection was refused rather than protected, and an account created
// with REQUIRE SSL could never connect.
func TestTheServerCertificateIsGeneratedOnce(t *testing.T) {
	certRoot(t)

	if err := ensureServerCertificate(); err != nil {
		t.Fatalf("ensureServerCertificate: %v", err)
	}
	firstCert := readFile(t, serverCertPath())
	if len(firstCert) == 0 {
		t.Fatal("the certificate is empty")
	}
	if len(readFile(t, serverKeyPath())) == 0 {
		t.Fatal("the key is empty")
	}

	// Idempotent: a usable pair is left alone, so this can run on every Apply.
	if err := ensureServerCertificate(); err != nil {
		t.Fatalf("second ensureServerCertificate: %v", err)
	}
	if string(readFile(t, serverCertPath())) != string(firstCert) {
		t.Fatal("the certificate was regenerated although the existing one was usable")
	}
}

// MariaDB reads the key as its own unprivileged user, so a root-only key leaves
// the server unable to offer TLS; it also refuses to start on a key it considers
// world readable.
func TestTheKeyIsReadableByMariaDBAndNobodyElse(t *testing.T) {
	certRoot(t)
	if err := ensureServerCertificate(); err != nil {
		t.Fatalf("ensureServerCertificate: %v", err)
	}

	keyInfo, err := os.Stat(serverKeyPath())
	if err != nil {
		t.Fatalf("stat the key: %v", err)
	}
	if mode := keyInfo.Mode().Perm(); mode != 0o640 {
		t.Fatalf("key mode = %o, want 0640", mode)
	}
	certInfo, err := os.Stat(serverCertPath())
	if err != nil {
		t.Fatalf("stat the certificate: %v", err)
	}
	if mode := certInfo.Mode().Perm(); mode != 0o644 {
		t.Fatalf("certificate mode = %o, want 0644", mode)
	}
}

// Nothing renews a self-signed certificate here, so one that expires cuts remote
// access with no warning and no obvious cause.
func TestTheCertificateOutlivesAnyPlausibleInstallation(t *testing.T) {
	certRoot(t)
	if err := ensureServerCertificate(); err != nil {
		t.Fatalf("ensureServerCertificate: %v", err)
	}

	block, _ := pem.Decode(readFile(t, serverCertPath()))
	if block == nil {
		t.Fatal("the certificate is not PEM")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse the certificate: %v", err)
	}
	if remaining := time.Until(parsed.NotAfter); remaining < 5*365*24*time.Hour {
		t.Fatalf("the certificate expires in %v, too soon for an unrenewed pair", remaining)
	}
}

// A pair that is missing, unreadable or close to expiry is not usable, and
// treating it as usable would leave the server with a certificate it cannot
// serve.
func TestAnUnusablePairIsReplaced(t *testing.T) {
	root := certRoot(t)
	dir := filepath.Join(root, "mariadb")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create the directory: %v", err)
	}

	if usableCertificate(filepath.Join(dir, "absent.crt"), filepath.Join(dir, "absent.key")) {
		t.Error("a missing pair was called usable")
	}

	certPath := filepath.Join(dir, "junk.crt")
	keyPath := filepath.Join(dir, "junk.key")
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if usableCertificate(certPath, keyPath) {
		t.Error("an unparseable certificate was called usable")
	}
}

// Opening the port without a key pair would publish the plain MySQL protocol to
// the internet, and an account created with REQUIRE SSL against such a server
// could never connect. Nothing may be written in that case.
func TestApplyWritesNothingWhenTheCertificateCannotBeMade(t *testing.T) {
	// A certificate root that is a FILE, so the directory cannot be created.
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("SERVIKA_CERT_ROOT", blocked)

	dropIn := filepath.Join(t.TempDir(), "zzz-servika-remote-db.cnf")
	previous := dropInPath
	setDropInPath(dropIn)
	t.Cleanup(func() { setDropInPath(previous) })

	err := Apply(context.Background(), nil, true)

	if err == nil {
		t.Fatal("Apply() opened the port with no server certificate")
	}
	if !strings.Contains(err.Error(), ErrTLSUnavailable.Error()) {
		t.Fatalf("Apply() error = %v, want it to name the missing certificate", err)
	}
	if _, statErr := os.Stat(dropIn); statErr == nil {
		t.Fatal("the drop-in was written although no certificate could be made")
	}
}

// The key pair is what lets the server offer TLS at all, and the same restart
// that applies the bind applies these lines. Without them a client asking for an
// encrypted connection is refused, and an account created with REQUIRE SSL can
// never connect.
func TestTheDropInPointsMariaDBAtTheKeyPair(t *testing.T) {
	certRoot(t)
	dropIn := filepath.Join(t.TempDir(), "zzz-servika-remote-db.cnf")
	previous := dropInPath
	setDropInPath(dropIn)
	t.Cleanup(func() { setDropInPath(previous) })

	if _, err := writeDropIn(true); err != nil {
		t.Fatalf("writeDropIn: %v", err)
	}
	body := string(readFile(t, dropIn))

	for _, want := range []string{
		"bind-address = *",
		"ssl_cert = " + serverCertPath(),
		"ssl_key = " + serverKeyPath(),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the drop-in is missing %q:\n%s", want, body)
		}
	}

	// Turning the feature off still REMOVES the file, so the installer's own
	// loopback bind is what takes effect again.
	if _, err := writeDropIn(false); err != nil {
		t.Fatalf("writeDropIn(false): %v", err)
	}
	if _, err := os.Stat(dropIn); !os.IsNotExist(err) {
		t.Fatal("turning the feature off left the drop-in behind")
	}
}

// A hostname is a label on this certificate, not a security boundary, but it is
// interpolated into an openssl subject, so anything that would change the
// meaning of that string is refused in favour of a fixed name.
func TestOnlyAPlainHostnameReachesTheSubject(t *testing.T) {
	for _, good := range []string{"host.example", "srv-01.example.com", "a"} {
		if !validCertificateName(good) {
			t.Errorf("%q was refused", good)
		}
	}
	for _, bad := range []string{"host example", "host/../x", "host\nCN=other", "host'", strings.Repeat("a", 254)} {
		if validCertificateName(bad) {
			t.Errorf("%q was accepted into the subject", bad)
		}
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test-owned path under t.TempDir().
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	return data
}
