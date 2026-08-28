package transfers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestSectionBetween checks that the marker extraction returns the text between
// two markers and an empty string when either marker is missing.
func TestSectionBetween(t *testing.T) {
	blob := "noise\n" + certMarkerStart + "\nCERTBODY\n" + certMarkerKey + "\nKEYBODY\n" + certMarkerEnd + "\ntail"
	if got := strings.TrimSpace(sectionBetween(blob, certMarkerStart, certMarkerKey)); got != "CERTBODY" {
		t.Errorf("cert section = %q, want CERTBODY", got)
	}
	if got := strings.TrimSpace(sectionBetween(blob, certMarkerKey, certMarkerEnd)); got != "KEYBODY" {
		t.Errorf("key section = %q, want KEYBODY", got)
	}
	if got := sectionBetween("no markers here", certMarkerStart, certMarkerKey); got != "" {
		t.Errorf("missing start marker should yield empty, got %q", got)
	}
	if got := sectionBetween(certMarkerStart+"only start", certMarkerStart, certMarkerKey); got != "" {
		t.Errorf("missing end marker should yield empty, got %q", got)
	}
}

// selfSignedPEM returns a self-signed leaf certificate (issuer == subject).
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "self.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// caSignedPEM returns a leaf certificate signed by a distinct CA (issuer != subject).
func caSignedPEM(t *testing.T) []byte {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca create: %v", err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf create: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
}

// TestIsSelfSignedCertificate separates a self-signed leaf from a CA-issued one,
// because only the self-signed case earns the "renew via Let's Encrypt" warning.
func TestIsSelfSignedCertificate(t *testing.T) {
	if !isSelfSignedCertificate(selfSignedPEM(t)) {
		t.Error("a self-signed certificate was not detected as self-signed")
	}
	if isSelfSignedCertificate(caSignedPEM(t)) {
		t.Error("a CA-issued certificate was reported as self-signed")
	}
	if isSelfSignedCertificate([]byte("not a pem")) {
		t.Error("garbage input must not report self-signed")
	}
}

// TestSourceCertificateScript proves each panel produces a reader that carries
// the shell-quoted domain and the markers, an unknown panel produces nothing,
// and DirectAdmin without a source user produces nothing (its path needs one).
func TestSourceCertificateScript(t *testing.T) {
	for _, panel := range []string{"cpanel", "plesk", "directadmin"} {
		s := sourceCertificateScript(panel, "site.example", "sourceuser")
		if s == "" {
			t.Errorf("%s produced an empty script", panel)
			continue
		}
		if !strings.Contains(s, "'site.example'") {
			t.Errorf("%s script does not shell-quote the domain: %q", panel, s)
		}
		if !strings.Contains(s, certMarkerStart) || !strings.Contains(s, certMarkerEnd) {
			t.Errorf("%s script is missing the markers", panel)
		}
	}
	if s := sourceCertificateScript("unknown", "site.example", "sourceuser"); s != "" {
		t.Errorf("an unknown panel must produce no script, got %q", s)
	}
	if s := sourceCertificateScript("directadmin", "site.example", ""); s != "" {
		t.Errorf("directadmin with no source user must produce no script, got %q", s)
	}
}
