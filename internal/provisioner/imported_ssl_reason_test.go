package provisioner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func selfSignedPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "import.test"},
		DNSNames:     []string{"import.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func rsaKeyPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

// A private key whose CRT values are wrong no longer parses at all: Go 1.24
// stopped recomputing them and returns `crypto/rsa: invalid CRT exponent`, and
// the panel builds at a language version past that. Reporting it as a mismatched
// pair sends the operator looking for a wrong file that does not exist, which is
// the one answer this screen must not give.
func TestAKeyThatCannotBeParsedIsNotReportedAsAMismatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	certPEM := selfSignedPEM(t, key)

	broken := *key
	broken.Precomputed.Dp = new(big.Int).Add(key.Precomputed.Dp, big.NewInt(1))
	brokenPEM := rsaKeyPEM(t, &broken)

	got := keyPairProblem(certPEM, brokenPEM)
	if !strings.Contains(got, "could not be parsed") {
		t.Fatalf("a corrupt key was reported as %q", got)
	}
	if strings.Contains(got, "do not match") {
		t.Fatalf("a corrupt key was reported as a mismatch: %q", got)
	}
}

// The mismatch message must survive for the case it was written for, or the
// split has only moved the wrong answer somewhere else.
func TestAGenuineMismatchIsStillReportedAsAMismatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	got := keyPairProblem(selfSignedPEM(t, key), rsaKeyPEM(t, other))
	if !strings.Contains(got, "do not match") {
		t.Fatalf("a genuinely mismatched pair was reported as %q", got)
	}
}

// A key of a different algorithm than the certificate is a mismatch, not a parse
// failure: it reads perfectly well, it is simply the wrong key.
func TestAKeyOfTheWrongAlgorithmIsAMismatchNotAParseFailure(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatalf("marshal ec key: %v", err)
	}
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})

	got := keyPairProblem(selfSignedPEM(t, key), ecPEM)
	if !strings.Contains(got, "do not match") {
		t.Fatalf("an ECDSA key against an RSA certificate was reported as %q", got)
	}
}

// A missing half is its own answer. Told "they do not match", the operator looks
// for the wrong file instead of the absent one.
func TestAMissingHalfIsNamedRatherThanCalledAMismatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	certPEM := selfSignedPEM(t, key)
	keyPEM := rsaKeyPEM(t, key)

	if got := keyPairProblem([]byte("not pem at all"), keyPEM); !strings.Contains(got, "no PEM certificate") {
		t.Fatalf("a missing certificate was reported as %q", got)
	}
	if got := keyPairProblem(certPEM, []byte("not pem at all")); !strings.Contains(got, "no PEM private key") {
		t.Fatalf("a missing key was reported as %q", got)
	}
	// A file holding only the certificate is the mistake people actually make,
	// pasting the same PEM into both fields.
	if got := keyPairProblem(certPEM, certPEM); !strings.Contains(got, "no PEM private key") {
		t.Fatalf("a certificate pasted in place of the key was reported as %q", got)
	}
}

// The key is found even when it sits behind the certificate in one file, which
// is how a combined PEM is usually laid out and how crypto/tls itself reads it.
//
// The pair is deliberately MISMATCHED, so the classifier has to run and has to
// reach the key: a version that stopped at the first block would find the
// certificate, fail to parse it as a key, and answer "could not be parsed" about
// a key that is perfectly readable.
func TestTheKeyIsFoundBehindACertificateInTheSameFile(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	certPEM := selfSignedPEM(t, key)
	combined := append(append([]byte{}, certPEM...), rsaKeyPEM(t, other)...)

	got := keyPairProblem(certPEM, combined)
	if !strings.Contains(got, "do not match") {
		t.Fatalf("a readable key behind a certificate was reported as %q", got)
	}
}

// InstallImportedSSL is what carries the message to the operator, so the split
// has to survive the wrapping.
func TestTheReasonReachesTheInstallError(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	broken := *key
	broken.Precomputed.Dq = new(big.Int).Add(key.Precomputed.Dq, big.NewInt(1))

	_, _, _, err = InstallImportedSSL("import.test", selfSignedPEM(t, key), rsaKeyPEM(t, &broken))
	if err == nil {
		t.Fatal("a corrupt key was accepted")
	}
	if !strings.Contains(err.Error(), "could not be parsed") {
		t.Fatalf("InstallImportedSSL reported %q", err)
	}
}
