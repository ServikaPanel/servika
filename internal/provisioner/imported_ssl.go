package provisioner

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrImportedSSLInvalid signals that the source certificate/key pair cannot be
// used safely. The import may leave the account without SSL in that case.
var ErrImportedSSLInvalid = errors.New("invalid source SSL certificate")

// InstallImportedSSL installs a verified PEM certificate chain and private key
// into the system certificate directory. The caller updates the DB first and
// then calls RerenderVhost, so concurrent vhost re-renders cannot overwrite SSL.
func InstallImportedSSL(domainName string, certPEM, keyPEM []byte) (string, string, time.Time, error) {
	if err := ValidateDomain(domainName); err != nil {
		return "", "", time.Time{}, fmt.Errorf("%w: %v", ErrImportedSSLInvalid, err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("%w: %s", ErrImportedSSLInvalid, keyPairProblem(certPEM, keyPEM))
	}
	if len(pair.Certificate) == 0 {
		return "", "", time.Time{}, fmt.Errorf("%w: no certificate found", ErrImportedSSLInvalid)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("%w: certificate could not be parsed", ErrImportedSSLInvalid)
	}
	now := time.Now()
	if leaf.NotBefore.After(now.Add(5 * time.Minute)) {
		return "", "", time.Time{}, fmt.Errorf("%w: certificate is not yet valid", ErrImportedSSLInvalid)
	}
	if !leaf.NotAfter.After(now) {
		return "", "", time.Time{}, fmt.Errorf("%w: certificate has expired", ErrImportedSSLInvalid)
	}
	if err := leaf.VerifyHostname(domainName); err != nil {
		return "", "", time.Time{}, fmt.Errorf("%w: certificate does not cover %s", ErrImportedSSLInvalid, domainName)
	}
	if len(leaf.ExtKeyUsage) > 0 && !hasServerAuth(leaf.ExtKeyUsage) {
		return "", "", time.Time{}, fmt.Errorf("%w: certificate is not valid for server authentication", ErrImportedSSLInvalid)
	}

	sslDir := certSystemDir(domainName)
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(sslDir, 0o755); err != nil {
		return "", "", time.Time{}, err
	}
	certPath := filepath.Join(sslDir, domainName+".crt")
	keyPath := filepath.Join(sslDir, domainName+".key")
	if err := writeImportedPEM(certPath, certPEM, 0o644); err != nil {
		return "", "", time.Time{}, err
	}
	if err := writeImportedPEM(keyPath, keyPEM, 0o600); err != nil {
		_ = os.Remove(certPath)
		return "", "", time.Time{}, err
	}
	if err := applyCertificatePermissions(sslDir, certPath, keyPath); err != nil {
		return "", "", time.Time{}, err
	}
	return certPath, keyPath, leaf.NotAfter, nil
}

// keyPairProblem says WHY a certificate and a private key could not be loaded
// together.
//
// crypto/tls reports several unrelated problems through one error value, so
// every failure used to reach the customer as "certificate and private key do
// not match". That is wrong for most of them, and it is wrong in the way that
// costs the most time: someone whose key simply will not PARSE goes looking for
// a mismatched pair that does not exist. Go 1.24 made that case reachable by
// itself, because `ParsePKCS1PrivateKey` stopped recomputing the CRT values of
// an RSA key and now rejects the key outright (`crypto/rsa: invalid CRT
// exponent`), and the panel builds at a language version past that.
//
// Each condition is re-derived here rather than matched against the text of
// Go's error, which is not part of its API and has changed before.
func keyPairProblem(certPEM, keyPEM []byte) string {
	if pemBlockOfType(certPEM, "CERTIFICATE") == nil {
		return "no PEM certificate was found"
	}
	block := privateKeyPEMBlock(keyPEM)
	if block == nil {
		return "no PEM private key was found"
	}
	if !privateKeyParses(block.Bytes) {
		return "the private key could not be parsed; it may be corrupt or in an unsupported format"
	}
	return "certificate and private key do not match"
}

// pemBlockOfType returns the first PEM block of the requested type.
func pemBlockOfType(data []byte, want string) *pem.Block {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil
		}
		if block.Type == want {
			return block
		}
	}
}

// privateKeyPEMBlock returns the first block that is not a certificate, which is
// how crypto/tls itself picks the key out of a file that carries both.
func privateKeyPEMBlock(data []byte) *pem.Block {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil
		}
		if block.Type != "CERTIFICATE" {
			return block
		}
	}
}

// privateKeyParses reports whether DER holds a private key any of the three
// encodings crypto/tls accepts can read, tried in the same order.
func privateKeyParses(der []byte) bool {
	if _, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return true
	}
	if _, err := x509.ParseECPrivateKey(der); err == nil {
		return true
	}
	return false
}

func hasServerAuth(usages []x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageAny || usage == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

// writeImportedPEM writes a PEM file atomically (temp file, fsync, rename) with
// the requested mode so a partial write is never observed at the target path.
func writeImportedPEM(target string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(target), ".servika-import-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, target)
}
