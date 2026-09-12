package dbremote

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/logx"
)

// Turning remote access on rebinds MariaDB from loopback to every interface, and
// the accounts it creates spoke the plain MySQL protocol: every query, every
// result set and everything written through them crossed the public internet in
// the clear, with nothing at the transport layer to detect a modification.
//
// MariaDB, unlike MySQL 8, does not generate a server certificate of its own, so
// the server could not offer TLS at all and a client asking for it was refused
// rather than protected. This produces that certificate.

// certValidity is deliberately long. Nothing renews a self-signed certificate
// here, and one that expires cuts remote access with no warning and no obvious
// cause.
const certValidity = 3650

// certRenewBefore is how close to expiry a certificate is replaced. It only
// matters for an installation that outlives certValidity.
const certRenewBefore = 30 * 24 * time.Hour

// mariadbCertDir returns the directory holding the server key pair. It sits
// under the panel's own certificate root so an operator finds it where every
// other certificate the panel manages lives.
func mariadbCertDir() string { return filepath.Join(config.CertRoot(), "mariadb") }

func serverCertPath() string { return filepath.Join(mariadbCertDir(), "server.crt") }
func serverKeyPath() string  { return filepath.Join(mariadbCertDir(), "server.key") }

// ensureServerCertificate makes sure MariaDB has a usable key pair, generating a
// self-signed one when it does not.
//
// Idempotent: a certificate that is present and not near expiry is left alone,
// so this can run on every Apply.
func ensureServerCertificate() error {
	if usableCertificate(serverCertPath(), serverKeyPath()) {
		return nil
	}
	dir := mariadbCertDir()
	// #nosec G301 -- the directory is read by the mysql user; the private key
	// inside it carries the restrictive mode, not the directory.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("remote db: certificate directory: %w", err)
	}
	name := certificateHostname()
	args := []string{
		"req", "-x509", "-nodes",
		"-newkey", "rsa:2048",
		"-keyout", serverKeyPath(),
		"-out", serverCertPath(),
		"-days", strconv.Itoa(certValidity),
		"-subj", "/C=TR/ST=Local/L=Servika/O=" + name + "/CN=" + name,
		"-addext", "subjectAltName=DNS:" + name,
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); the hostname is validated by certificateHostname.
	if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("remote db: openssl: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return applyCertificatePermissions()
}

// applyCertificatePermissions makes the pair readable by MariaDB and nobody
// else.
//
// These modes are NOT the ones the nginx certificates get. MariaDB reads the key
// as its own unprivileged user, so a root-only key would leave the server unable
// to offer TLS at all, and it refuses to start on a key it considers world
// readable.
func applyCertificatePermissions() error {
	if err := os.Chmod(serverCertPath(), 0o644); err != nil {
		return fmt.Errorf("remote db: certificate mode: %w", err)
	}
	if err := os.Chmod(serverKeyPath(), 0o640); err != nil {
		return fmt.Errorf("remote db: key mode: %w", err)
	}
	// A failed chown is reported, not fatal.
	//
	// The mode is already restrictive, so discarding an otherwise usable
	// certificate over the group would leave the server with NO TLS at all, which
	// is worse than one MariaDB may not be able to read. The panel runs as root
	// against a host that has a mysql group, so this succeeds in production; a
	// host where it does not is one where MariaDB is not installed the way this
	// expects, and the caller's own restart verification is what catches that.
	gid, err := mysqlGroupID()
	if err != nil {
		logx.Errorf("remote db: no mysql group to own %s: %v", serverKeyPath(), err)
		return nil
	}
	if err := os.Chown(serverKeyPath(), 0, gid); err != nil {
		logx.Errorf("remote db: could not give %s to the mysql group: %v", serverKeyPath(), err)
	}
	return nil
}

// mysqlGroupID resolves the group MariaDB runs as.
func mysqlGroupID() (int, error) {
	group, err := user.LookupGroup("mysql")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(group.Gid)
}

// usableCertificate reports whether the pair exists and has enough life left.
func usableCertificate(certPath, keyPath string) bool {
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	// #nosec G304 -- a path composed from config.CertRoot() and package constants.
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return false
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return time.Until(parsed.NotAfter) > certRenewBefore
}

// certificateHostname names the certificate.
//
// A remote client connects by address and cannot verify a hostname it did not
// ask for, so this is a label rather than a security boundary; it exists because
// a certificate needs a subject. An unusable hostname falls back to a fixed name
// instead of failing: refusing to generate a certificate would leave the server
// with no TLS at all, which is the state this replaces.
func certificateHostname() string {
	name, err := os.Hostname()
	name = strings.TrimSpace(strings.ToLower(name))
	if err != nil || name == "" || !validCertificateName(name) {
		return "servika-mariadb"
	}
	return name
}

// validCertificateName keeps a hostname out of the openssl subject when it
// carries anything that would change the meaning of that string.
func validCertificateName(name string) bool {
	if len(name) > 253 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return false
		}
	}
	return true
}
