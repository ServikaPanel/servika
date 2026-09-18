package main

// The agent's own configuration and its self-signed identity.
//
// This file carries no build tag. The settings file, the secret generation and
// the certificate are plain Go, so they are compiled and measured on every
// build rather than only on the host they run on.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// defaultListen is the agent API address. The panel reaches this one.
const defaultListen = "0.0.0.0:8460"

// errNoToken means the agent has never been installed on this host.
var errNoToken = errors.New("there is no token: run `servika-agent install`, or set SERVIKA_AGENT_TOKEN")

// settings is what the agent keeps between runs.
//
// It lives in a file rather than in the environment because a Windows service
// carries no environment of its own. An environment variable still WINS when
// one is set, which is what makes a foreground development run possible without
// touching the installed configuration.
type settings struct {
	Token   string `json:"token"`
	Listen  string `json:"listen"`
	Version string `json:"version"`

	// PanelPasswordHash is the bcrypt hash of the local panel's admin password.
	// The plain password is stored NOWHERE: install and reset-password generate
	// one and print it once. There is deliberately no environment variable for
	// it, so the only copy is the hash in this file, which the installer locks
	// to SYSTEM and Administrators.
	PanelPasswordHash string `json:"panel_password_hash"`
}

// settingsPath is where the file lives inside the data directory.
func settingsPath(dir string) string { return filepath.Join(dir, "agent.json") }

// readSettings reads the file, or returns an empty value when there is none.
// A file that cannot be parsed is an error rather than a silent reset: writing
// a fresh file over a broken one would throw the token away and break the
// panel's registration.
func readSettings(dir string) (settings, error) {
	var s settings
	b, err := os.ReadFile(settingsPath(dir))
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("the settings could not be read: %w", err)
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("the settings file %s is not valid JSON: %w", settingsPath(dir), err)
	}
	return s, nil
}

// writeSettings saves the file with 0600.
func writeSettings(dir string, s settings) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(settingsPath(dir), b, 0o600)
}

// loadSettings reads the file and applies the environment overrides a
// foreground run may carry.
func loadSettings(dir string) (settings, error) {
	s, err := readSettings(dir)
	if err != nil {
		return s, err
	}
	if v := os.Getenv("SERVIKA_AGENT_TOKEN"); v != "" {
		s.Token = v
	}
	if v := os.Getenv("SERVIKA_AGENT_LISTEN"); v != "" {
		s.Listen = v
	}
	if s.Listen == "" {
		s.Listen = defaultListen
	}
	if s.Token == "" {
		return s, errNoToken
	}
	return s, nil
}

// randomToken returns 24 random bytes as hex: the agent API token.
func randomToken() (string, error) { return randomHex(24) }

// randomPanelPassword returns 12 random bytes as hex. That is 24 characters, so
// an operator can retype it while it stays far out of reach of a brute force.
func randomPanelPassword() (string, error) { return randomHex(12) }

// randomHex returns n random bytes as a hex string.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// tokenMatches compares two tokens in constant time.
//
// A plain string comparison stops at the first differing byte, and the time it
// takes leaks how much of the token was guessed correctly.
func tokenMatches(given, want string) bool {
	return len(given) == len(want) && subtle.ConstantTimeCompare([]byte(given), []byte(want)) == 1
}

// hashPanelPassword produces the stored form.
func hashPanelPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("the panel password could not be hashed: %w", err)
	}
	return string(h), nil
}

// panelPasswordMatches checks a login attempt.
//
// An account with no hash is refused OUTRIGHT rather than treated as having no
// password. That case happens when the settings file is half written, and
// letting it through would open the panel to anyone.
func panelPasswordMatches(hash, password string) bool {
	if hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// certPaths returns the certificate and key paths inside the data directory.
func certPaths(dir string) (string, string) {
	return filepath.Join(dir, "agent.crt"), filepath.Join(dir, "agent.key")
}

// loadCertificate loads the pair, generating it on the first run.
//
// AN EXISTING PAIR IS NEVER REGENERATED. The panel pinned this certificate's
// SHA-256 the first time it saw it. A new certificate is a new fingerprint, the
// pin breaks, and the panel refuses the agent as "the certificate changed".
// Renewal is therefore a deliberate act: the operator deletes both files,
// starts the agent, and registers it with the panel again.
func loadCertificate(dir string) (tls.Certificate, error) {
	crtPath, keyPath := certPaths(dir)
	_, crtErr := os.Stat(crtPath)
	_, keyErr := os.Stat(keyPath)
	if crtErr == nil && keyErr == nil {
		return tls.LoadX509KeyPair(crtPath, keyPath)
	}
	if (crtErr != nil && !os.IsNotExist(crtErr)) || (keyErr != nil && !os.IsNotExist(keyErr)) {
		return tls.Certificate{}, fmt.Errorf("the certificate files could not be read: crt=%v key=%v", crtErr, keyErr)
	}
	// A first run, or a half-written pair. Half a pair cannot be used anyway.
	if err := generateCertificate(crtPath, keyPath); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(crtPath, keyPath)
}

// generateCertificate writes a self-signed ECDSA P-256 pair valid for ten years.
//
// The SAN list is deliberately EMPTY. The panel verifies the fingerprint, not
// the name, so the agent's address can change without invalidating the pin.
func generateCertificate(crtPath, keyPath string) error {
	if err := os.MkdirAll(filepath.Dir(crtPath), 0o755); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("the key could not be generated: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("the serial number could not be generated: %w", err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "servika-agent"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("the certificate could not be generated: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("the key could not be encoded: %w", err)
	}
	if err := os.WriteFile(crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	// The key is 0600. On Windows that is not enough on its own, which is why
	// the installer also puts an ACL on the whole directory.
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
}

// fingerprintOf returns the SHA-256 of the leaf certificate, which is exactly
// what the panel pins.
func fingerprintOf(cert tls.Certificate) string {
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:])
}
