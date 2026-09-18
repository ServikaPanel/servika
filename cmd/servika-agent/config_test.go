package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestASettingsFileThatCannotBeParsedIsAnError(t *testing.T) {
	// Writing a fresh file over a broken one would throw the token away and
	// break the panel's registration for this host.
	dir := t.TempDir()
	if err := os.WriteFile(settingsPath(dir), []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSettings(dir); err == nil {
		t.Fatal("a corrupt settings file was read as empty")
	}
}

func TestAMissingSettingsFileIsNotAnError(t *testing.T) {
	s, err := readSettings(t.TempDir())
	if err != nil {
		t.Fatalf("a first run failed: %v", err)
	}
	if s.Token != "" {
		t.Fatalf("an empty settings value carried a token: %+v", s)
	}
}

func TestTheSettingsSurviveAWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	want := settings{Token: "abc", Listen: "0.0.0.0:8460", PanelPasswordHash: "$2a$x", Version: "1.2.3"}
	if err := writeSettings(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := readSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("the settings read back as %+v", got)
	}
}

func TestTheSettingsFileIsNotWorldReadable(t *testing.T) {
	// It holds the token the panel authenticates with.
	dir := t.TempDir()
	if err := writeSettings(dir, settings{Token: "secret"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(settingsPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the settings file is mode %v", fi.Mode().Perm())
	}
}

func TestAnAgentWithNoTokenRefusesToStart(t *testing.T) {
	t.Setenv("SERVIKA_AGENT_TOKEN", "")
	t.Setenv("SERVIKA_AGENT_LISTEN", "")
	if _, err := loadSettings(t.TempDir()); !errors.Is(err, errNoToken) {
		t.Fatalf("an uninstalled agent started anyway: %v", err)
	}
}

func TestTheEnvironmentOverridesTheInstalledSettings(t *testing.T) {
	// A Windows service carries no environment, so the file is the source of
	// truth there. A foreground development run needs to override it without
	// touching what is installed.
	dir := t.TempDir()
	if err := writeSettings(dir, settings{Token: "from-file", Listen: "0.0.0.0:8460"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SERVIKA_AGENT_TOKEN", "from-env")
	t.Setenv("SERVIKA_AGENT_LISTEN", "127.0.0.1:9000")
	got, err := loadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "from-env" || got.Listen != "127.0.0.1:9000" {
		t.Fatalf("the override did not apply: %+v", got)
	}
	// The file itself must be untouched: an override that wrote itself back
	// would make a development run rewrite the installed token.
	onDisk, err := readSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if onDisk.Token != "from-file" {
		t.Fatalf("the override was written back to disk: %+v", onDisk)
	}
}

func TestAnAddressIsFilledInWhenNoneIsSet(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVIKA_AGENT_TOKEN", "x")
	t.Setenv("SERVIKA_AGENT_LISTEN", "")
	got, err := loadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Listen != defaultListen {
		t.Fatalf("the address read %q", got.Listen)
	}
}

func TestTheTokenComparisonDoesNotStopAtTheFirstWrongByte(t *testing.T) {
	// A plain comparison leaks how much of the token was guessed correctly.
	token := "0123456789abcdef"
	if !tokenMatches(token, token) {
		t.Fatal("the right token was refused")
	}
	for _, wrong := range []string{"", "0123456789abcde", "0123456789abcdeff", "0123456789abcdee", "X123456789abcdef"} {
		if tokenMatches(wrong, token) {
			t.Fatalf("the wrong token %q was accepted", wrong)
		}
	}
}

func TestAGeneratedTokenIsLongAndDifferentEveryTime(t *testing.T) {
	first, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 48 {
		t.Fatalf("the token is %d characters, expected 48", len(first))
	}
	if first == second {
		t.Fatal("two generated tokens are identical")
	}
}

func TestAPanelAccountWithNoHashCannotLogIn(t *testing.T) {
	// A half-written settings file must not open the panel to anyone.
	if panelPasswordMatches("", "") {
		t.Fatal("an empty hash accepted an empty password")
	}
	if panelPasswordMatches("", "anything") {
		t.Fatal("an empty hash accepted a password")
	}
}

func TestThePanelPasswordRoundTripsThroughItsHash(t *testing.T) {
	password, err := randomPanelPassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != 24 {
		t.Fatalf("the password is %d characters, expected 24", len(password))
	}
	hash, err := hashPanelPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hash, password) {
		t.Fatal("the plain password is visible inside its own hash")
	}
	if !panelPasswordMatches(hash, password) {
		t.Fatal("the right password was refused")
	}
	if panelPasswordMatches(hash, password+"x") {
		t.Fatal("a wrong password was accepted")
	}
}

func TestTheCertificateIsGeneratedOnceAndNeverAgain(t *testing.T) {
	// The panel pinned this certificate's SHA-256. A new one breaks the pin and
	// the agent is refused as "the certificate changed".
	dir := t.TempDir()
	first, err := loadCertificate(dir)
	if err != nil {
		t.Fatalf("the first run could not make a certificate: %v", err)
	}
	second, err := loadCertificate(dir)
	if err != nil {
		t.Fatalf("the second run failed: %v", err)
	}
	if fingerprintOf(first) != fingerprintOf(second) {
		t.Fatal("a second run produced a different fingerprint, which breaks the panel's pin")
	}
}

func TestTheGeneratedCertificateIsSelfSignedAndLongLived(t *testing.T) {
	dir := t.TempDir()
	cert, err := loadCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "servika-agent" {
		t.Fatalf("the subject reads %q", leaf.Subject.CommonName)
	}
	if years := leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24 / 365; years < 9 {
		t.Fatalf("the certificate lasts %.1f years, so it would expire while the pin still holds", years)
	}
	if !leaf.NotBefore.Before(time.Now()) {
		t.Fatal("the certificate is not valid yet, so the first connection would fail")
	}
	// The SAN list is empty on purpose: the panel verifies the fingerprint, not
	// the name, so the agent's address can change without breaking the pin.
	if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 {
		t.Fatalf("the certificate carries names (%v %v), which ties the pin to an address", leaf.DNSNames, leaf.IPAddresses)
	}
}

func TestThePrivateKeyIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadCertificate(dir); err != nil {
		t.Fatal(err)
	}
	_, keyPath := certPaths(dir)
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the private key is mode %v", fi.Mode().Perm())
	}
}

func TestAHalfWrittenPairIsRebuiltRatherThanFailing(t *testing.T) {
	// A certificate with no key cannot be used for anything, so starting over is
	// the only way forward.
	dir := t.TempDir()
	crtPath, _ := certPaths(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crtPath, []byte("left over from a crash"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCertificate(dir); err != nil {
		t.Fatalf("a half-written pair could not be repaired: %v", err)
	}
}

func TestTheFingerprintIsTheLeafHashThePanelPins(t *testing.T) {
	dir := t.TempDir()
	cert, err := loadCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := fingerprintOf(cert)
	if len(got) != 64 {
		t.Fatalf("the fingerprint is %d characters, expected 64", len(got))
	}
	// The same bytes a TLS client sees on the wire.
	crtPath, keyPath := certPaths(dir)
	reloaded, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprintOf(reloaded) != got {
		t.Fatal("the fingerprint changes between loads")
	}
}

func TestTheSettingsFileHoldsNoPlainPanelPassword(t *testing.T) {
	// The plain password exists only on the screen, once.
	dir := t.TempDir()
	password, err := randomPanelPassword()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := hashPanelPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSettings(dir, settings{Token: "t", PanelPasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(settingsPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), password) {
		t.Fatal("the plain panel password was written to disk")
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if _, found := raw["panel_password"]; found {
		t.Fatal("the settings file carries a plain password field")
	}
}

func TestTheDataDirectoryIsCreatedWhenItIsMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deeper", "still")
	if err := writeSettings(dir, settings{Token: "t"}); err != nil {
		t.Fatalf("a missing directory was not created: %v", err)
	}
}
