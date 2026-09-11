package backups

import (
	"context"
	"os"
	"strings"
	"testing"
)

const samplePinnedKey = "backup.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterial"

// An SFTP destination must be verified against the key it was pinned to. The
// settings this returns replace `sftp:auto-confirm yes`, which accepted
// whatever key answered, on every connection, so anything on the path could
// take the password the client offers and receive the backup.
func TestLFTPHostKeySettingsPinTheStoredKey(t *testing.T) {
	d := &Destination{Type: "sftp", Host: "backup.example.com", Port: 22, HostKey: samplePinnedKey}

	settings, cleanup, err := lftpHostKeySettings(context.Background(), nil, d)
	if err != nil {
		t.Fatalf("lftpHostKeySettings() = %v, want nil", err)
	}
	defer cleanup()

	if strings.Contains(settings, "auto-confirm yes") {
		t.Fatal("the settings still accept any host key")
	}
	if !strings.Contains(settings, "StrictHostKeyChecking=yes") {
		t.Error("ssh is not told to refuse an unknown key")
	}
	if !strings.Contains(settings, "GlobalKnownHostsFile=/dev/null") {
		t.Error("the system known_hosts is still consulted, so a key trusted elsewhere would satisfy the check")
	}

	path := knownHostsPathFrom(t, settings)
	content, err := os.ReadFile(path) // #nosec G304 -- path produced by the function under test, under t's temp root.
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	if strings.TrimSpace(string(content)) != samplePinnedKey {
		t.Errorf("known_hosts holds %q, want the pinned key", content)
	}

	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the temporary known_hosts file outlives the transfer")
	}
}

// An FTP destination has no SSH layer, so it must not be sent ssh settings and
// must not trigger a key scan (which would reach the network on every upload).
func TestLFTPHostKeySettingsSkipFTP(t *testing.T) {
	d := &Destination{Type: "ftp", Host: "backup.example.com", Port: 21}
	settings, cleanup, err := lftpHostKeySettings(context.Background(), nil, d)
	if err != nil {
		t.Fatalf("lftpHostKeySettings() = %v, want nil", err)
	}
	defer cleanup()
	if settings != "" {
		t.Errorf("settings = %q, want nothing for an FTP destination", settings)
	}
}

// A destination that already carries a pin is never rescanned; that is what
// makes it a pin rather than a fresh trust decision on every connection.
func TestEnsureHostKeyDoesNotRescanAPinnedDestination(t *testing.T) {
	d := &Destination{Type: "sftp", Host: "unresolvable.invalid", Port: 22, HostKey: samplePinnedKey}
	// A nil DB and an unresolvable host would both fail a scan, so returning the
	// stored key proves no scan happened.
	key, err := ensureHostKey(context.Background(), nil, d)
	if err != nil {
		t.Fatalf("ensureHostKey() = %v, want the stored key", err)
	}
	if key != samplePinnedKey {
		t.Errorf("ensureHostKey() = %q, want the stored key", key)
	}
}

// A scan that produces nothing must fail the connection, never fall through to
// accepting any key.
func TestScanHostKeyRefusesAnUnreachableHost(t *testing.T) {
	if _, err := scanHostKey(context.Background(), "host.invalid", 22); err == nil {
		t.Fatal("scanHostKey() = nil, want a refusal for an unreachable host")
	}
}

func TestSSHHostKeyOptionsCloseEveryFallback(t *testing.T) {
	joined := strings.Join(sshHostKeyOptions("/tmp/known", "backup.example.com"), " ")
	for _, want := range []string{
		"StrictHostKeyChecking=yes",
		"UserKnownHostsFile=/tmp/known",
		"GlobalKnownHostsFile=/dev/null",
		// The connection goes to the vetted ADDRESS; the pin was written under
		// the NAME. Without the alias ssh looks the address up, finds nothing,
		// and refuses every connection.
		"HostKeyAlias=backup.example.com",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("options %q are missing %q", joined, want)
		}
	}
	if strings.Contains(joined, "StrictHostKeyChecking=no") {
		t.Error("the options still accept an unknown key")
	}
}

// ssh uses HostKeyAlias verbatim and applies no bracketing of its own, so the
// alias has to be spelled exactly as ssh-keyscan wrote the pin. Measured
// against OpenSSH 10.3p1 with a real sshd: on port 22 ssh-keyscan writes the
// bare name and a bare alias verifies; on any other port it writes
// `[host]:port`, and a bare alias there answers "No ED25519 host key is known
// for <host> and you have requested strict checking" and refuses the
// connection. A bare alias therefore broke every SFTP destination on a
// non-default port, which is most of them.
func TestTheHostKeyAliasMatchesWhatTheScanWrote(t *testing.T) {
	if got := hostKeyAlias("backup.example.com", 22); got != "backup.example.com" {
		t.Errorf("hostKeyAlias(_, 22) = %q, want the bare name ssh-keyscan writes", got)
	}
	if got := hostKeyAlias("backup.example.com", 2222); got != "[backup.example.com]:2222" {
		t.Errorf("hostKeyAlias(_, 2222) = %q, want the bracketed form ssh-keyscan writes", got)
	}
}

// And the two places that build ssh options use it, or the helper is decorative.
func TestBothSSHPathsAliasThroughThePortAwareForm(t *testing.T) {
	body := readBackupsSource(t, "destination.go")
	for _, want := range []string{
		"HostKeyAlias=` + lftpEscape(hostKeyAlias(d.Host, d.Port))",
		"sshHostKeyOptions(knownHosts, hostKeyAlias(d.Host, d.Port))",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("destination.go does not build its alias through hostKeyAlias: %q is missing", want)
		}
	}
}

func readBackupsSource(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name) // #nosec G304 -- a file of this package.
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}

func knownHostsPathFrom(t *testing.T, settings string) string {
	t.Helper()
	const marker = "UserKnownHostsFile="
	_, rest, ok := strings.Cut(settings, marker)
	if !ok {
		t.Fatalf("settings %q carry no known_hosts path", settings)
	}
	end := strings.IndexAny(rest, " \"")
	if end < 0 {
		t.Fatalf("settings %q do not terminate the known_hosts path", settings)
	}
	return rest[:end]
}
