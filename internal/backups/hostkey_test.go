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
	joined := strings.Join(sshHostKeyOptions("/tmp/known"), " ")
	for _, want := range []string{
		"StrictHostKeyChecking=yes",
		"UserKnownHostsFile=/tmp/known",
		"GlobalKnownHostsFile=/dev/null",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("options %q are missing %q", joined, want)
		}
	}
	if strings.Contains(joined, "StrictHostKeyChecking=no") {
		t.Error("the options still accept an unknown key")
	}
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
