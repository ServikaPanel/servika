package git

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// The tenant ssh config used to carry StrictHostKeyChecking no with
// UserKnownHostsFile=/dev/null, so every clone and fetch the panel ran as the
// tenant accepted whatever host key was presented and recorded nothing. An
// attacker with a network position between the panel and github.com could
// present their own key, be accepted silently, and serve an arbitrary
// repository into the tenant's document root, which the clone empties first.
func TestTheTenantSSHConfigVerifiesTheHostKey(t *testing.T) {
	if strings.Contains(sshConfigBody, "StrictHostKeyChecking no") {
		t.Error("the tenant config still accepts any host key")
	}
	if strings.Contains(sshConfigBody, "/dev/null") && !strings.Contains(sshConfigBody, "GlobalKnownHostsFile /dev/null") {
		t.Error("the tenant config still throws the known_hosts file away")
	}
	for _, want := range []string{
		"StrictHostKeyChecking yes",
		"UserKnownHostsFile ~/.ssh/servika_known_hosts",
		// Closed too, or a key trusted on this host for some unrelated purpose
		// would satisfy the check.
		"GlobalKnownHostsFile /dev/null",
	} {
		if !strings.Contains(sshConfigBody, want) {
			t.Errorf("the tenant config is missing %q", want)
		}
	}
}

// The pinned lines must be the keys GitHub publishes. The fingerprints are the
// ones served beside them at https://api.github.com/meta, so this compares the
// shipped material against a value that was written down independently of it.
func TestThePinnedKeysMatchTheirPublishedFingerprints(t *testing.T) {
	published := map[string]string{
		"ssh-ed25519":         "+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
		"ecdsa-sha2-nistp256": "p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",
		"ssh-rsa":             "uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
	}
	seen := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(githubHostKeys), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("a pinned line is not host/type/key: %q", line)
		}
		host, keyType, material := fields[0], fields[1], fields[2]
		if host != "github.com" {
			t.Errorf("a pinned line names %q rather than github.com", host)
		}
		want, known := published[keyType]
		if !known {
			t.Errorf("%s is pinned but has no published fingerprint to check against", keyType)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(material)
		if err != nil {
			t.Errorf("the %s key is not valid base64: %v", keyType, err)
			continue
		}
		sum := sha256.Sum256(raw)
		got := strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
		if got != want {
			t.Errorf("the pinned %s key has fingerprint SHA256:%s, want SHA256:%s", keyType, got, want)
		}
		seen[keyType] = true
	}
	// All three, so a single upstream rotation does not stop every deployment.
	for keyType := range published {
		if !seen[keyType] {
			t.Errorf("%s is not pinned, so a rotation of another type leaves nothing to fall back to", keyType)
		}
	}
}

// generateDeployKey returns early for a tenant that already has a key, so the
// trust files have to be written BEFORE that return. Without it, a host
// installed before this change would keep the configuration that disables
// verification for the life of the installation.
func TestTheTrustFilesAreWrittenForATenantThatAlreadyHasAKey(t *testing.T) {
	body, err := os.ReadFile("git.go") // #nosec G304 -- a file of this package.
	if err != nil {
		t.Fatalf("read git.go: %v", err)
	}
	generate := sourceFunction(t, string(body), "func generateDeployKey(")

	write := strings.Index(generate, "writeSSHTrust(home, systemUser)")
	reuse := strings.Index(generate, "Reuse the current key")
	if write < 0 {
		t.Fatal("generateDeployKey never installs the pinned host keys")
	}
	if reuse < 0 {
		t.Fatal("the early return for an existing key is gone; this test is out of date")
	}
	if write > reuse {
		t.Error("the trust files are written after the early return, so an existing tenant never gets them")
	}
}
