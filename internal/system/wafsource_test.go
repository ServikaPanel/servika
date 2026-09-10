package system

import (
	"regexp"
	"strings"
	"testing"
)

const wafSetup = "../../assets/ops/servika-waf-setup"

// The nginx source tree this script downloads is compiled AS ROOT into a shared
// object that nginx loads into its master and every worker: the process that
// terminates TLS and serves every hosted site. Nothing verified what arrived, so
// the only control was the TLS certificate of nginx.org at download time.
func TestTheNginxSourceIsVerifiedBeforeItIsBuilt(t *testing.T) {
	script := readScript(t, wafSetup)

	if !strings.Contains(script, "verify_nginx_source") {
		t.Fatal("the nginx source is not verified at all")
	}

	// The order is the point: the check has to stand between the download and
	// everything that compiles what the tarball contains.
	downloadAt := strings.Index(script, `wget -qO "$SRC/nginx-$NGVER.tar.gz"`)
	verifyAt := strings.Index(script, `verify_nginx_source "$SRC/nginx-$NGVER.tar.gz"`)
	extractAt := strings.Index(script, `tar xzf "$SRC/nginx-$NGVER.tar.gz"`)
	if downloadAt < 0 || verifyAt < 0 || extractAt < 0 {
		t.Fatalf("a step is missing (download=%d, verify=%d, extract=%d)", downloadAt, verifyAt, extractAt)
	}
	if downloadAt >= verifyAt || verifyAt >= extractAt {
		t.Fatal("the source is extracted before it is verified")
	}
}

// A tarball left behind after a failed check is one the next run finds already
// downloaded and builds from without asking again.
func TestARefusedSourceIsRemoved(t *testing.T) {
	script := readScript(t, wafSetup)

	verifyAt := strings.Index(script, "if ! verify_nginx_source")
	if verifyAt < 0 {
		t.Fatal("the verification is not a refusal branch")
	}
	branch := script[verifyAt:min(verifyAt+600, len(script))]
	if !strings.Contains(branch, `rm -f "$SRC/nginx-$NGVER.tar.gz"`) {
		t.Fatalf("a refused tarball is left on disk:\n%s", branch)
	}
	if !strings.Contains(branch, "die ") {
		t.Fatalf("a refused source does not stop the build:\n%s", branch)
	}
}

// Importing whatever nginx.org serves would add nothing: the same host serves
// the tarball, the signature and the key, so a swapped key would sign a swapped
// tarball. The fingerprints are what make the check mean something.
func TestTheSigningKeysArePinnedByFingerprint(t *testing.T) {
	script := readScript(t, wafSetup)

	block := regexp.MustCompile(`(?s)NGINX_KEY_FPRS="(.*?)"`).FindStringSubmatch(script)
	if block == nil {
		t.Fatal("no pinned fingerprint list")
	}
	fingerprint := regexp.MustCompile(`^[0-9A-F]{40}$`)
	count := 0
	for line := range strings.SplitSeq(block[1], "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !fingerprint.MatchString(trimmed) {
			t.Errorf("%q is not a 40-character uppercase fingerprint", trimmed)
		}
		count++
	}
	// The five key files nginx.org lists, and the three keys the repository key
	// file carries.
	if count < 5 {
		t.Errorf("only %d fingerprints are pinned; nginx publishes more signers than that", count)
	}
	if !strings.Contains(script, "NGINX_KEY_FPRS") || !strings.Contains(script, "was not imported") {
		t.Error("an unpinned key is not refused with a reason")
	}
}

// gpg has to be present for the check to run at all, so the build's own package
// step installs it.
func TestTheVerificationToolIsInstalledWithTheBuildDependencies(t *testing.T) {
	script := readScript(t, wafSetup)

	line := regexp.MustCompile(`(?m)^\s*dnf install -y gcc make wget git.*$`).FindString(script)
	if line == "" {
		t.Fatal("the connector build no longer installs its dependencies")
	}
	if !strings.Contains(line, "gnupg2") {
		t.Fatalf("gpg is not installed with the build dependencies: %s", strings.TrimSpace(line))
	}
}
