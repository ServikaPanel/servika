package system

import (
	"strings"
	"testing"
)

// Both release tools used to fall back to the mutable branch tarball when a
// release tag could not be resolved, when the bundle download failed, or when the
// operator passed --branch. That path could never complete: the server binary is
// built inside the release job and copied into the bundle, and has not been
// committed to the repository since the prebuilt assets were deleted, so the
// branch tarball carries no <arch>/servika-server and every fallback ended at the
// missing-binary check.
//
// servika-restore made it worse: it exists to repair a host that is already
// broken, and its abort said "canonical release is corrupt or incomplete",
// sending the operator after an upstream fault that was not there.
func TestNeitherReleaseToolFetchesTheBranchTarball(t *testing.T) {
	for _, script := range opsScripts {
		body := readScript(t, script)
		if strings.Contains(body, "codeload.github.com") {
			t.Errorf("%s still downloads the branch tarball, which carries no server binary", script)
		}
		if strings.Contains(body, "refs/heads/") {
			t.Errorf("%s still resolves a branch ref as an install source", script)
		}
	}
}

// A documented option must not be a path that always aborts. It is recognised so
// an operator who has it in a runbook is told why it is gone, rather than reading
// "unknown argument".
func TestTheRetiredBranchFlagIsRefusedWithItsReason(t *testing.T) {
	for _, script := range opsScripts {
		body := readScript(t, script)
		if !strings.Contains(body, "--branch|--branch=*)") {
			t.Errorf("%s no longer recognises --branch, so it reports 'unknown argument'", script)
		}
		if !strings.Contains(body, "--branch was removed") {
			t.Errorf("%s refuses --branch without saying why", script)
		}
		// The help text renders the header comment block, so a usage line naming
		// the flag is the tool OFFERING it. Explaining in that block why it is
		// gone is the opposite, and has to stay allowed.
		header, _, _ := strings.Cut(body, "\nset -euo pipefail")
		for line := range strings.SplitSeq(header, "\n") {
			usage := strings.TrimPrefix(strings.TrimSpace(line), "# ")
			if strings.HasPrefix(usage, "servika-") && strings.Contains(usage, "--branch") {
				t.Errorf("%s still offers --branch in its usage: %s", script, usage)
			}
		}
	}
}

// Removing the fallback must not weaken what replaced it: the tagged bundle is
// still verified before anything is installed from it.
func TestBothReleaseToolsStillVerifyTheBundleTheyInstall(t *testing.T) {
	for _, script := range opsScripts {
		body := readScript(t, script)
		if !strings.Contains(body, "verify_release_bundle") {
			t.Errorf("%s installs the release bundle without checking it against SHA256SUMS", script)
		}
		if !strings.Contains(body, "checksum mismatch") {
			t.Errorf("%s no longer reports a checksum mismatch as its own outcome", script)
		}
	}
}

// The three ways the source can fail now end in three different messages, so an
// operator is not sent after the wrong cause. A tag that cannot be resolved is a
// network problem, and used to be reported as a corrupt release.
func TestEachSourceFailureNamesItsOwnCause(t *testing.T) {
	for _, script := range opsScripts {
		body := readScript(t, script)
		for _, message := range []string{
			"could not resolve a release tag",
			"release bundle download failed",
			"could not be unpacked",
		} {
			if !strings.Contains(body, message) {
				t.Errorf("%s does not report %q as its own failure", script, message)
			}
		}
	}
}

// servika-restore runs on a host that is already in trouble, so the one way to
// repair it without reaching GitHub has to stay reachable and be named in the
// messages that replaced the fallback.
func TestTheRepairToolStillOffersItsOfflineSource(t *testing.T) {
	body := readScript(t, "../../assets/ops/servika-restore")
	if !strings.Contains(body, "SERVIKA_ASSETS_OVERRIDE") {
		t.Fatal("servika-restore lost its offline asset source")
	}
	if strings.Count(body, "Set SERVIKA_ASSETS_OVERRIDE") < 2 {
		t.Fatal("the network failures do not point the operator at the offline source")
	}
}
