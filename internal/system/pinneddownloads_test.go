package system

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The Roundcube archive is PHP the panel then serves publicly at /webmail/, so
// the only thing between a tampered download and arbitrary code in that document
// root was the TLS certificate of the download host. It was the one third-party
// download in this repository that skipped the checksum gate the installer
// already applies to wp-cli and phpMyAdmin.
func TestTheRoundcubeArchiveIsVerifiedBeforeItIsExtracted(t *testing.T) {
	script := readScript(t, "../../assets/ops/servika-mail-setup")

	if !strings.Contains(script, "verify_sha256()") {
		t.Fatal("servika-mail-setup carries no checksum helper")
	}
	pin := regexp.MustCompile(`(?m)^RCSHA256="([0-9a-f]{64})"$`)
	if !pin.MatchString(script) {
		t.Fatal("RCSHA256 is missing or is not a 64-character sha256")
	}
	if !strings.Contains(script, `verify_sha256 "$RCARCHIVE" "$RCSHA256"`) {
		t.Fatal("the archive is not checked against the pin")
	}

	// The order is the point: the check has to stand between the download and the
	// extraction, not beside it.
	checkAt := strings.Index(script, `verify_sha256 "$RCARCHIVE"`)
	extractAt := strings.Index(script, `tar xzf "$RCARCHIVE"`)
	if checkAt < 0 || extractAt < 0 {
		t.Fatalf("one of the two steps is missing (check=%d, extract=%d)", checkAt, extractAt)
	}
	if checkAt > extractAt {
		t.Fatal("the archive is extracted before it is verified")
	}
}

// A mismatch is not a download failure. Sharing an outcome with one would let a
// tampered archive be reported as a network problem, which is the message an
// operator ignores.
func TestAChecksumMismatchIsReportedAsItsOwnOutcome(t *testing.T) {
	script := readScript(t, "../../assets/ops/servika-mail-setup")

	if !strings.Contains(script, "checksum mismatch") {
		t.Fatal("a mismatched archive is not reported as a mismatch")
	}
}

// The pin is only a pin if something compares it to upstream. A version bumped
// without its checksum otherwise fails on a customer's server, where the symptom
// is a warning and a missing feature.
func TestTheCheckedInPinIsCoveredByCI(t *testing.T) {
	workflow, err := os.ReadFile("../../.github/workflows/pinned-downloads.yml")
	if err != nil {
		t.Fatalf("read the workflow: %v", err)
	}
	body := string(workflow)

	for _, want := range []string{
		"assets/ops/servika-mail-setup",
		"RCVER",
		"RCSHA256",
		"roundcubemail-${RCVER}-complete.tar.gz",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the pinned-downloads workflow does not mention %q", want)
		}
	}
	// The path filter as well as the check: a job that never runs on the file
	// carrying the pin verifies nothing.
	if strings.Count(body, "assets/ops/servika-mail-setup") < 3 {
		t.Error("the workflow checks the pin but does not run on the file that carries it")
	}
}
