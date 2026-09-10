package system

import (
	"regexp"
	"strings"
	"testing"
)

// releaseConsumers are the three entry points into the release channel. All
// three install the same artefact as root, so a control present in two of them
// is only as strong as the third.
var releaseConsumers = []string{
	"../../install.sh",
	"../../assets/ops/servika-update",
	"../../assets/ops/servika-restore",
}

// SHA256SUMS and the bundle it describes are published to the SAME release, so a
// checksum verified against a list from the same place proves only that the
// download was not corrupted in transit. The signature is what says who produced
// it, and servika-restore had the checksum without it: the tool an operator runs
// on a host they already suspect has been tampered with.
func TestEveryReleaseConsumerVerifiesTheSignature(t *testing.T) {
	for _, path := range releaseConsumers {
		body := readScript(t, path)
		for _, want := range []string{
			"SERVIKA_RELEASE_PUBKEY",
			"verify_release_signature",
			"openssl pkeyutl -verify -pubin",
			"SHA256SUMS.sig",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s is missing %q", path, want)
			}
		}
	}
}

// "Verify it if the .sig is present" is not a check: an attacker who can replace
// the artefacts can simply not publish one. With a key embedded, an absent
// signature has to fail.
func TestAnAbsentSignatureFailsOnceAKeyIsSet(t *testing.T) {
	for _, path := range releaseConsumers {
		body := readScript(t, path)
		// The line belongs to verify_release_signature and appears nowhere else in
		// these scripts, so matching the file is matching that function. The
		// bootstrap installer dies inline where the two ops tools return non-zero
		// for their caller to judge, so both shapes are accepted.
		refusesEmpty := strings.Contains(body, `[ -s "$sig_path" ] || return 1`) ||
			strings.Contains(body, `[ -s "$sig_path" ] || die `)
		if !refusesEmpty {
			t.Errorf("%s accepts an empty or absent signature file", path)
		}
		// And the empty key is the only thing that skips the step.
		if !strings.Contains(body, `[ -n "$SERVIKA_RELEASE_PUBKEY" ] || return 0`) {
			t.Errorf("%s does not skip the step only for an unset key", path)
		}
	}
}

// The three copies of the key have to agree, or setting it in one place leaves
// the other paths unverified, which is the defect this closes.
func TestTheEmbeddedKeyIsIdenticalInEveryConsumer(t *testing.T) {
	pin := regexp.MustCompile(`(?m)^SERVIKA_RELEASE_PUBKEY='([^']*)'$`)

	var first string
	for i, path := range releaseConsumers {
		match := pin.FindStringSubmatch(readScript(t, path))
		if match == nil {
			t.Fatalf("%s does not assign SERVIKA_RELEASE_PUBKEY on its own line", path)
		}
		if i == 0 {
			first = match[1]
			continue
		}
		if match[1] != first {
			t.Errorf("%s embeds a different key from %s", path, releaseConsumers[0])
		}
	}
}

// A signature that does not hold says SHA256SUMS is not the one the maintainer
// signed, so comparing the bundle against it proves nothing. The signature has
// to be judged first, and its failure has to stop the run.
func TestTheSignatureIsJudgedBeforeTheChecksum(t *testing.T) {
	for _, path := range []string{"../../assets/ops/servika-update", "../../assets/ops/servika-restore"} {
		body := readScript(t, path)
		signatureAt := strings.Index(body, "verify_release_signature \"$TMP/SHA256SUMS\"")
		checksumAt := strings.Index(body, "verify_release_bundle \"$TMP/$BUNDLE\"")
		if signatureAt < 0 || checksumAt < 0 {
			t.Errorf("%s: a step is missing (signature=%d, checksum=%d)", path, signatureAt, checksumAt)
			continue
		}
		if signatureAt > checksumAt {
			t.Errorf("%s judges the checksum before the signature that authenticates it", path)
		}
		// The failure is fatal, never a reason to reach for an unverified source.
		branch := body[signatureAt:min(signatureAt+700, len(body))]
		if !strings.Contains(branch, "die ") {
			t.Errorf("%s does not stop on a signature failure:\n%s", path, branch)
		}
	}
}
