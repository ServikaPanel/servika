package wordpress

import (
	"os"
	"testing"
)

// The fixture is a REAL capture from WP-CLI 2.12.0 against WordPress 6.5.5, not
// a hand-written file: the wording, the stream and the absence of a
// machine-readable format are all things only the tool can prove, and a
// hand-written fixture would encode what the parser already assumes.
func TestTheRealReportYieldsOneVerdictPerWarning(t *testing.T) {
	output, err := os.ReadFile("testdata/wp-verify-checksums.txt")
	if err != nil {
		t.Fatal(err)
	}
	got := parseChecksumReport(string(output))

	want := []verdict{
		{Signature: SignatureMissing, Rel: "wp-includes/blocks/index.php"},
		{Signature: SignatureModified, Rel: "wp-includes/version.php"},
		{Signature: SignatureExtraFile, Rel: "wp-includes/js/tinymce/a b.php"},
		{Signature: SignatureExtraFile, Rel: "wp-admin/evil.php"},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d verdicts, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("verdict %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// The summary line says the installation does not verify. Turning it into a
// finding would report one extra file that does not exist on every check.
func TestTheSummaryLineIsNotAFinding(t *testing.T) {
	for _, line := range []string{
		"Error: WordPress installation doesn't verify against checksums.",
		"Success: WordPress installation verifies against checksums.",
		"Warning: Could not fetch checksums from WordPress.org.",
		"",
	} {
		if got := parseChecksumReport(line); len(got) != 0 {
			t.Errorf("parseChecksumReport(%q) produced %+v", line, got)
		}
	}
}

// A path that carries a space is kept whole. Splitting the line on whitespace
// would truncate a legitimate WordPress path and point the finding at a file
// that is not the one wp-cli named.
func TestAPathWithASpaceSurvivesIntact(t *testing.T) {
	got := parseChecksumReport("Warning: File should not exist: wp-content/mu plugins/x.php")
	if len(got) != 1 || got[0].Rel != "wp-content/mu plugins/x.php" {
		t.Errorf("parsed %+v, want the whole path", got)
	}
}

// wp-cli's output is third-party text for this purpose, so a path that climbs
// out of the installation is dropped rather than repaired.
func TestAPathThatClimbsOutIsDropped(t *testing.T) {
	for _, line := range []string{
		"Warning: File should not exist: ../../../etc/shadow",
		"Warning: File should not exist: ..",
		"Warning: File should not exist: /etc/shadow",
		"Warning: File doesn't verify against checksum: ../outside.php",
		"Warning: File should not exist: ",
	} {
		if got := parseChecksumReport(line); len(got) != 0 {
			t.Errorf("parseChecksumReport(%q) produced %+v", line, got)
		}
	}
}

// A path that merely CONTAINS "..", such as a directory really named "..cache",
// is still a legitimate path and must not be dropped with the climbing ones.
func TestAPathThatOnlyContainsDotsIsKept(t *testing.T) {
	got := parseChecksumReport("Warning: File should not exist: wp-content/..cache/x.php")
	if len(got) != 1 || got[0].Rel != "wp-content/..cache/x.php" {
		t.Errorf("parsed %+v, want the path kept", got)
	}
}

// The three verdicts are distinct actions, so the signatures must stay distinct
// and stable: the screen groups by them and only the extra-file one is
// quarantined.
func TestTheThreeSignaturesAreDistinctAndStable(t *testing.T) {
	if SignatureExtraFile != "WP.Core.ExtraFile" ||
		SignatureModified != "WP.Core.Modified" ||
		SignatureMissing != "WP.Core.Missing" {
		t.Error("a signature name changed; the screen and the stored findings depend on these")
	}
	seen := map[string]bool{}
	for _, candidate := range checksumPrefixes {
		if seen[candidate.signature] {
			t.Errorf("two prefixes map to %s", candidate.signature)
		}
		seen[candidate.signature] = true
	}
	if len(seen) != 3 {
		t.Errorf("the report maps %d signatures, want 3", len(seen))
	}
}
