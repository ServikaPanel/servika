package wordpress

import (
	"errors"
	"os"
	"testing"
)

// The five outcomes of `wp core verify-checksums`, captured from WP-CLI 2.12.0
// against a real WordPress 7.1 installation. The exit status is part of the
// capture because it is half of what the rule reads, and because two of these
// rows share a status while meaning opposite things.
var realOutcomes = []struct {
	name     string
	exitErr  error
	output   string
	measured bool
}{
	{
		name:     "clean installation, wordpress.org reachable",
		exitErr:  nil,
		output:   "Success: WordPress installation verifies against checksums.",
		measured: true,
	},
	{
		// An extra file is the webshell case this endpoint exists to catch, and
		// the command exits ZERO for it. So "exit 0 means clean" is false, and a
		// rule built on the status alone would be wrong in the direction that
		// matters most.
		name:     "extra file only, wordpress.org reachable",
		exitErr:  nil,
		output:   "Warning: File should not exist: wp-includes/pluggable.php.bak_test\nSuccess: WordPress installation verifies against checksums.",
		measured: true,
	},
	{
		name:    "modified core file, wordpress.org reachable",
		exitErr: errors.New("exit status 1"),
		output: "Warning: File doesn't verify against checksum: wp-includes/pluggable.php\n" +
			"Error: WordPress installation doesn't verify against checksums.",
		measured: true,
	},
	{
		name:    "api.wordpress.org unreachable",
		exitErr: errors.New("exit status 1"),
		output: "Error: RuntimeException: Failed to get url " +
			"'https://api.wordpress.org/core/checksums/1.0/?version=7.1&locale=tr_TR': " +
			"cURL error 7: Failed to connect to api.wordpress.org port 443 after 0 ms: Could not connect to server.",
		measured: false,
	},
	{
		name:     "a version wordpress.org never published",
		exitErr:  errors.New("exit status 1"),
		output:   "Error: Couldn't get checksums from WordPress.org.",
		measured: false,
	},
}

// The endpoint used to discard the command's error entirely, so the last two
// rows produced zero verdicts and the screen reported the core as matching the
// official checksums. Zero findings and no comparison are the same JSON and are
// not the same fact.
func TestACheckThatComparedNothingIsNotReportedAsClean(t *testing.T) {
	for _, outcome := range realOutcomes {
		verdicts := parseChecksumReport(outcome.output)
		if got := commandMeasured(outcome.exitErr, verdicts); got != outcome.measured {
			t.Errorf("%s: measured = %v, want %v", outcome.name, got, outcome.measured)
		}
	}
}

// The rule is not vacuous in either direction: three of the five rows above are
// measured and two are not, and one measured row carries a zero exit while
// another carries a non-zero one.
func TestTheMeasuredRuleSeparatesBothWays(t *testing.T) {
	var measured, unmeasured int
	for _, outcome := range realOutcomes {
		if outcome.measured {
			measured++
		} else {
			unmeasured++
		}
	}
	if measured < 2 || unmeasured < 2 {
		t.Fatalf("the outcome table proves too little: %d measured, %d not", measured, unmeasured)
	}
	// A failure whose output still names a file is a real finding, so the error
	// alone cannot be the test.
	dirty := parseChecksumReport(realOutcomes[2].output)
	if len(dirty) != 1 {
		t.Fatalf("the modified-file capture parsed %d verdicts, want 1", len(dirty))
	}
	if !commandMeasured(errors.New("exit status 1"), dirty) {
		t.Error("a non-zero exit that named a file was treated as unmeasured")
	}
	if commandMeasured(errors.New("exit status 1"), nil) {
		t.Error("a non-zero exit that named nothing was treated as measured")
	}
}

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
