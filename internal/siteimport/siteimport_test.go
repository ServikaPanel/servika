package siteimport

import (
	"os"
	"strings"
	"testing"
)

// Every reader of a staged archive must address the PINNED descriptor.
//
// The staging directory and the file in it are created beneath the home and
// chowned to the tenant, so the tenant owns both and can unlink the file and
// leave a symlink in its place. A path string checked once and resolved again by
// each reader is not a boundary: between the check and the tar branch's second
// root-side open lie a mkdir, an optional clear, an optional full summary pass
// and the whole validation scan, and the tar branch pipes what it opens into an
// extractor. Any root-readable file on the host was reachable that way.
func TestEveryArchiveReaderUsesThePinnedDescriptor(t *testing.T) {
	source, err := os.ReadFile("archive.go")
	if err != nil {
		t.Fatalf("read the package source: %v", err)
	}
	readers := 0
	for line := range strings.SplitSeq(string(source), "\n") {
		if !strings.Contains(line, "archivex.Summarize(") && !strings.Contains(line, "archivex.ExtractStrip(") {
			continue
		}
		readers++
		if !strings.Contains(line, "archive.Pinned") {
			t.Errorf("an archive reader resolves a path instead of the pinned descriptor:\n%s", strings.TrimSpace(line))
		}
	}
	if readers < 2 {
		t.Fatalf("found %d archive readers, want the summary and the extraction: the scan no longer covers them", readers)
	}
}

// The pinned path addresses the descriptor, so it must be built from the open
// file rather than from anything the caller supplied.
func TestOpenStagedArchiveRefusesAnIDThatIsNotGenerated(t *testing.T) {
	for _, bad := range []string{
		"../" + strings.Repeat("a", 32) + ".zip",
		strings.Repeat("a", 32),
		"/etc/passwd",
		"",
	} {
		if _, err := openStagedArchive("/home/c_site", bad); err == nil {
			t.Errorf("openStagedArchive() accepted the staging id %q", bad)
		}
	}
}

// The staging id is generated, never taken from the upload, so a crafted file
// name reaches the filesystem only as an extension.
func TestNewStageIDIgnoresTheUploadedName(t *testing.T) {
	id, err := newStageID("../../etc/cron.d/evil.tar.gz")
	if err != nil {
		t.Fatalf("newStageID() = %v, want nil", err)
	}
	if !reStageID.MatchString(id) {
		t.Errorf("stage id %q does not match the accepted pattern", id)
	}
	if strings.ContainsAny(id, "/\\.") != strings.Contains(id, ".") {
		t.Errorf("stage id %q carries a path component", id)
	}
	if strings.Contains(id, "etc") || strings.Contains(id, "cron") {
		t.Errorf("stage id %q kept part of the uploaded name", id)
	}
	if !strings.HasSuffix(id, ".tar.gz") {
		t.Errorf("stage id %q lost the archive extension", id)
	}
}

func TestNewStageIDRefusesAnUnsupportedExtension(t *testing.T) {
	for _, name := range []string{"site.php", "site", "site.tar.gz.php", "site.sql"} {
		if _, err := newStageID(name); err == nil {
			t.Errorf("newStageID(%q) = nil error, want a refusal", name)
		}
	}
}

// A staging id is the only thing a caller supplies to reach a staged file, so
// the pattern has to exclude anything that could address another path.
func TestStageIDPatternRejectsEverythingButAGeneratedID(t *testing.T) {
	valid := strings.Repeat("a", 32) + ".zip"
	if !reStageID.MatchString(valid) {
		t.Fatalf("the pattern rejects a generated id: %q", valid)
	}
	for _, bad := range []string{
		"../" + valid,
		strings.Repeat("a", 32) + ".zip/../../etc/passwd",
		strings.Repeat("a", 31) + ".zip",
		strings.Repeat("g", 32) + ".zip",
		strings.Repeat("a", 32) + ".php",
		strings.Repeat("a", 32),
		"/etc/passwd",
	} {
		if reStageID.MatchString(bad) {
			t.Errorf("the pattern accepts %q", bad)
		}
	}
}

// Extracting an archive over its own staging area cannot be what a caller
// means, and would destroy the source mid-extraction.
func TestTargetDirectoryRefusesTheWorkArea(t *testing.T) {
	for _, requested := range []string{stagingDir, stagingDir + "/nested", "./" + stagingDir} {
		if _, err := targetDirectory(requested); err == nil {
			t.Errorf("targetDirectory(%q) = nil error, want a refusal", requested)
		}
	}
}

func TestTargetDirectoryRefusesTheHomeItself(t *testing.T) {
	for _, requested := range []string{"/", ".", "..", "/../.."} {
		if got, err := targetDirectory(requested); err == nil {
			t.Errorf("targetDirectory(%q) = %q, want a refusal", requested, got)
		}
	}
}

func TestTargetDirectoryNormalisesAndDefaults(t *testing.T) {
	cases := map[string]string{
		"":                    "public_html",
		"   ":                 "public_html",
		"public_html":         "public_html",
		"/public_html/":       "public_html",
		"public_html/../apps": "apps",
		`sub\dir`:             "sub/dir",
		"../../../etc":        "etc",
	}
	for requested, want := range cases {
		got, err := targetDirectory(requested)
		if err != nil {
			t.Errorf("targetDirectory(%q) = %v, want %q", requested, err, want)
			continue
		}
		if got != want {
			t.Errorf("targetDirectory(%q) = %q, want %q", requested, got, want)
		}
	}
}

// A PHP single-quoted string treats only the backslash and the quote as
// special, and Go's replacement treats $ as a group reference. A password
// carrying either would otherwise be written wrong and break the site the
// rewrite is meant to fix.
func TestPHPLiteralEscapesQuotesBackslashesAndGroupReferences(t *testing.T) {
	if got, want := phpLiteral(`a'b\c`), `a\'b\\c`; got != want {
		t.Errorf("phpLiteral() = %q, want %q", got, want)
	}
	if got, want := phpLiteralForTemplate(`p$1x`), `p$$1x`; got != want {
		t.Errorf("phpLiteralForTemplate() = %q, want %q", got, want)
	}
}

func TestWPDefinePatternMatchesBothQuoteStyles(t *testing.T) {
	pattern := wpDefinePattern("DB_PASSWORD")
	for _, line := range []string{
		`define('DB_PASSWORD', 'old');`,
		`define( "DB_PASSWORD" , "old" );`,
		`DEFINE('db_password','old');`,
		`define('DB_PASSWORD', 'has \' escaped quote');`,
	} {
		if !pattern.MatchString(line) {
			t.Errorf("the pattern misses %q", line)
		}
	}
	// A constant whose value comes from a variable or getenv is left alone
	// rather than rewritten into something that no longer parses.
	for _, line := range []string{
		`define('DB_PASSWORD', getenv('DB_PASSWORD'));`,
		`define('DB_PASSWORD', $password);`,
		`define('DB_NAME', 'old');`,
	} {
		if pattern.MatchString(line) {
			t.Errorf("the pattern wrongly matches %q", line)
		}
	}
}

// The rewritten value has to survive a dotenv parser, which means quoting
// anything carrying whitespace or its own syntax characters.
func TestDotEnvValueQuotesOnlyWhenItMustAndEscapesWhenItDoes(t *testing.T) {
	cases := map[string]string{
		"simple":     "simple",
		"c_user_db":  "c_user_db",
		"":           `""`,
		"has space":  `"has space"`,
		`has"quote`:  `"has\"quote"`,
		`has$dollar`: `"has\$dollar"`,
		`has\slash`:  `"has\\slash"`,
		"has#hash":   `"has#hash"`,
	}
	for value, want := range cases {
		if got := dotEnvValue(value); got != want {
			t.Errorf("dotEnvValue(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestImportFailureIsBoundedAndNeverEmpty(t *testing.T) {
	if got := importFailure(errString("")); !strings.Contains(got, "could not be imported") {
		t.Errorf("importFailure(empty) = %q", got)
	}
	long := importFailure(errString(strings.Repeat("x", 5000)))
	if len(long) > 500 {
		t.Errorf("importFailure() returned %d bytes; a failing dump must not size the response", len(long))
	}
	if !strings.HasSuffix(long, "…") {
		t.Error("a truncated failure does not say it was truncated")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
