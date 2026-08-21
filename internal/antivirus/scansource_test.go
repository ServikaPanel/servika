package antivirus

// Every scan the panel records has to say who started it.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// av_scans.source defaults to 'unknown', which belongs to rows written before
// the column existed. A write site that forgets the column therefore lands on
// that default in SILENCE: nothing fails, and the screen reports a scan nobody
// can trace as one nobody measured.
//
// This walks the package rather than listing the sites, because the failure is a
// site that was ADDED without the column and a list would not know about it.
func TestEveryScanRecordSaysWhoStartedIt(t *testing.T) {
	// The statement is written across two lines at most of the sites, so the
	// file is flattened before matching.
	insert := regexp.MustCompile(`INSERT\s+INTO\s+av_scans\s*\(([^)]*)\)`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		flat := strings.Join(strings.Fields(string(source)), " ")
		for _, match := range insert.FindAllStringSubmatch(flat, -1) {
			found++
			if !strings.Contains(match[1], "source") {
				t.Errorf("%s records a scan without naming its source: INSERT INTO av_scans (%s)", name, match[1])
			}
		}
	}
	// A pass that matched nothing would report every future site as correct.
	if found < 5 {
		t.Fatalf("only %d av_scans write sites were found; the search is not reaching them", found)
	}
}

// The values are the ones the screen has words for. A sixth spelling at a sixth
// site is a value nothing can draw, and nothing would report the drift.
func TestTheScanSourcesAreTheOnesTheScreenKnows(t *testing.T) {
	for _, value := range []string{SourceManual, SourceScheduled, SourceTimer, SourceRealtime, SourceUnknown} {
		if value == "" || len(value) > 16 {
			t.Errorf("%q does not fit av_scans.source, which is VARCHAR(16)", value)
		}
	}
	// Nothing writes SourceUnknown: it is the column default and means the row
	// predates the column, which is a different claim from "started by hand".
	source, err := os.ReadFile("scansource.go")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "scansource.go" {
			continue
		}
		body, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "SourceUnknown") {
			t.Errorf("%s writes SourceUnknown, which would claim a row was measured as unmeasurable", name)
		}
	}
	_ = source
}
