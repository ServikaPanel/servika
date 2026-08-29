package phpversion

import "testing"

// TestParseRemiFPMVersions proves the parse keeps only phpXX-php-fpm names,
// dedupes by code, rejects noise (a bare php-fpm, a -cli sibling, blanks), and
// reads a TWO-DIGIT minor (php810-php-fpm = 8.10) that the old two-single-digit
// regex dropped silently.
func TestParseRemiFPMVersions(t *testing.T) {
	out := "php83-php-fpm\nphp84-php-fpm\nphp90-php-fpm\nphp83-php-fpm\n" + // duplicate
		"php-fpm\nphp83-php-cli\nphp84-php-common\n\n  php85-php-fpm  \n" +
		"php810-php-fpm\nphp8-php-fpm\n" // two-digit minor kept; a minorless "php8" dropped
	got := parseRemiFPMVersions(out)
	want := []VersionMetadata{
		{"8.3", "83", "remi"},
		{"8.4", "84", "remi"},
		{"9.0", "90", "remi"},
		{"8.5", "85", "remi"},
		{"8.10", "810", "remi"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d versions, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestParseRemiFPMVersionsEmpty proves an empty repoquery output yields no
// versions, so the caller falls back to the fixed SupportedVersions.
func TestParseRemiFPMVersionsEmpty(t *testing.T) {
	if got := parseRemiFPMVersions(""); got != nil {
		t.Fatalf("empty output should yield nil, got %+v", got)
	}
}

// TestMergedMetadataAddsAndDedupes proves discovery ADDS a new Remi version and
// never duplicates one the fixed list already names.
func TestMergedMetadataAddsAndDedupes(t *testing.T) {
	discoveredMu.Lock()
	prev := discoveredCache
	discoveredCache = []VersionMetadata{
		{"8.3", "83", "remi"}, // already in SupportedVersions → must not duplicate
		{"9.0", "90", "remi"}, // new → must be added once
	}
	discoveredMu.Unlock()
	t.Cleanup(func() {
		discoveredMu.Lock()
		discoveredCache = prev
		discoveredMu.Unlock()
	})

	merged := mergedMetadata()
	count83, count90 := 0, 0
	for _, m := range merged {
		if m.Resource == "remi" && m.Code == "83" {
			count83++
		}
		if m.Resource == "remi" && m.Code == "90" {
			count90++
		}
	}
	if count83 != 1 {
		t.Errorf("remi 8.3 appears %d times, want 1 (no duplicate of a fixed version)", count83)
	}
	if count90 != 1 {
		t.Errorf("discovered remi 9.0 appears %d times, want 1", count90)
	}
	if len(merged) != len(SupportedVersions)+1 {
		t.Errorf("merged has %d entries, want %d (fixed + one discovered)", len(merged), len(SupportedVersions)+1)
	}
}
