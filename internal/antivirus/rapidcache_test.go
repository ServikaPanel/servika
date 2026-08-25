package antivirus

import (
	"os"
	"path/filepath"
	"testing"
)

// The fingerprint is what stops the cache skipping a file on a judgement that no
// longer holds, so what it covers and what it deliberately does not are both
// pinned here.

func TestTurningTheContentRulesOffChangesTheFingerprint(t *testing.T) {
	// The escape this closes: sweep once with rule_engine off (every file then
	// judged on its path alone and recorded clean), turn it back on, and without
	// this every unchanged file is skipped for good on a judgement earned with
	// the content rules disabled.
	off := ScanRequest{RuleEngine: false, LocationHeuristics: true}
	on := ScanRequest{RuleEngine: true, LocationHeuristics: true}
	if cacheFingerprint(off) == cacheFingerprint(on) {
		t.Fatal("rule_engine does not reach the fingerprint, so a sweep run with the content rules off would let the next sweep skip every unchanged file")
	}
}

func TestTurningTheLocationRulesOffChangesTheFingerprint(t *testing.T) {
	off := ScanRequest{RuleEngine: true, LocationHeuristics: false}
	on := ScanRequest{RuleEngine: true, LocationHeuristics: true}
	if cacheFingerprint(off) == cacheFingerprint(on) {
		t.Fatal("location_heuristics does not reach the fingerprint")
	}
}

func TestTheCriticalThresholdIsDeliberatelyNotInTheFingerprint(t *testing.T) {
	// Only a file whose level came back "" is recorded, and levelFor clamps its
	// threshold argument up to scoreSuspicious before comparing, so a recorded
	// file scored below scoreSuspicious and no threshold an operator can set
	// turns it into a finding. Including it would throw the whole cache away
	// every time somebody moved a slider that cannot change the answer.
	low := ScanRequest{RuleEngine: true, LocationHeuristics: true, CriticalThreshold: 50}
	high := ScanRequest{RuleEngine: true, LocationHeuristics: true, CriticalThreshold: 100}
	if cacheFingerprint(low) != cacheFingerprint(high) {
		t.Fatal("critical_threshold reaches the fingerprint, which discards the cache for a setting that cannot change a recorded file's verdict")
	}

	// The clamp that makes the above safe, measured rather than asserted from
	// the comment: a score under scoreSuspicious is clean at EVERY threshold,
	// including one below it.
	for _, threshold := range []int{0, 1, 49, 50, 100, 10000} {
		if level := levelFor(scoreSuspicious-1, threshold); level != "" {
			t.Fatalf("a score of %d was called %q at threshold %d; the cache records such files as clean",
				scoreSuspicious-1, level, threshold)
		}
	}
}

func TestAStaleFingerprintDiscardsTheWholeCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rapidscan.json")
	if err := storeRapidCache(path, "one", map[string]string{"/home/c_a/x.php": "1:2:3"}); err != nil {
		t.Fatalf("store: %v", err)
	}
	if got := loadRapidCache(path, "one"); len(got) != 1 {
		t.Fatalf("the cache did not survive its own fingerprint: %v", got)
	}
	if got := loadRapidCache(path, "two"); got != nil {
		t.Fatalf("a cache written under another fingerprint was read: %v", got)
	}
}

func TestAnUnreadableCacheMeansEveryFileIsInspected(t *testing.T) {
	dir := t.TempDir()

	// Absent.
	if got := loadRapidCache(filepath.Join(dir, "missing.json"), "fp"); got != nil {
		t.Fatalf("a missing cache answered %v", got)
	}
	// Not JSON.
	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadRapidCache(broken, "fp"); got != nil {
		t.Fatalf("a corrupt cache answered %v", got)
	}
	// A directory where a file belongs.
	if got := loadRapidCache(dir, "fp"); got != nil {
		t.Fatalf("a directory answered %v", got)
	}
}

func TestTheCacheIsWrittenPrivately(t *testing.T) {
	// It names every path under every tenant home on the server, so it is not
	// readable by the c_* accounts those homes belong to.
	dir := filepath.Join(t.TempDir(), "av")
	path := filepath.Join(dir, "rapidscan.json")
	if err := storeRapidCache(path, "fp", map[string]string{"/home/c_a/x.php": "1:2:3"}); err != nil {
		t.Fatalf("store: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("the cache file is %o, not 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("the cache directory is %o, not 0700", di.Mode().Perm())
	}
	// Nothing is left beside it: a half-written temporary file carrying the same
	// listing would be readable for as long as it stayed there.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "rapidscan.json" {
		t.Fatalf("the cache directory holds %d entries, not the cache alone", len(entries))
	}
}

func TestAnEmptyKeyNeitherMatchesNorIsStored(t *testing.T) {
	// fileKey answers "" on a platform that hands back no *syscall.Stat_t and on
	// a stat that could not be read. Such a file must reach the rules rather
	// than be compared on a weaker key.
	c := &scanCache{old: map[string]string{"/a": ""}, fresh: map[string]string{}}
	if c.unchanged("/a", "") {
		t.Fatal("an empty key matched an empty stored key, so a file with no readable stat would be skipped")
	}
	c.markClean("/a", "")
	if len(c.fresh) != 0 {
		t.Fatalf("an empty key was stored: %v", c.fresh)
	}
}

func TestAScanWithNoCacheFileNeitherReadsNorWrites(t *testing.T) {
	// This is what a per-domain scan and the real-time watcher get.
	c := newScanCache(ScanRequest{})
	if c != nil {
		t.Fatal("a request naming no cache file built one")
	}
	if c.unchanged("/a", "1:2:3") {
		t.Fatal("the absent cache reported a file as unchanged")
	}
	c.markClean("/a", "1:2:3")
	if err := c.save(ScanRequest{}); err != nil {
		t.Fatalf("saving the absent cache failed: %v", err)
	}
}
