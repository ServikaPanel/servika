//go:build linux

package antivirus

// The cache is a GATE on the scan, so what it lets past is measured against a
// real filesystem rather than reasoned about. Linux only, because ctime is what
// carries the whole property and only a real *syscall.Stat_t has one.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// webshell is a file the shipped rule set convicts on its own. The comment pads
// it to exactly the length of cleanPHP, so an in-place edit that swaps one for
// the other leaves the file's SIZE unchanged. The test asserts the two lengths
// agree rather than trusting this comment.
const webshell = "<?php @eval(base64_decode($_POST['x']));/*abcde*/ ?>\n"

const cleanPHP = "<?php /* nothing at all happens here, honestly */ ?>\n"

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// sweepOnce runs one scan over root with a cache at cachePath.
func sweepOnce(t *testing.T, root, cachePath string) (scanned, skipped int, findings []Finding) {
	t.Helper()
	req := ScanRequest{
		Roots:              []string{root},
		RuleEngine:         true,
		LocationHeuristics: true,
		CacheFile:          cachePath,
	}
	cache := newScanCache(req)
	scanned, skipped, findings, complete := runScan(context.Background(), root, req, cache)
	if !complete {
		t.Fatal("the walk did not finish")
	}
	if err := cache.save(req); err != nil {
		t.Fatalf("save: %v", err)
	}
	return scanned, skipped, findings
}

func TestASecondSweepSkipsWhatTheFirstFoundClean(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(t.TempDir(), "rapidscan.json")
	writeTree(t, root, map[string]string{
		"public_html/index.php":         cleanPHP,
		"public_html/wp-load.php":       cleanPHP,
		"public_html/inc/helpers.php":   cleanPHP,
		"public_html/inc/template.php":  cleanPHP,
		"public_html/assets/bundle.php": cleanPHP,
	})

	scanned, skipped, findings := sweepOnce(t, root, cache)
	if scanned != 5 || skipped != 0 {
		t.Fatalf("cold sweep read %d and skipped %d; wanted 5 and 0", scanned, skipped)
	}
	if len(findings) != 0 {
		t.Fatalf("the clean tree produced %d findings", len(findings))
	}

	scanned, skipped, findings = sweepOnce(t, root, cache)
	if scanned != 0 || skipped != 5 {
		t.Fatalf("warm sweep read %d and skipped %d; wanted 0 and 5", scanned, skipped)
	}
	if len(findings) != 0 {
		t.Fatalf("the warm sweep produced %d findings", len(findings))
	}
}

func TestAnInPlaceEditWithTheTimestampPutBackIsStillCaught(t *testing.T) {
	// The escape the key exists to close. The payload is written over a clean
	// file of the SAME LENGTH and the modification time is then restored to the
	// nanosecond, so size and mtime both match what the cache recorded. Only
	// ctime moves, and no syscall writes ctime.
	root := t.TempDir()
	cachePath := filepath.Join(t.TempDir(), "rapidscan.json")
	victim := filepath.Join(root, "public_html", "index.php")
	writeTree(t, root, map[string]string{
		"public_html/index.php":  cleanPHP,
		"public_html/second.php": cleanPHP,
	})

	if _, _, findings := sweepOnce(t, root, cachePath); len(findings) != 0 {
		t.Fatalf("the clean tree produced %d findings", len(findings))
	}

	before, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if len(webshell) != len(cleanPHP) {
		t.Fatalf("the fixture is not a same-length edit: %d against %d", len(webshell), len(cleanPHP))
	}
	// The edit is in place, over the existing inode, so nothing about the file
	// changes except its content and its ctime.
	f, err := os.OpenFile(victim, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte(webshell), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// Timestomp: atime and mtime back to what they were, to the nanosecond.
	stomped := before.ModTime()
	if err := os.Chtimes(victim, stomped, stomped); err != nil {
		t.Fatal(err)
	}

	after, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	// The two halves of the key an attacker CAN control really are unchanged, so
	// this test is a proof about ctime and not about a size or mtime it happened
	// to move.
	if after.Size() != before.Size() {
		t.Fatalf("the size changed (%d against %d); this no longer measures ctime",
			after.Size(), before.Size())
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("the modification time was not restored (%v against %v); this no longer measures ctime",
			after.ModTime(), before.ModTime())
	}
	if fileKey(after) == fileKey(before) {
		t.Fatal("size, mtime AND ctime all matched after an in-place edit, so the key carries nothing an owner cannot forge")
	}

	scanned, skipped, findings := sweepOnce(t, root, cachePath)
	if scanned != 1 {
		t.Fatalf("the warm sweep read %d files; only the edited one should have been read", scanned)
	}
	if skipped != 1 {
		t.Fatalf("the warm sweep skipped %d files; the untouched one should have been skipped", skipped)
	}
	if len(findings) != 1 {
		t.Fatalf("the edited file produced %d findings, so the cache let a webshell past", len(findings))
	}
	if findings[0].File != victim {
		t.Fatalf("the finding names %q rather than the edited file", findings[0].File)
	}
	if findings[0].Level != LevelCritical {
		t.Fatalf("the webshell came back %q rather than %q", findings[0].Level, LevelCritical)
	}
}

func TestTouchingAFileBackwardsDoesNotRestoreItsKey(t *testing.T) {
	// `touch -d '2020-01-01'` is the ordinary shape of a timestomp. It moves
	// mtime into the past and leaves ctime at the present moment, which is
	// precisely what gives it away.
	dir := t.TempDir()
	p := filepath.Join(dir, "x.php")
	if err := os.WriteFile(p, []byte(cleanPHP), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fileKey(after) == fileKey(before) {
		t.Fatal("a backdated file kept its key")
	}
	if want := strconv.FormatInt(after.Size(), 10) + ":"; !strings.HasPrefix(fileKey(after), want) {
		t.Fatalf("the key %q does not start with the size %q", fileKey(after), want)
	}
}

func TestAFindingIsReportedByEverySweepUntilItStops(t *testing.T) {
	// A file that produced a finding is never recorded as clean, so a sweep that
	// found a webshell nobody has removed reports it again. Recording it would
	// make the detection disappear from the next night's report while the file
	// was still executing.
	root := t.TempDir()
	cachePath := filepath.Join(t.TempDir(), "rapidscan.json")
	writeTree(t, root, map[string]string{
		"public_html/shell.php": webshell,
		"public_html/index.php": cleanPHP,
	})

	for pass := 1; pass <= 2; pass++ {
		scanned, _, findings := sweepOnce(t, root, cachePath)
		if len(findings) != 1 {
			t.Fatalf("pass %d produced %d findings, not 1", pass, len(findings))
		}
		if pass == 2 && scanned != 1 {
			t.Fatalf("the second pass read %d files; only the infected one should have been re-read", scanned)
		}
	}
}

func TestANewFingerprintReAnalysesEveryFile(t *testing.T) {
	// The reachable escape, and it is NOT the one that first suggests itself.
	//
	// Turning rule_engine off does not fill the cache with a tree recorded clean:
	// with no read limit and no location match the walk returns before the cache
	// is consulted at all, so an ordinary file is never recorded. Measured: such
	// a sweep reads 0 files and writes 0 entries.
	//
	// Turning LOCATION off is the direction that does it. Every file is still
	// read and weighed on its content, so a content-clean file IS recorded clean.
	// A PHP file under wp-content/uploads is one the location layer convicts on
	// its own, and without the fingerprint it would be skipped for good the
	// moment that layer came back on.
	root := t.TempDir()
	cachePath := filepath.Join(t.TempDir(), "rapidscan.json")
	writeTree(t, root, map[string]string{
		"public_html/wp-content/uploads/2026/01/note.php": cleanPHP,
		"public_html/index.php":                           cleanPHP,
	})

	noLocation := ScanRequest{Roots: []string{root}, RuleEngine: true, CacheFile: cachePath}
	cache := newScanCache(noLocation)
	scanned, _, findings, _ := runScan(context.Background(), root, noLocation, cache)
	if scanned != 2 {
		t.Fatalf("the location-off sweep read %d files, not 2", scanned)
	}
	if len(findings) != 0 {
		t.Fatalf("the content rules alone convicted %d files in this fixture, so it cannot show the escape", len(findings))
	}
	if err := cache.save(noLocation); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Non-vacuity: the cache really did record the file the next sweep must not
	// skip. Without this the test would pass on an empty cache.
	if got := loadRapidCache(cachePath, cacheFingerprint(noLocation)); len(got) != 2 {
		t.Fatalf("the location-off sweep recorded %d entries, not 2; there is nothing for the fingerprint to discard", len(got))
	}

	scanned, skipped, findings := sweepOnce(t, root, cachePath)
	if skipped != 0 {
		t.Fatalf("%d files were skipped on a judgement earned with the location rules off", skipped)
	}
	if scanned != 2 {
		t.Fatalf("the sweep read %d files, not 2", scanned)
	}
	if len(findings) != 1 {
		t.Fatalf("the executable file under uploads was not reported once the location rules came back on: %d findings", len(findings))
	}
	if !strings.Contains(findings[0].File, "note.php") {
		t.Fatalf("the finding names %q rather than the file under uploads", findings[0].File)
	}
}
