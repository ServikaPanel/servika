package phpversion

import (
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// resetAvailabilityCache clears the cache for deterministic test runs.
func resetAvailabilityCache() {
	availabilityMu.Lock()
	availabilityCache = map[string]bool{}
	availabilityMu.Unlock()
}

// TestPackageAvailableCacheOnly verifies the request path (packageAvailable / AllVersions)
// NEVER calls dnf, only reads the cache populated by the background sweeper, and that
// concurrent access has no races. Run with `go test -race`.
func TestPackageAvailableCacheOnly(t *testing.T) {
	sweeperOnce.Do(func() {})
	resetAvailabilityCache()

	var probeCalls atomic.Int64
	old := dnfProbe
	dnfProbe = func(pkg string) (available bool, checked bool) { // fake probe that never calls dnf
		probeCalls.Add(1)
		return pkg == "php82-php-fpm", true // only php82 installable; all give DEFINITE answer
	}
	defer func() { dnfProbe = old }()

	// Populate synchronously.
	sweepOnce()

	if !packageAvailable(VersionMetadata{Version: "8.2", Code: "82", Resource: "remi"}) {
		t.Fatal("php82 should be installable")
	}
	if packageAvailable(VersionMetadata{Version: "8.1", Code: "81", Resource: "remi"}) {
		t.Fatal("php81 should not be installable (cache=false)")
	}
	if !packageAvailable(VersionMetadata{Version: "8.3", Code: "", Resource: "appstream"}) {
		t.Fatal("appstream should always be available")
	}

	base := probeCalls.Load()

	// Concurrent reads: cache-only, NO dnf calls, NO races.
	var wg sync.WaitGroup
	for range 200 {
		wg.Go(func() {
			_ = packageAvailable(VersionMetadata{Version: "8.2", Code: "82", Resource: "remi"})
			_ = packageAvailable(VersionMetadata{Version: "8.4", Code: "84", Resource: "remi"})
			_ = AllVersions()
		})
	}
	wg.Wait()

	if got := probeCalls.Load(); got != base {
		t.Fatalf("request path called dnf: base=%d got=%d (cache-only expected)", base, got)
	}
}

// TestEmptyCacheDoesNotBlock verifies that when the cache is empty (first boot) the
// request path returns a safe default (false) immediately without calling dnf — it does
// not hang.
func TestEmptyCacheDoesNotBlock(t *testing.T) {
	sweeperOnce.Do(func() {})

	old := dnfProbe
	dnfProbe = func(pkg string) (bool, bool) {
		t.Fatalf("request path called dnf: %s", pkg)
		return false, false
	}
	defer func() { dnfProbe = old }()

	resetAvailabilityCache()

	// Empty cache → false, and dnf is NEVER called (dnfProbe would fail the test).
	if packageAvailable(VersionMetadata{Version: "8.5", Code: "85", Resource: "remi"}) {
		t.Fatal("empty cache should default to false")
	}
}

// TestSweepTransientFailurePreservesLastKnownGood: (a) transient-fail true→true RETAINED.
// Round 1 writes CONFIRMED true; round 2 COULD NOT ASK dnf (checked=false) → previous true
// MUST NOT be flipped to false. This is the exact regression test for the original
// false-negative bug: a transient dnf lock used to atomically wipe the entire cache to false.
func TestSweepTransientFailurePreservesLastKnownGood(t *testing.T) {
	sweeperOnce.Do(func() {})
	resetAvailabilityCache()
	old := dnfProbe
	defer func() { dnfProbe = old }()

	// Round 1: every package DEFINITELY available (checked=true, available=true).
	dnfProbe = func(pkg string) (bool, bool) { return true, true }
	sweepOnce()
	if !packageAvailable(VersionMetadata{Version: "8.2", Code: "82", Resource: "remi"}) {
		t.Fatal("round 1: php82 cache=true expected")
	}
	if !packageAvailable(VersionMetadata{Version: "8.4", Code: "84", Resource: "remi"}) {
		t.Fatal("round 1: php84 cache=true expected")
	}

	// Round 2: dnf transiently COULD NOT BE ASKED (checked=false) for ALL packages.
	// Expectation: previous true values are PRESERVED.
	dnfProbe = func(pkg string) (bool, bool) { return false, false }
	sweepOnce()
	if !packageAvailable(VersionMetadata{Version: "8.2", Code: "82", Resource: "remi"}) {
		t.Fatal("transient dnf failure (checked=false) MUST NOT flip last-known-good true to false")
	}
	if !packageAvailable(VersionMetadata{Version: "8.4", Code: "84", Resource: "remi"}) {
		t.Fatal("transient dnf failure must also preserve php84 true")
	}
}

// TestSweepTimeoutIsNotUnavailable: (b) timeout ≠ unavailable.
// For the same package: checked=false (timeout) preserves previous value; checked=true +
// available=false (dnf DEFINITE 'No match') flips to false. Proves the two cases are DISTINCT.
func TestSweepTimeoutIsNotUnavailable(t *testing.T) {
	sweeperOnce.Do(func() {})
	resetAvailabilityCache()
	old := dnfProbe
	defer func() { dnfProbe = old }()

	// Seed: php81 DEFINITELY available.
	dnfProbe = func(pkg string) (bool, bool) { return true, true }
	sweepOnce()
	if !packageAvailable(VersionMetadata{Version: "8.1", Code: "81", Resource: "remi"}) {
		t.Fatal("after seed php81 should be true")
	}

	// Timeout round (checked=false): is NOT 'unavailable' → true retained.
	dnfProbe = func(pkg string) (bool, bool) { return false, false }
	sweepOnce()
	if !packageAvailable(VersionMetadata{Version: "8.1", Code: "81", Resource: "remi"}) {
		t.Fatal("timeout (checked=false) is NOT unavailable; previous true must be retained")
	}

	// Confirmed-unavailable round (checked=true, available=false): NOW it should be false.
	dnfProbe = func(pkg string) (bool, bool) { return false, true }
	sweepOnce()
	if packageAvailable(VersionMetadata{Version: "8.1", Code: "81", Resource: "remi"}) {
		t.Fatal("dnf DEFINITE 'No match' (checked=true) should yield false")
	}
}

// TestSweepConfirmedUnavailableIsFalse: (c) confirmed-unavailable → still false.
// Starting from empty cache, when dnf DEFINITELY returns 'No match', cache should EXPLICITLY
// hold false.
func TestSweepConfirmedUnavailableIsFalse(t *testing.T) {
	sweeperOnce.Do(func() {})
	resetAvailabilityCache()
	old := dnfProbe
	defer func() { dnfProbe = old }()

	dnfProbe = func(pkg string) (bool, bool) { return false, true } // dnf clear: package absent
	sweepOnce()

	if packageAvailable(VersionMetadata{Version: "8.4", Code: "84", Resource: "remi"}) {
		t.Fatal("confirmed-unavailable → packageAvailable should return false")
	}
	// Cache should hold EXPLICIT false, not be absent.
	availabilityMu.Lock()
	v, ok := availabilityCache["php84-php-fpm"]
	availabilityMu.Unlock()
	if !ok {
		t.Fatal("php84 should be present in cache (confirmed → written)")
	}
	if v {
		t.Fatal("php84 cache value should be false")
	}
}

// TestAvailabilityVerifyThreeState verifies the install-gate LIVE authoritative probe
// (dnfLiveProbe) correctly distinguishes the three states — in particular 'could not ask'
// (checked=false) NEVER implies EOL/unavailable (false-negative prevention). AppStream
// is never probed live.
func TestAvailabilityVerifyThreeState(t *testing.T) {
	old := dnfLiveProbe
	defer func() { dnfLiveProbe = old }()

	remi81 := VersionMetadata{Version: "8.1", Code: "81", Resource: "remi"}

	// 1) confirmed-unavailable: checked=true & available=false → safe to say EOL.
	dnfLiveProbe = func(pkg string) (bool, bool) { return false, true }
	if a, c := availabilityVerify(remi81); !c || a {
		t.Fatalf("confirmed-unavailable expected (checked=true, available=false): a=%v c=%v", a, c)
	}

	// 2) could not ask: checked=false → NEVER say EOL (false-negative prevention).
	dnfLiveProbe = func(pkg string) (bool, bool) { return false, false }
	if _, c := availabilityVerify(remi81); c {
		t.Fatal("could not ask dnf → checked=false expected (must not claim EOL)")
	}

	// 3) available: checked=true & available=true.
	dnfLiveProbe = func(pkg string) (bool, bool) { return true, true }
	if a, c := availabilityVerify(remi81); !a || !c {
		t.Fatalf("available expected: a=%v c=%v", a, c)
	}

	// 4) appstream: always (true, true) WITHOUT calling the live probe.
	dnfLiveProbe = func(pkg string) (bool, bool) {
		t.Fatal("appstream must not call live dnf probe")
		return false, false
	}
	if a, c := availabilityVerify(VersionMetadata{Version: "8.3", Code: "", Resource: "appstream"}); !a || !c {
		t.Fatalf("appstream should be (true,true): a=%v c=%v", a, c)
	}
}

// ---- Version scan cache ----
//
// What the cache is FOR is measured elsewhere: with a counter against the real
// call chain, GET /php-settings runs AllVersions() twice, and each run execs
// `php -v` and `php -m` per installed version. What is measured here is that the
// cache answers the same thing the scan would, that it stops being an answer at
// the points that change it, and that one caller cannot rewrite what the next
// one reads.

// countedScan replaces the scan with a fixed answer and counts how often it
// runs. The cache is emptied first, because it is package state every test in
// this file shares.
func countedScan(t *testing.T, versions ...Version) *atomic.Int64 {
	t.Helper()
	var scans atomic.Int64
	previous := discoverAll
	discoverAll = func() []Version {
		scans.Add(1)
		return append([]Version(nil), versions...)
	}
	t.Cleanup(func() {
		discoverAll = previous
		InvalidateAllVersions()
	})
	InvalidateAllVersions()
	return &scans
}

func scanned(version, real string) Version {
	return Version{
		VersionMetadata: VersionMetadata{Version: version, Resource: "remi"},
		Loaded:          true,
		RealVersion:     real,
	}
}

// The whole point: the second reader of one request pays nothing.
func TestASecondCallInsideTheWindowDoesNotScanAgain(t *testing.T) {
	scans := countedScan(t, scanned("8.3", "8.3.31"))

	first, second := AllVersions(), AllVersions()
	if got := scans.Load(); got != 1 {
		t.Errorf("two calls ran %d scans, want 1", got)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("the cached answer lost its contents: %d then %d", len(first), len(second))
	}
	if first[0].RealVersion != second[0].RealVersion {
		t.Errorf("the cached answer differs from the scanned one: %q vs %q",
			first[0].RealVersion, second[0].RealVersion)
	}
}

// The TTL is the backstop for a change made outside the panel, so it has to
// actually expire. The clock is moved rather than slept on: waiting out the
// shipped sixty seconds would measure the same thing at sixty times the cost.
func TestTheAnswerIsScannedAgainOnceTheWindowHasPassed(t *testing.T) {
	scans := countedScan(t, scanned("8.3", "8.3.31"))

	_ = AllVersions()
	allVersionsMu.Lock()
	allVersionsAt = time.Now().Add(-allVersionsTTL - time.Second)
	allVersionsMu.Unlock()
	_ = AllVersions()

	if got := scans.Load(); got != 2 {
		t.Errorf("a call past the window ran %d scans in total, want 2", got)
	}
}

// A change the panel itself makes is not left to the window, because the
// operator is watching the list at exactly that moment.
func TestInvalidatingMakesTheNextCallScan(t *testing.T) {
	scans := countedScan(t, scanned("8.3", "8.3.31"))

	_ = AllVersions()
	InvalidateAllVersions()
	_ = AllVersions()

	if got := scans.Load(); got != 2 {
		t.Errorf("a call after invalidation ran %d scans in total, want 2", got)
	}
}

// One caller must not be able to rewrite what the next one reads. This is what
// handing out the cache's own slice costs, and it is measured on BOTH paths:
// the call that filled the cache and the call that was served from it.
func TestOneCallerCannotRewriteWhatTheNextOneReads(t *testing.T) {
	countedScan(t, scanned("8.3", "8.3.31"))

	filled := AllVersions() // the scan
	filled[0].RealVersion = "rewritten by the first caller"
	served := AllVersions() // the cache
	if served[0].RealVersion != "8.3.31" {
		t.Errorf("the caller that ran the scan rewrote the cache: %q", served[0].RealVersion)
	}

	served[0].RealVersion = "rewritten by the second caller"
	if next := AllVersions(); next[0].RealVersion != "8.3.31" {
		t.Errorf("a caller served from the cache rewrote it: %q", next[0].RealVersion)
	}
}

// A dnf install or remove is about to change which versions exist, so the cache
// stops being an answer the moment the unit starts.
func TestStartingAnOperationDropsTheScan(t *testing.T) {
	opPaths(t)
	stubUnit(t, "active", nil)
	scans := countedScan(t, scanned("8.3", "8.3.31"))
	m := remiVersion(t)

	_ = AllVersions()
	if err := startPHPOp(opDescriptor{Version: m.Version, Resource: m.Resource, Action: "install"},
		installScript(m)); err != nil {
		t.Fatalf("startPHPOp: %v", err)
	}
	_ = AllVersions()

	if got := scans.Load(); got != 2 {
		t.Errorf("starting an operation left %d scans in total, want 2", got)
	}
}

// The transition is observed for free: the screen polls this endpoint for as
// long as an operation runs, so the first poll that sees it stopped is the first
// moment the list can have changed.
func TestStatusDropsTheScanOnceTheOperationHasStopped(t *testing.T) {
	opPaths(t)
	stubUnit(t, "inactive", nil)
	scans := countedScan(t, scanned("8.3", "8.3.31"))

	_ = AllVersions()
	recorder := httptest.NewRecorder()
	(&Handlers{}).Status(recorder, httptest.NewRequest("GET", "/php-versions/status", nil))
	if recorder.Code != 200 {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	_ = AllVersions()

	if got := scans.Load(); got != 2 {
		t.Errorf("a finished operation left %d scans in total, want 2", got)
	}
}

// The other direction, or the check above would pass on a Status that drops the
// cache unconditionally: while dnf is still running the version list cannot have
// changed yet, and every poll would pay for a full scan.
func TestStatusKeepsTheScanWhileTheOperationIsStillRunning(t *testing.T) {
	opPaths(t)
	stubUnit(t, "active", nil)
	scans := countedScan(t, scanned("8.3", "8.3.31"))

	_ = AllVersions()
	for range 3 {
		recorder := httptest.NewRecorder()
		(&Handlers{}).Status(recorder, httptest.NewRequest("GET", "/php-versions/status", nil))
	}
	_ = AllVersions()

	if got := scans.Load(); got != 1 {
		t.Errorf("polling a running operation ran %d scans, want 1", got)
	}
}
