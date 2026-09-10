package performance

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// resetCacheStats empties the aggregation cache and restores both seams, so one
// test cannot see what another cached.
func resetCacheStats(t *testing.T) {
	t.Helper()
	previousNow, previousRead := cacheStatsNow, aggregateCacheLog
	cacheStatsMu.Lock()
	clear(cacheStatsCache)
	clear(cacheStatsInflight)
	cacheStatsMu.Unlock()
	t.Cleanup(func() {
		cacheStatsNow, aggregateCacheLog = previousNow, previousRead
		cacheStatsMu.Lock()
		clear(cacheStatsCache)
		clear(cacheStatsInflight)
		cacheStatsMu.Unlock()
	})
}

// The route is CustomerScope with no rate limit, and the panel runs as root, so
// the read is not charged to the tenant's cgroup I/O limit. A held-down refresh
// used to start a fresh full-file scan per request.
func TestAHeldDownRefreshCostsOneRead(t *testing.T) {
	resetCacheStats(t)
	var reads int
	aggregateCacheLog = func(string) *CacheStats {
		reads++
		return &CacheStats{Hit: 1, Total: 1}
	}

	for range 50 {
		if got := computeFastCGICacheStats("example.com"); got == nil || got.Hit != 1 {
			t.Fatalf("computeFastCGICacheStats() = %+v, want the cached result", got)
		}
	}

	if reads != 1 {
		t.Fatalf("%d reads for 50 requests, want 1", reads)
	}
}

// Two domains are two logs, so one must not answer for the other.
func TestTheCacheIsKeyedByDomain(t *testing.T) {
	resetCacheStats(t)
	aggregateCacheLog = func(domain string) *CacheStats {
		if domain == "a.test" {
			return &CacheStats{Hit: 1, Total: 1}
		}
		return &CacheStats{Hit: 2, Total: 2}
	}

	if got := computeFastCGICacheStats("a.test"); got.Hit != 1 {
		t.Fatalf("a.test read %d hits", got.Hit)
	}
	if got := computeFastCGICacheStats("b.test"); got.Hit != 2 {
		t.Fatalf("b.test read %d hits, so it answered from another domain's entry", got.Hit)
	}
}

// A hit rate moves, so the cache must not outlive its TTL.
func TestTheAggregationExpires(t *testing.T) {
	resetCacheStats(t)
	moment := time.Unix(1_700_000_000, 0)
	cacheStatsNow = func() time.Time { return moment }
	var reads int
	aggregateCacheLog = func(string) *CacheStats {
		reads++
		return &CacheStats{Hit: int64(reads), Total: int64(reads)}
	}

	computeFastCGICacheStats("example.com")
	moment = moment.Add(cacheStatsTTL - time.Second)
	computeFastCGICacheStats("example.com")
	if reads != 1 {
		t.Fatalf("%d reads inside the TTL, want 1", reads)
	}

	moment = moment.Add(2 * time.Second)
	computeFastCGICacheStats("example.com")
	if reads != 2 {
		t.Fatalf("%d reads past the TTL, want a fresh one", reads)
	}
}

// Concurrent requests for one domain share the read in flight rather than each
// starting their own. Run with -race.
func TestConcurrentRequestsShareOneRead(t *testing.T) {
	resetCacheStats(t)
	release := make(chan struct{})
	var mu sync.Mutex
	reads := 0
	aggregateCacheLog = func(string) *CacheStats {
		mu.Lock()
		reads++
		mu.Unlock()
		<-release
		return &CacheStats{Hit: 1, Total: 1}
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if got := computeFastCGICacheStats("example.com"); got == nil || got.Hit != 1 {
				t.Errorf("computeFastCGICacheStats() = %+v", got)
			}
		})
	}
	// Let the readers pile up on the one call in flight before releasing it.
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if reads != 1 {
		t.Fatalf("%d concurrent reads, want 1", reads)
	}
}

// A read that broke half way is a hit rate that looks measured and is not. The
// old code discarded the scanner error and reported exactly that.
func TestAFailedScanReportsNothingRatherThanAPartialCount(t *testing.T) {
	stats, err := countCacheStatuses(&brokenReader{data: []byte("HIT\nHIT\n"), err: errors.New("input/output error")})
	if err == nil {
		t.Fatal("countCacheStatuses() swallowed the read failure")
	}
	if stats != nil {
		t.Fatalf("countCacheStatuses() returned %+v beside its error", stats)
	}
}

type brokenReader struct {
	data []byte
	err  error
}

func (r *brokenReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

// The tally itself, and the rate: HIT, STALE and REVALIDATED are served from
// cache, the rest are not.
func TestTheHitRateCountsEveryStatusServedFromCache(t *testing.T) {
	stats, err := countCacheStatuses(strings.NewReader(
		"HIT\nHIT\nSTALE\nREVALIDATED\nMISS\nEXPIRED\nBYPASS\nUPDATING\n"))
	if err != nil {
		t.Fatalf("countCacheStatuses() returned an error: %v", err)
	}
	if stats.Total != 8 {
		t.Fatalf("total = %d, want 8", stats.Total)
	}
	// 4 of 8 came from cache.
	if stats.HitRate != 50 {
		t.Fatalf("hit rate = %v, want 50", stats.HitRate)
	}
	if stats.Hit != 2 || stats.Stale != 1 || stats.Revalidated != 1 || stats.Miss != 1 {
		t.Fatalf("counters = %+v", stats)
	}
}

// The log's length is the domain's whole traffic volume since the last rotation,
// so the read has to be bounded. The window starts at a line boundary, or a
// token split across it would be counted as an unknown one.
func TestTheReadIsBoundedAndStartsAtALineBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.log")
	// Well past the window: every line before the last cacheLogWindow bytes must
	// be outside the count.
	var builder strings.Builder
	for builder.Len() < cacheLogWindow*2 {
		builder.WriteString("MISS\n")
	}
	head := int64(builder.Len())
	builder.WriteString("HIT\n")
	if err := os.WriteFile(path, []byte(builder.String()), 0o600); err != nil {
		t.Fatalf("write the log: %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open the log: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })

	reader, err := tailReader(file)
	if err != nil {
		t.Fatalf("tailReader() returned an error: %v", err)
	}
	stats, err := countCacheStatuses(reader)
	if err != nil {
		t.Fatalf("countCacheStatuses() returned an error: %v", err)
	}

	if stats.Total >= head/5 {
		t.Fatalf("the read covered %d lines, so it was not bounded to the window", stats.Total)
	}
	if stats.Hit != 1 {
		t.Fatalf("hit = %d, want the one line at the end of the log", stats.Hit)
	}
	// Every counted line is a whole token: a window cutting "MISS" in half would
	// leave a fragment this tally does not recognise, and the total would fall
	// short of the lines actually in the window.
	if stats.Miss != stats.Total-1 {
		t.Fatalf("%d of %d lines were not whole tokens", stats.Total-1-stats.Miss, stats.Total)
	}
}

// A log shorter than the window is read whole, so a quiet domain still reports
// everything it has.
func TestAShortLogIsReadWhole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.log")
	if err := os.WriteFile(path, []byte("HIT\nMISS\nHIT\n"), 0o600); err != nil {
		t.Fatalf("write the log: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open the log: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })

	reader, err := tailReader(file)
	if err != nil {
		t.Fatalf("tailReader() returned an error: %v", err)
	}
	stats, err := countCacheStatuses(reader)
	if err != nil {
		t.Fatalf("countCacheStatuses() returned an error: %v", err)
	}
	if stats.Total != 3 || stats.Hit != 2 {
		t.Fatalf("counters = %+v, want the whole short log", stats)
	}
}

// A line the log format never writes is not counted, so an unrelated file cannot
// produce a rate.
func TestAnUnknownTokenIsNotCounted(t *testing.T) {
	stats, err := countCacheStatuses(strings.NewReader("HIT\n192.0.2.1 - - [10/Sep/2026]\n-\n"))
	if err != nil {
		t.Fatalf("countCacheStatuses() returned an error: %v", err)
	}
	if stats.Total != 1 {
		t.Fatalf("total = %d, want only the one real status", stats.Total)
	}
}
