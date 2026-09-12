package performance

import (
	"bufio"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// The FastCGI cache-status log receives ONE line per request through a cached
// location, so its length is the domain's whole traffic volume since the last
// rotation. Aggregating it used to mean a full-file scan on every call, with no
// cache, no coalescing and no ceiling, on a CustomerScope route with no rate
// limit; the panel runs as root, so that read is not charged to the tenant's
// cgroup I/O limit either. A customer holding down refresh turned a page into
// unbounded disk I/O.
//
// These three constants close the same three holes internal/diskusage was
// created to close for du.
const (
	// cacheLogWindow bounds one read. Each line is a short token ("HIT", "MISS"),
	// so this covers hundreds of thousands of requests: enough to measure a hit
	// rate, and a fixed cost whatever the log has grown to.
	cacheLogWindow = 1 << 20

	// cacheStatsTTL is how long an aggregation is reused. A hit rate does not
	// move meaningfully inside half a minute, and this is what stops a held-down
	// refresh from costing a read per request.
	cacheStatsTTL = 30 * time.Second

	// cacheStatsSweepAt is the entry count above which expired entries are
	// dropped. The map is keyed by domain, so it is bounded by the number of
	// domains already; the sweep only stops a long-lived process from holding
	// entries for domains that are gone.
	cacheStatsSweepAt = 512
)

type cacheStatsEntry struct {
	stats *CacheStats
	at    time.Time
}

// cacheStatsCall is one in-flight aggregation. A caller arriving while it runs
// waits on done rather than starting a second read of the same log.
type cacheStatsCall struct {
	done  chan struct{}
	stats *CacheStats
}

var (
	cacheStatsMu       sync.Mutex
	cacheStatsCache    = map[string]cacheStatsEntry{}
	cacheStatsInflight = map[string]*cacheStatsCall{}

	// Test seams. cacheStatsNow lets a test age the cache without sleeping, and
	// aggregateCacheLog lets it count how many real reads a set of calls produced.
	cacheStatsNow     = time.Now
	aggregateCacheLog = readCacheLogWindow
)

// computeFastCGICacheStats aggregates the domain's cache-status log into hit and
// miss counters. It returns nil when the log cannot be read, so a screen never
// shows a rate that looks measured but is not.
func computeFastCGICacheStats(domainName string) *CacheStats {
	cacheStatsMu.Lock()
	if entry, ok := cacheStatsCache[domainName]; ok && cacheStatsNow().Sub(entry.at) < cacheStatsTTL {
		cacheStatsMu.Unlock()
		return entry.stats
	}
	if call, ok := cacheStatsInflight[domainName]; ok {
		cacheStatsMu.Unlock()
		<-call.done
		return call.stats
	}
	call := &cacheStatsCall{done: make(chan struct{})}
	cacheStatsInflight[domainName] = call
	cacheStatsMu.Unlock()

	call.stats = aggregateCacheLog(domainName)

	cacheStatsMu.Lock()
	cacheStatsCache[domainName] = cacheStatsEntry{stats: call.stats, at: cacheStatsNow()}
	delete(cacheStatsInflight, domainName)
	sweepCacheStatsLocked()
	cacheStatsMu.Unlock()
	close(call.done)
	return call.stats
}

// sweepCacheStatsLocked drops expired entries once the map grows past
// cacheStatsSweepAt. The caller holds cacheStatsMu.
func sweepCacheStatsLocked() {
	if len(cacheStatsCache) < cacheStatsSweepAt {
		return
	}
	cutoff := cacheStatsNow().Add(-cacheStatsTTL)
	for domain, entry := range cacheStatsCache {
		if entry.at.Before(cutoff) {
			delete(cacheStatsCache, domain)
		}
	}
}

// readCacheLogWindow reads the last cacheLogWindow bytes of one domain's
// cache-status log and counts the statuses in it.
//
// nil means the log could not be read to the end of the window. A partial count
// would be a hit rate that looks measured and is not, which is the one answer a
// statistics screen must not invent; the old code discarded the scanner error
// and reported exactly that.
func readCacheLogWindow(domainName string) *CacheStats {
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	file, err := os.Open("/var/log/nginx/" + domainName + ".cache.log")
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }() // read-only: nothing to flush

	reader, err := tailReader(file)
	if err != nil {
		return nil
	}
	stats, err := countCacheStatuses(reader)
	if err != nil {
		return nil
	}
	return stats
}

// tailReader positions a file at the start of the last cacheLogWindow bytes and
// drops the partial line at that boundary, so a window never begins mid-token.
func tailReader(file *os.File) (io.Reader, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() <= cacheLogWindow {
		return file, nil
	}
	if _, err := file.Seek(info.Size()-cacheLogWindow, io.SeekStart); err != nil {
		return nil, err
	}
	buffered := bufio.NewReader(file)
	if _, err := buffered.ReadString('\n'); err != nil {
		// No newline in the whole window: one token cannot be that long, so this
		// is not a cache-status log and there is nothing honest to count.
		return nil, err
	}
	return buffered, nil
}

// count tallies one upstream_cache_status token. A token nginx does not emit is
// counted nowhere rather than into a bucket of its own, so Total stays the
// number of requests the seven states describe.
func (s *CacheStats) count(token string) {
	switch token {
	case "HIT":
		s.Hit++
	case "MISS":
		s.Miss++
	case "EXPIRED":
		s.Expired++
	case "BYPASS":
		s.Bypass++
	case "STALE":
		s.Stale++
	case "UPDATING":
		s.Updating++
	case "REVALIDATED":
		s.Revalidated++
	}
}

// countCacheStatuses tallies the upstream_cache_status tokens in a reader.
func countCacheStatuses(reader io.Reader) (*CacheStats, error) {
	var stats CacheStats
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		stats.count(strings.TrimSpace(scanner.Text()))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	stats.Total = stats.Hit + stats.Miss + stats.Expired + stats.Bypass + stats.Stale + stats.Updating + stats.Revalidated
	if stats.Total > 0 {
		// HIT, STALE, and REVALIDATED are served from cache.
		stats.HitRate = float64(stats.Hit+stats.Stale+stats.Revalidated) / float64(stats.Total) * 100
	}
	return &stats, nil
}
