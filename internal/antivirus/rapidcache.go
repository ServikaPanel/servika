package antivirus

// Skipping a file the last sweep already read and found clean.
//
// A nightly sweep of a whole server reads the same tens of thousands of
// unchanged files every night. This records what each inspected file looked
// like when it was found clean, and the next sweep skips it while it still
// looks the same.
//
// It is a GATE on the scan, which is the class of thing this package treats
// with the most suspicion: a file that never reaches the rules is not a file
// that was inspected and found clean, and nothing on the screen tells the two
// apart. Two properties are what make this one safe, and both were measured
// rather than reasoned about.
//
// THE KEY CANNOT BE FORGED. It is size, mtime and ctime. mtime is settable by
// whoever owns the file, so it carries nothing on its own; ctime is set by the
// kernel on every metadata or content change and no syscall writes it.
// Measured on Linux with a same-length in-place edit followed by an
// os.Chtimes that put atime and mtime back to the nanosecond: size matched,
// mtime matched exactly, and ctime had moved. `touch -d '2020-01-01'` likewise
// left mtime in 2020 and ctime at the present moment, which is precisely what
// gives timestomping away.
//
// THE JUDGEMENT IS FINGERPRINTED. An entry says "this file was clean", and
// that is only true under the rules and layers the scan ran with. Turning
// rule_engine off, sweeping (every file then judged on its path alone and
// recorded clean), and turning it back on would otherwise skip every unchanged
// file for good on a judgement earned with the content rules disabled. The
// whole cache is discarded when the fingerprint changes, so a change of rules
// or layers costs one full sweep and hides nothing.
//
// critical_threshold is deliberately NOT in the fingerprint. Only a file whose
// level came back "" is recorded, and rules.levelFor clamps its threshold
// argument up to scoreSuspicious before comparing, so such a file scored below
// 50 and no value an operator can set turns it into a finding.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
)

// rapidCache is the file the sweep reads and writes.
//
// The fingerprint travels INSIDE the file rather than in its name, so a cache
// that no longer applies is replaced rather than accumulating one file per
// configuration the server has ever had.
type rapidCache struct {
	Fingerprint string            `json:"fingerprint"`
	Files       map[string]string `json:"files"`
}

// rapidCacheLimit bounds the JSON this will parse. At the walk's file cap a
// real cache measures about 7 MB, so this is room for a tree several times
// larger and still refuses a file that has been corrupted into something
// enormous.
const rapidCacheLimit = 256 << 20

// fileKey renders size:mtime:ctime for a file the walk has already stat'ed.
//
// It returns "" when the platform does not hand back a *syscall.Stat_t, which
// is every non-Linux build. An empty key never matches and is never stored, so
// the cache simply does nothing there rather than skipping on a weaker key.
func fileKey(fi fs.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	ctime := ctimeNanos(st)
	if ctime == 0 {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d", fi.Size(), fi.ModTime().UnixNano(), ctime)
}

// cacheFingerprint identifies everything that decides whether a file is clean.
//
// The WORKER computes it, not the panel, because the worker is what loads the
// rule package and what the layer switches actually reached. Recording what the
// scan really ran with is the point; recording what the panel intended would
// let the two drift.
func cacheFingerprint(req ScanRequest) string {
	h := sha256.New()

	// This binary. The built-in rule set carries no version, and ten of the
	// detections are Go code rather than patterns (the two taint rules, the
	// entropy line, the concealed function name, the five location rules and
	// WP.Core.ExtraFile), so hashing the patterns alone would miss a change in
	// taint.go entirely. The binary's own size:mtime:ctime needs no discipline
	// to keep current and fails in the safe direction: a panel update discards
	// the cache and costs one full sweep.
	// Writing to a hash never fails: hash.Hash documents Write as always
	// returning a nil error.
	_, _ = fmt.Fprintf(h, "binary=%s\n", selfKey())

	// The signed rule package in force. New signatures have to reach files that
	// have not changed.
	set := RuleSetInUse()
	_, _ = fmt.Fprintf(h, "rules=%s:%d:%s\n", set.Source, set.Version, set.Produced)

	// The detection layers. A file judged with the content rules off is not a
	// file that was found clean.
	_, _ = fmt.Fprintf(h, "engine=%t location=%t\n", req.RuleEngine, req.LocationHeuristics)

	return hex.EncodeToString(h.Sum(nil))
}

// selfKey is this executable's own size:mtime:ctime.
//
// A path or an error that cannot be resolved yields a value that is stable
// within one process but different from any real key, so the cache is
// discarded rather than trusted.
func selfKey() string {
	self, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	fi, err := os.Stat(self)
	if err != nil {
		return "unknown"
	}
	if key := fileKey(fi); key != "" {
		return key
	}
	return "unkeyed:" + strconv.FormatInt(fi.Size(), 10)
}

// loadRapidCache reads the cache when it still applies.
//
// Every failure answers an empty map, which means every file is inspected. That
// is the direction this must fail in: an unreadable or stale cache costs one
// full sweep, while trusting one would skip files on a judgement that no longer
// holds.
func loadRapidCache(path, fingerprint string) map[string]string {
	if path == "" {
		return nil
	}
	f, err := os.Open(path) // #nosec G304 -- server-internal path from config, never request text.
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > rapidCacheLimit {
		return nil
	}
	var cache rapidCache
	if err := json.NewDecoder(f).Decode(&cache); err != nil {
		return nil
	}
	if cache.Fingerprint != fingerprint {
		return nil
	}
	return cache.Files
}

// storeRapidCache writes what this sweep observed.
//
// The file is REPLACED rather than merged, so an entry for a path the walk no
// longer reaches falls out on its own and the cache cannot grow forever. A walk
// that stopped early therefore writes fewer entries, which again is the safe
// direction: a missing entry is a file that gets inspected.
func storeRapidCache(path, fingerprint string, files map[string]string) error {
	if path == "" {
		return nil
	}
	body, err := json.Marshal(rapidCache{Fingerprint: fingerprint, Files: files})
	if err != nil {
		return fmt.Errorf("encode the scan cache: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	// The temporary file sits in the same directory, so the rename below is a
	// rename rather than a copy and no reader ever sees a half-written cache.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("write the scan cache: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace the scan cache: %w", err)
	}
	return nil
}

// scanCache is one sweep's view of the cache: what the last sweep recorded, and
// what this one is recording.
//
// A nil pointer is a scan with no cache at all, which is what a per-domain scan
// and the real-time watcher get. Every method tolerates it, so the walk needs no
// branch of its own.
type scanCache struct {
	// old is read-only for the life of the scan, so the walk reads it without a
	// lock. Only the walk consults it.
	old map[string]string

	mu    sync.Mutex
	fresh map[string]string
}

// newScanCache reads the cache for a request. It answers nil when the request
// names no cache file, and an empty one when the stored fingerprint no longer
// applies.
func newScanCache(req ScanRequest) *scanCache {
	if req.CacheFile == "" {
		return nil
	}
	return &scanCache{
		old:   loadRapidCache(req.CacheFile, cacheFingerprint(req)),
		fresh: map[string]string{},
	}
}

// unchanged reports whether this exact file was found clean by the last sweep.
//
// An empty key never matches. That is what keeps a platform with no ctime, or a
// file whose stat could not be read, on the full path rather than on a weaker
// comparison.
func (c *scanCache) unchanged(path, key string) bool {
	if c == nil || key == "" {
		return false
	}
	return c.old[path] == key
}

// markClean records a file for the next sweep. It is called both by the walk
// for a file it skipped and by a worker for one it read and found clean, so an
// entry survives only while the file keeps being found clean.
func (c *scanCache) markClean(path, key string) {
	if c == nil || key == "" {
		return
	}
	c.mu.Lock()
	c.fresh[path] = key
	c.mu.Unlock()
}

// save writes what this sweep observed.
func (c *scanCache) save(req ScanRequest) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return storeRapidCache(req.CacheFile, cacheFingerprint(req), c.fresh)
}
