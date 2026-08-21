// Package performance provides a read-only domain acceleration and performance summary.
// It combines current php_settings and nginx_settings data and generates suggestions.
package performance

import (
	"bufio"
	"database/sql"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"servika/internal/httpx"
	"servika/internal/phpdefaults"

	"github.com/go-chi/chi/v5"
)

// Handlers provides domain performance HTTP handlers.
type Handlers struct {
	DB *sql.DB
}

// Item describes a performance setting and its current state.
type Item struct {
	Name        string `json:"name"`
	Enabled     bool   `json:"active"`
	Value       string `json:"value"`
	Setting     string `json:"setting"` // Settings page slug.
	Description string `json:"description"`
}

// Suggestion describes a performance improvement recommendation.
type Suggestion struct {
	Text     string `json:"text"`
	Severity string `json:"severity"` // "high" | "medium" | "info"
	Setting  string `json:"setting"`
}

// CacheStats holds aggregated cache hit/miss counters and a computed hit rate.
// For FastCGI, every upstream_cache_status variant is tracked. For Redis, only
// keyspace_hits and keyspace_misses are available.
type CacheStats struct {
	Hit         int64   `json:"hit"`
	Miss        int64   `json:"miss"`
	Expired     int64   `json:"expired,omitempty"`
	Bypass      int64   `json:"bypass,omitempty"`
	Stale       int64   `json:"stale,omitempty"`
	Updating    int64   `json:"updating,omitempty"`
	Revalidated int64   `json:"revalidated,omitempty"`
	Total       int64   `json:"total"`
	HitRate     float64 `json:"hit_rate"`
}

// Summary describes a domain's performance configuration.
type Summary struct {
	DomainName   string       `json:"domain_name"`
	PHPVersion   string       `json:"php_version"`
	Score        int          `json:"score"` // Approximate performance score from 0 to 100.
	Items        []Item       `json:"items"`
	Suggestions  []Suggestion `json:"suggestions"`
	FastCGICache *CacheStats  `json:"fastcgi_cache,omitempty"`
	RedisCache   *CacheStats  `json:"redis_cache,omitempty"`
}

// Show returns the current performance summary for a domain.
func (h *Handlers) Show(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var domainName, phpVersion string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, php_version FROM domains WHERE id=?`, id).Scan(&domainName, &phpVersion); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	summary := Summary{DomainName: domainName, PHPVersion: phpVersion}

	// Use default php_settings when no record exists.
	var opcache, fileUploads int
	var memLimit, pmStrategy string
	var pmMaxChildren, maxExec int
	opcache, memLimit, pmStrategy, pmMaxChildren, maxExec = 1, phpdefaults.MemoryLimit, "ondemand", 8, phpdefaults.MaxExecutionTime
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT opcache_enable, memory_limit, pm_strategy, pm_max_children, max_execution_time
		   FROM php_settings WHERE domain_id=? AND subdomain_id=0`, id).
		Scan(&opcache, &memLimit, &pmStrategy, &pmMaxChildren, &maxExec)
	_ = fileUploads

	// Use default nginx_settings when no record exists.
	var fastcgi, browserCache, browserCacheDays int
	browserCache, browserCacheDays = 1, 30
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT fastcgi_cache, browser_cache, browser_cache_days FROM nginx_settings WHERE domain_id=? AND subdomain_id=0`, id).
		Scan(&fastcgi, &browserCache, &browserCacheDays)

	b := func(i int) bool { return i == 1 }
	summary.Items = []Item{
		{Name: "OPcache", Enabled: b(opcache), Value: statusString(b(opcache)), Setting: "php", Description: "PHP bytecode cache significantly reduces CPU usage."},
		{Name: "FastCGI Cache", Enabled: b(fastcgi), Value: statusString(b(fastcgi)), Setting: "web-server", Description: "nginx caches dynamic PHP output for high-traffic sites."},
		{Name: "Browser Cache", Enabled: b(browserCache), Value: ifElse(b(browserCache), strconv.Itoa(browserCacheDays)+" days", "disabled"), Setting: "web-server", Description: "Long-lived cache headers for static files."},
		{Name: "PHP-FPM Pool", Enabled: true, Value: pmStrategy + " · " + strconv.Itoa(pmMaxChildren) + " workers", Setting: "php", Description: "Worker process management strategy."},
		{Name: "Memory Limit", Enabled: true, Value: memLimit, Setting: "php", Description: "PHP memory_limit."},
	}

	// Calculate the score and suggestions.
	score := 40
	if b(opcache) {
		score += 30
	} else {
		summary.Suggestions = append(summary.Suggestions, Suggestion{Text: "Enable OPcache to improve PHP performance.", Severity: "high", Setting: "php"})
	}
	if b(fastcgi) {
		score += 20
	} else {
		summary.Suggestions = append(summary.Suggestions, Suggestion{Text: "Consider enabling FastCGI Cache for high traffic.", Severity: "medium", Setting: "web-server"})
	}
	if b(browserCache) {
		score += 10
	} else {
		summary.Suggestions = append(summary.Suggestions, Suggestion{Text: "Enable browser caching for static assets.", Severity: "medium", Setting: "web-server"})
	}
	if phpVersion < "8.0" {
		summary.Suggestions = append(summary.Suggestions, Suggestion{Text: "PHP " + phpVersion + " is outdated; PHP 8.3 or later is recommended for speed and security.", Severity: "high", Setting: "php"})
	}
	if len(summary.Suggestions) == 0 {
		summary.Suggestions = append(summary.Suggestions, Suggestion{Text: "Performance settings are in good condition.", Severity: "info", Setting: ""})
	}

	// Collect cache metrics when accelerators are enabled.
	if b(fastcgi) {
		summary.FastCGICache = computeFastCGICacheStats(domainName)
	}
	if h.redisEnabled(r, id) {
		summary.RedisCache = computeRedisCacheStats()
		summary.Items = append(summary.Items, Item{
			Name: "Redis Cache", Enabled: true, Value: "Enabled",
			Setting: "redis", Description: "In-memory object cache for WordPress and PHP applications.",
		})
	}

	summary.Score = score
	httpx.WriteJSON(w, http.StatusOK, summary)
}

// redisEnabled checks whether the domain has an active Redis/Valkey cache.
func (h *Handlers) redisEnabled(r *http.Request, domainID int64) bool {
	var enabled int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT enabled FROM domain_redis WHERE domain_id=?`, domainID).Scan(&enabled)
	return err == nil && enabled == 1
}

// computeFastCGICacheStats reads the domain's dedicated cache-status log
// and aggregates upstream_cache_status values into a CacheStats struct.
// The log file is written by nginx using the servika_cache_status log_format,
// which records only the $upstream_cache_status variable per request.
func computeFastCGICacheStats(domainName string) *CacheStats {
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	f, err := os.Open("/var/log/nginx/" + domainName + ".cache.log")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var cs CacheStats
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		switch strings.TrimSpace(sc.Text()) {
		case "HIT":
			cs.Hit++
		case "MISS":
			cs.Miss++
		case "EXPIRED":
			cs.Expired++
		case "BYPASS":
			cs.Bypass++
		case "STALE":
			cs.Stale++
		case "UPDATING":
			cs.Updating++
		case "REVALIDATED":
			cs.Revalidated++
		}
	}
	cs.Total = cs.Hit + cs.Miss + cs.Expired + cs.Bypass + cs.Stale + cs.Updating + cs.Revalidated
	if cs.Total > 0 {
		// HIT, STALE, and REVALIDATED are served from cache.
		cs.HitRate = float64(cs.Hit+cs.Stale+cs.Revalidated) / float64(cs.Total) * 100
	}
	_ = sc.Err()
	return &cs
}

// computeRedisCacheStats runs valkey-cli INFO stats and extracts keyspace
// hit/miss counters. Returns nil when the admin password is unset or the
// command fails.
func computeRedisCacheStats() *CacheStats {
	pass := os.Getenv("SERVIKA_REDIS_ADMIN_PASS")
	if pass == "" {
		return nil
	}
	cmd := exec.Command("valkey-cli", "INFO", "stats")
	cmd.Env = append(os.Environ(), "REDISCLI_AUTH="+pass)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}
	var cs CacheStats
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "keyspace_hits:"); ok {
			cs.Hit, _ = strconv.ParseInt(strings.TrimSpace(after), 10, 64)
		}
		if after, ok := strings.CutPrefix(line, "keyspace_misses:"); ok {
			cs.Miss, _ = strconv.ParseInt(strings.TrimSpace(after), 10, 64)
		}
	}
	cs.Total = cs.Hit + cs.Miss
	if cs.Total > 0 {
		cs.HitRate = float64(cs.Hit) / float64(cs.Total) * 100
	}
	return &cs
}

func statusString(enabled bool) string {
	if enabled {
		return "Enabled"
	}
	return "Disabled"
}

func ifElse(condition bool, a, b string) string {
	if condition {
		return a
	}
	return b
}
