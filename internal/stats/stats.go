// Package stats provides read-only per-domain traffic analysis from nginx access logs.
package stats

import (
	"bufio"
	"database/sql"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"servika/internal/httpx"
	"servika/internal/provisioner"
	"servika/internal/subdomain"

	"github.com/go-chi/chi/v5"
)

// Handlers provides domain traffic statistics HTTP handlers.
type Handlers struct {
	DB *sql.DB
}

// KV represents a named aggregate count.
type KV struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Day represents the request count for one day.
type Day struct {
	Date    string `json:"date"`
	Request int    `json:"request"`
}

// Summary contains aggregated traffic statistics for a domain.
type Summary struct {
	DomainName       string         `json:"domain_name"`
	HasLog           bool           `json:"has_log"`
	TotalRequests    int            `json:"total_requests"`
	TotalBandwidthMB float64        `json:"total_bandwidth_mb"`
	UniqueIP         int            `json:"unique_ip"`
	BotRatio         int            `json:"bot_ratio"` // Percentage.
	StatusGroup      map[string]int `json:"status_group"`
	TopPaths         []KV           `json:"top_paths"`
	TopIP            []KV           `json:"top_ip"`
	AggStatus        []KV           `json:"agg_status"`
	Daily            []Day          `json:"daily"`
	LastRequests     []string       `json:"last_requests"`
}

// reLog parses the combined log format: IP - - [date] "METHOD path proto" status bytes "ref" "ua".
var reLog = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^:]+):[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-) "[^"]*" "([^"]*)"`)

const maxLines = 200000

func topN(m map[string]int, n int) []KV {
	out := make([]KV, 0, len(m))
	for k, v := range m {
		out = append(out, KV{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// logSources returns the access logs a request must aggregate, plus the name to
// report. A {sid} URL parameter narrows the result to that subdomain's own log; a
// parent domain request returns its own log followed by every subdomain's log, so
// the parent reports its traffic plus the traffic of all sites nested under it.
func (h *Handlers) logSources(r *http.Request, id int64, domainName string) (string, []string, bool) {
	if raw := chi.URLParam(r, "sid"); raw != "" {
		sid, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return "", nil, false
		}
		scope, ok := subdomain.ResolveScope(r.Context(), h.DB, id, sid)
		if !ok {
			return "", nil, false
		}
		return scope.FQDN, []string{accessLogPath(scope.FQDN)}, true
	}
	names := []string{accessLogPath(domainName)}
	rows, err := h.DB.QueryContext(r.Context(), `SELECT fqdn FROM subdomains WHERE domain_id=?`, id)
	if err != nil {
		// A subdomain lookup failure must not hide the parent's own traffic.
		return domainName, names, true
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var fqdn string
		if err := rows.Scan(&fqdn); err != nil {
			// A dropped subdomain has its traffic left out of the parent's figure.
			log.Printf("stats: skipping an unreadable subdomain row for domain %d: %v", id, err)
			continue
		}
		// Re-validate before the value becomes a filesystem path. A stored name
		// that fails is refused rather than dropped in silence.
		if provisioner.ValidateDomain(fqdn) != nil {
			log.Printf("stats: refusing an invalid stored subdomain name for domain %d", id)
			continue
		}
		names = append(names, accessLogPath(fqdn))
	}
	if err := rows.Err(); err != nil {
		// Same reasoning as the query failure above: a subdomain missing from this
		// list only understates the parent's traffic, so the parent's own log is
		// still reported rather than the whole figure being withheld.
		log.Printf("stats: could not read the subdomain list for domain %d: %v", id, err)
	}
	return domainName, names, true
}

func accessLogPath(fqdn string) string {
	return "/var/log/nginx/" + fqdn + ".access.log"
}

// Show returns aggregated nginx access log statistics for a domain or subdomain.
func (h *Handlers) Show(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var domainName string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name FROM domains WHERE id=?`, id).Scan(&domainName); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	reportName, logPaths, ok := h.logSources(r, id, domainName)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	summary := Summary{
		DomainName:   reportName,
		StatusGroup:  map[string]int{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0},
		TopPaths:     []KV{},
		TopIP:        []KV{},
		AggStatus:    []KV{},
		Daily:        []Day{},
		LastRequests: []string{},
	}

	accumulated := newAccumulator()
	for _, logPath := range logPaths {
		// #nosec G703 G304 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		file, err := os.Open(logPath)
		if err != nil {
			continue // A missing log is normal for a site that has served no traffic.
		}
		summary.HasLog = true
		readErr := accumulated.consume(file)
		_ = file.Close()
		if readErr != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not read access log")
			return
		}
	}
	if !summary.HasLog {
		httpx.WriteJSON(w, http.StatusOK, summary) // Return an empty summary when no log exists.
		return
	}
	accumulated.finalize(&summary)
	httpx.WriteJSON(w, http.StatusOK, summary)
}

var botKeys = []string{"bot", "spider", "crawl", "slurp", "bingpreview", "facebookexternal", "curl", "wget", "python", "go-http"}

// accumulator holds the raw counters for a statistics request. It is kept separate
// from Summary so several access logs can be folded into one result before any
// derived value is computed: a parent domain sums its own log with every subdomain
// log, and ratios such as BotRatio stay correct because they are calculated once,
// in finalize, over the combined totals.
type accumulator struct {
	paths       map[string]int
	ips         map[string]int
	statuses    map[string]int
	days        map[string]int
	statusGroup map[string]int
	recent      []string
	totalBytes  int64
	requests    int
	botHits     int
	// lines caps parsed lines across every consumed log, bounding total work
	// no matter how many subdomains a domain has.
	lines int
}

func newAccumulator() *accumulator {
	return &accumulator{
		paths:       map[string]int{},
		ips:         map[string]int{},
		statuses:    map[string]int{},
		days:        map[string]int{},
		statusGroup: map[string]int{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0},
	}
}

// summarizeLog aggregates a single access log into summary.
func summarizeLog(reader io.Reader, summary *Summary) error {
	accumulated := newAccumulator()
	if err := accumulated.consume(reader); err != nil {
		return err
	}
	accumulated.finalize(summary)
	return nil
}

// consume parses one access log into the accumulator's counters.
func (a *accumulator) consume(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		matches := reLog.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		a.lines++
		if a.lines > maxLines {
			break
		}
		ip, date, method, path, statusCode, byteCount, userAgent := matches[1], matches[2], matches[3], matches[4], matches[5], matches[6], matches[7]
		a.requests++
		a.ips[ip]++
		// Normalize the path by removing its query string.
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		if len(path) > 80 {
			path = path[:80]
		}
		a.paths[method+" "+path]++
		a.statuses[statusCode]++
		switch statusCode[0] {
		case '2':
			a.statusGroup["2xx"]++
		case '3':
			a.statusGroup["3xx"]++
		case '4':
			a.statusGroup["4xx"]++
		case '5':
			a.statusGroup["5xx"]++
		}
		a.days[date]++
		if byteCount != "-" {
			if parsedBytes, parseErr := strconv.ParseInt(byteCount, 10, 64); parseErr == nil {
				a.totalBytes += parsedBytes
			}
		}
		lowerUserAgent := strings.ToLower(userAgent)
		for _, botKey := range botKeys {
			if strings.Contains(lowerUserAgent, botKey) {
				a.botHits++ // Count bot requests before converting to a percentage.
				break
			}
		}
		if len(a.recent) < 40 {
			a.recent = append(a.recent, statusCode+" "+method+" "+path+" ("+ip+")")
		}
	}
	return scanner.Err()
}

// finalize computes derived values from the accumulated counters and writes them
// into summary. It runs once per request, after every log has been consumed.
func (a *accumulator) finalize(summary *Summary) {
	summary.TotalRequests = a.requests
	summary.StatusGroup = a.statusGroup
	summary.UniqueIP = len(a.ips)
	summary.TotalBandwidthMB = float64(a.totalBytes) / (1024 * 1024)
	summary.BotRatio = 0
	if a.requests > 0 {
		summary.BotRatio = a.botHits * 100 / a.requests
	}
	summary.TopPaths = topN(a.paths, 10)
	summary.TopIP = topN(a.ips, 10)
	summary.AggStatus = topN(a.statuses, 8)
	recentRequests := a.recent
	days := a.days
	summary.LastRequests = []string{}
	summary.Daily = []Day{}
	// Reverse the captured requests and return the newest 20 from the last 40.
	for i := len(recentRequests) - 1; i >= 0 && len(summary.LastRequests) < 20; i-- {
		summary.LastRequests = append(summary.LastRequests, recentRequests[i])
	}
	// Return the last seven days sorted by day name.
	dayKeys := make([]string, 0, len(days))
	for day := range days {
		dayKeys = append(dayKeys, day)
	}
	sort.Strings(dayKeys)
	if len(dayKeys) > 7 {
		dayKeys = dayKeys[len(dayKeys)-7:]
	}
	for _, day := range dayKeys {
		summary.Daily = append(summary.Daily, Day{day, days[day]})
	}
}
