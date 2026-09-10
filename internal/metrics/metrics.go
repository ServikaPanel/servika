// Package metrics provides zero-dependency RED (Rate, Errors, Duration)
// instrumentation for the HTTP API: a request counter labelled by method, route,
// and status, plus a latency histogram labelled by method and route. Metrics are
// held in memory and exposed in Prometheus text exposition format so operators can
// scrape them for alerting without pulling in a metrics client library.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// buckets are the latency histogram upper bounds in seconds (Prometheus "le").
var buckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type counterKey struct {
	method string
	route  string
	status int
}

type histKey struct {
	method string
	route  string
}

type histogram struct {
	counts []uint64 // cumulative count of observations <= buckets[i]
	sum    float64
	count  uint64
}

type registry struct {
	mu        sync.Mutex
	counters  map[counterKey]uint64
	histgrams map[histKey]*histogram
}

var reg = &registry{
	counters:  map[counterKey]uint64{},
	histgrams: map[histKey]*histogram{},
}

// knownMethods are the labels the method dimension may take.
//
// The registry is keyed on the label triple and is never evicted or capped, and
// the route and status labels are already bounded (a registered chi pattern or
// the literal "unmatched"; an HTTP status). The method was not: HTTP allows an
// arbitrary token there and net/http passes it through, so an unauthenticated
// client sending a fresh token per request grew both maps for ever. The
// middleware runs before routing and there is no global rate limit, so nothing
// else stood in the way.
//
// The set is RFC 9110's methods plus PATCH. Anything else is counted, under
// "other": dropping it would hide a real client from the operator reading the
// error rate during an incident, which is what these numbers are for.
var knownMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true,
	http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
	http.MethodConnect: true, http.MethodOptions: true, http.MethodTrace: true,
}

// methodLabel bounds the method dimension to knownMethods.
func methodLabel(method string) string {
	if knownMethods[method] {
		return method
	}
	return "other"
}

// record adds one observation for the given method/route/status and latency.
func record(method, route string, status int, dur time.Duration) {
	method = methodLabel(method)
	sec := dur.Seconds()
	reg.mu.Lock()
	defer reg.mu.Unlock()

	reg.counters[counterKey{method, route, status}]++

	hk := histKey{method, route}
	h := reg.histgrams[hk]
	if h == nil {
		h = &histogram{counts: make([]uint64, len(buckets))}
		reg.histgrams[hk] = h
	}
	h.sum += sec
	h.count++
	for i, b := range buckets {
		if sec <= b {
			h.counts[i]++
		}
	}
}

// Middleware records RED metrics for every request. The chi route pattern is
// only populated after routing, so it is read once next.ServeHTTP returns; the
// health endpoint is skipped to avoid unbounded cardinality-free noise.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}
		record(r.Method, route, status, time.Since(start))
	})
}

// escapeLabel escapes a Prometheus label value (backslash, double-quote, newline).
func escapeLabel(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

// Handler writes the current metrics in Prometheus text exposition format.
// It is admin-gated at the route layer; it exposes no secrets, only counts.
func Handler(w http.ResponseWriter, _ *http.Request) {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	// Request counter (RED: Rate + Errors, since status is a label).
	// Response body write errors are not actionable: the metrics scrape simply
	// fails on a dropped connection, and headers are already sent.
	_, _ = fmt.Fprintln(w, "# HELP servika_http_requests_total Total HTTP requests by method, route, and status.")
	_, _ = fmt.Fprintln(w, "# TYPE servika_http_requests_total counter")
	ckeys := make([]counterKey, 0, len(reg.counters))
	for k := range reg.counters {
		ckeys = append(ckeys, k)
	}
	sort.Slice(ckeys, func(i, j int) bool {
		if ckeys[i].route != ckeys[j].route {
			return ckeys[i].route < ckeys[j].route
		}
		if ckeys[i].method != ckeys[j].method {
			return ckeys[i].method < ckeys[j].method
		}
		return ckeys[i].status < ckeys[j].status
	})
	for _, k := range ckeys {
		_, _ = fmt.Fprintf(w, "servika_http_requests_total{method=%q,route=%q,status=%q} %d\n",
			escapeLabel(k.method), escapeLabel(k.route), strconv.Itoa(k.status), reg.counters[k])
	}

	// Latency histogram (RED: Duration).
	_, _ = fmt.Fprintln(w, "# HELP servika_http_request_duration_seconds HTTP request latency by method and route.")
	_, _ = fmt.Fprintln(w, "# TYPE servika_http_request_duration_seconds histogram")
	hkeys := make([]histKey, 0, len(reg.histgrams))
	for k := range reg.histgrams {
		hkeys = append(hkeys, k)
	}
	sort.Slice(hkeys, func(i, j int) bool {
		if hkeys[i].route != hkeys[j].route {
			return hkeys[i].route < hkeys[j].route
		}
		return hkeys[i].method < hkeys[j].method
	})
	for _, k := range hkeys {
		h := reg.histgrams[k]
		m, rt := escapeLabel(k.method), escapeLabel(k.route)
		for i, b := range buckets {
			_, _ = fmt.Fprintf(w, "servika_http_request_duration_seconds_bucket{method=%q,route=%q,le=%q} %d\n",
				m, rt, strconv.FormatFloat(b, 'g', -1, 64), h.counts[i])
		}
		_, _ = fmt.Fprintf(w, "servika_http_request_duration_seconds_bucket{method=%q,route=%q,le=\"+Inf\"} %d\n", m, rt, h.count)
		_, _ = fmt.Fprintf(w, "servika_http_request_duration_seconds_sum{method=%q,route=%q} %s\n",
			m, rt, strconv.FormatFloat(h.sum, 'g', -1, 64))
		_, _ = fmt.Fprintf(w, "servika_http_request_duration_seconds_count{method=%q,route=%q} %d\n", m, rt, h.count)
	}
}
