package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// resetRegistry empties the in-memory registry so a test measures only its own
// observations.
func resetRegistry() {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.counters = map[counterKey]uint64{}
	reg.histgrams = map[histKey]*histogram{}
}

// The registry is keyed on the label triple and never evicted, and the route and
// status labels are already bounded. The method was not: HTTP allows an
// arbitrary token there, net/http passes it through, the middleware runs before
// routing, and there is no global rate limit. An unauthenticated client sending
// a fresh token per request grew both maps for ever and filled the exposition
// with series the operator did not ask for.
func TestAnUnknownMethodDoesNotGrowTheRegistry(t *testing.T) {
	resetRegistry()

	for i := range 500 {
		record("EVIL"+strconv.Itoa(i), "unmatched", 404, time.Millisecond)
	}

	reg.mu.Lock()
	counters, histograms := len(reg.counters), len(reg.histgrams)
	reg.mu.Unlock()
	if counters != 1 {
		t.Errorf("500 distinct method tokens produced %d counter series, want 1", counters)
	}
	if histograms != 1 {
		t.Errorf("500 distinct method tokens produced %d histograms, want 1", histograms)
	}

	rec := httptest.NewRecorder()
	Handler(rec, httptest.NewRequest(http.MethodGet, "/system/metrics", nil))
	body := rec.Body.String()
	if strings.Contains(body, "EVIL") {
		t.Errorf("a client-supplied method token reached the exposition:\n%s", body)
	}
	if !strings.Contains(body, `method="other"`) {
		t.Errorf("the unknown methods were not counted under \"other\":\n%s", body)
	}
}

// Bounding the label must not lose the request. An operator reading the error
// rate during an incident needs the traffic counted, just not under a label the
// client chose.
func TestAnUnknownMethodIsStillCounted(t *testing.T) {
	resetRegistry()

	record("EVIL", "unmatched", 404, time.Millisecond)
	record("ALSO-EVIL", "unmatched", 404, time.Millisecond)

	rec := httptest.NewRecorder()
	Handler(rec, httptest.NewRequest(http.MethodGet, "/system/metrics", nil))
	want := `servika_http_requests_total{method="other",route="unmatched",status="404"} 2`
	if body := rec.Body.String(); !strings.Contains(body, want) {
		t.Errorf("exposition missing %q\n---\n%s", want, body)
	}
}

// Every real verb keeps its own label, or the metrics stop distinguishing a read
// from a write.
func TestEveryKnownMethodKeepsItsOwnLabel(t *testing.T) {
	resetRegistry()

	methods := []string{
		http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect,
		http.MethodOptions, http.MethodTrace,
	}
	for _, method := range methods {
		record(method, "/api/v1/domains", 200, time.Millisecond)
	}

	rec := httptest.NewRecorder()
	Handler(rec, httptest.NewRequest(http.MethodGet, "/system/metrics", nil))
	body := rec.Body.String()
	for _, method := range methods {
		want := fmt.Sprintf(`servika_http_requests_total{method=%q,route="/api/v1/domains",status="200"} 1`, method)
		if !strings.Contains(body, want) {
			t.Errorf("exposition missing %q", want)
		}
	}
	if strings.Contains(body, `method="other"`) {
		t.Error("a known method was folded into the \"other\" bucket")
	}
}

// The middleware is the real entry point, and it takes the method straight off
// the request.
func TestTheMiddlewareBoundsTheMethodItReads(t *testing.T) {
	resetRegistry()

	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	request := httptest.NewRequest(http.MethodGet, "/nowhere", nil)
	request.Method = "TOKEN-FROM-THE-CLIENT" // what net/http passes through verbatim
	handler.ServeHTTP(httptest.NewRecorder(), request)

	reg.mu.Lock()
	defer reg.mu.Unlock()
	for key := range reg.counters {
		if key.method != "other" {
			t.Errorf("the middleware recorded method %q, want it bounded to \"other\"", key.method)
		}
	}
}
