package middleware

import (
	"log"
	"net/http"
	"time"

	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// AccessLog logs the lifecycle of every API request: request ID, method, route
// pattern (falling back to the raw path), response status, byte count, latency,
// and the originating client IP. This gives operators the per-request data they
// need during incidents (endpoint rate, failing route, latency spikes, affected
// request ID) without an external tracing stack.
//
// Mount it after RequestID so the correlation ID is available. The chi
// route pattern is only populated once the request has been routed, so it is
// read after next.ServeHTTP returns.
func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health checks are polled continuously by update/restore automation;
		// logging them would drown the signal without adding operational value.
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = r.URL.Path
		}
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		// NOT httpx.LogR: this line already carries the id as a named field, and
		// the helper's prefix would print it twice. It is the summary line the
		// helper's prefix exists to be correlated WITH.
		log.Printf("http reqid=%s ip=%s method=%s route=%q status=%d bytes=%d dur=%s",
			chimw.GetReqID(r.Context()), httpx.ClientIP(r), r.Method, route,
			ww.Status(), ww.BytesWritten(), time.Since(start).Round(time.Millisecond))
	})
}
