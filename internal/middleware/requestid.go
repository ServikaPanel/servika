package middleware

import (
	"net/http"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// RequestID puts a SERVER-GENERATED correlation id in the request context.
//
// Not chimw.RequestID on its own: it takes the id from the inbound
// X-Request-Id header whenever the client sends one, and generates a value
// only when the header is absent. The panel runs that middleware before
// authentication, and nginx does not overwrite the header, so any
// unauthenticated client chose the value that then reached three sinks: the
// access-log line (`http reqid=%s ip=...`), the LogR prefix on every line a
// handler writes, and the X-Request-Id response header plus the request_id
// field of every error body.
//
// A chosen id with a newline in it writes whole log lines of its own, and the
// access-log format puts reqid FIRST, so the forged line can carry any ip,
// method, route and status the client likes. Deleting the header before chi
// reads it makes the generated id the only one there is, which is what both
// the panel's documentation and the #nosec justification on the access log
// already claimed.
func RequestID(next http.Handler) http.Handler {
	generate := chimw.RequestID(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del(chimw.RequestIDHeader)
		generate.ServeHTTP(w, r)
	})
}
