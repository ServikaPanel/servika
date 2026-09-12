package httpx

import (
	"net/http"

	"servika/internal/logx"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// LogR logs a FAILURE on a request path at error severity, prefixed with the
// request's correlation ID. Use WarnR for a request the handler continued
// through: a skipped row, a cleanup that did not finish, a fallback.
//
// The ID used to reach three places only: the access-log summary line, the
// X-Request-Id response header and, optionally, a response body. Every other
// line the panel wrote carried nothing, so an operator handed an ID by a user
// could find the one `http reqid=... status=500` line and then had to match the
// actual cause by timestamp proximity. On a panel serving concurrent dashboard
// polls that is ambiguous, which means the ID identified THAT a request failed
// but not WHY, the question it exists to answer.
//
// Use this instead of log.Printf in anything reachable from an HTTP handler.
// The format string and arguments are the caller's, unchanged; only the prefix
// is added. A request with no ID (a background caller passing a synthetic
// request, or a handler invoked directly in a test) logs without the prefix
// rather than with an empty one.
func LogR(r *http.Request, format string, args ...any) {
	// #nosec G706 -- the caller's own values, logged exactly as log.Printf would have; the prefix is a chi-generated id.
	logx.Errorf(reqPrefix(r)+format, args...)
}

// WarnR logs a degraded path on a request, prefixed with the same correlation
// ID. A row the handler skipped and a request the handler could not answer are
// different facts, and a journal that calls both an error cannot be filtered.
func WarnR(r *http.Request, format string, args ...any) {
	// #nosec G706 -- the caller's own values, logged exactly as log.Printf would have; the prefix is a chi-generated id.
	logx.Warnf(reqPrefix(r)+format, args...)
}

// reqPrefix renders the correlation prefix, or "" when there is no ID to carry.
func reqPrefix(r *http.Request) string {
	if r == nil {
		return ""
	}
	id := chimw.GetReqID(r.Context())
	if id == "" {
		return ""
	}
	return "reqid=" + id + " "
}
