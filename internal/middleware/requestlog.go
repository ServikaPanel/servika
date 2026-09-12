package middleware

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"servika/internal/httpx"
	"servika/internal/logsink"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// bodyCaptureLimit bounds what is read from a request body for the log.
//
// It matches logsink.MaxBodyBytes: reading more only to throw it away is work
// done on the request path for nothing.
const bodyCaptureLimit = logsink.MaxBodyBytes

// queueRequest is where a finished row goes. A test replaces it to read what
// the middleware assembled without opening a database.
var queueRequest = logsink.Request

// RequestLog records one request_logs row for every API request.
//
// It sits alongside AccessLog rather than replacing it. The journald line is
// written synchronously and survives a database that is down or not yet open;
// this row carries what a journald line cannot hold usefully: the user agent,
// the redacted body and query string, and the identity behind the request.
//
// Mount it AFTER RequestID, so the correlation id exists, and after BodyLimit,
// so a body this reads is already capped. It is deliberately outside
// RequireAuth: a failed login and a webhook call are requests an operator needs
// in the table too, and those carry no session, so user_id stays NULL for them.
func RequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health checks are polled continuously by update and restore
		// automation. Logging them would fill the table with the one request
		// that tells an operator nothing, exactly as AccessLog skips them.
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		body := captureBody(r)
		start := time.Now()
		recorder := chimw.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(recorder, r)

		queueRequest(buildRow(r, recorder, body, time.Since(start)))
	})
}

// captureBody reads what the log may keep and puts the body back for the
// handler.
//
// A body the log must not keep is never read at all: an upload streams
// gigabytes, and reading it here would hold the whole file in memory to store
// nothing. The content type decides, because that is what says whether the body
// is a JSON document at all.
func captureBody(r *http.Request) []byte {
	if r.Body == nil || !isLoggableBody(r) {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, bodyCaptureLimit+1))
	if err != nil {
		return nil
	}
	// The handler must still see the whole body. The unread remainder is
	// chained behind what was consumed, so an oversized body is served intact
	// even though the log keeps none of it.
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(body), r.Body), r.Body}
	return body
}

// isLoggableBody reports whether a body is worth reading for the log.
func isLoggableBody(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodDelete {
		return false
	}
	contentType := r.Header.Get("Content-Type")
	return strings.HasPrefix(contentType, "application/json")
}

// buildRow assembles the row from the finished request.
func buildRow(r *http.Request, recorder chimw.WrapResponseWriter, body []byte, took time.Duration) logsink.RequestRow {
	endpoint := chi.RouteContext(r.Context()).RoutePattern()
	if endpoint == "" {
		endpoint = r.URL.Path
	}
	module, action := moduleAction(endpoint)

	row := logsink.RequestRow{
		RequestID:      chimw.GetReqID(r.Context()),
		IP:             httpx.ClientIP(r),
		UserAgent:      r.Header.Get("User-Agent"),
		Method:         r.Method,
		Endpoint:       endpoint,
		Module:         module,
		Action:         action,
		ResponseStatus: recorder.Status(),
		ResponseMS:     took.Milliseconds(),
	}
	if claims := ClaimsFrom(r); claims != nil {
		row.UserID = claims.UserID
		row.Username = claims.Username
	}
	if params, ok := logsink.RedactPairs(r.URL.Query()); ok {
		row.QueryParams = params
	}
	if stored, ok := logsink.RedactJSON(body); ok {
		row.RequestBody = stored
	}
	return row
}

// moduleAction names the feature a route belongs to and what it does there.
//
// It reads the chi route PATTERN, not the path, so `/domains/{id}/ssl` groups
// with every other domain's SSL call instead of producing one module per
// domain id. The module is the first segment after the API version and the
// action is the last segment that is not a parameter, which is what makes
// "every failing SSL call today" a query rather than a scan.
func moduleAction(pattern string) (module, action string) {
	segments := make([]string, 0, 8)
	for segment := range strings.SplitSeq(pattern, "/") {
		if segment == "" || segment == "api" || segment == "v1" {
			continue
		}
		segments = append(segments, segment)
	}
	if len(segments) == 0 {
		return "", ""
	}
	module = segments[0]
	for i := len(segments) - 1; i >= 1; i-- {
		if !strings.HasPrefix(segments[i], "{") {
			return module, segments[i]
		}
	}
	return module, ""
}
