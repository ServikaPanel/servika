package middleware

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// chi's own RequestID takes the id out of the client's X-Request-Id header, and
// the panel mounts it before authentication, so the correlation id an
// unauthenticated caller chose reached the access log, the LogR prefix, the
// response header and every error body. These tests measure that the id is the
// server's own whatever the client sends.

// captureLog collects what the middleware writes for one test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previousOutput, previousFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
	})
	return &buf
}

// loggedRequest runs one request through the middleware the router mounts, and
// returns the response and everything that was logged.
func loggedRequest(t *testing.T, header string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	buf := captureLog(t)
	router := chi.NewRouter()
	router.Use(RequestID, RequestIDHeader, AccessLog)
	router.Get("/auth/login", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	request := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	if header != "" {
		request.Header.Set(chimw.RequestIDHeader, header)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response, buf.String()
}

// The forged value carries a newline and the rest of an access-log line, which
// is what the access-log format allows: reqid is its FIRST field, so a value
// that ends a line can supply every field of the next one.
const forgedID = "x\nhttp reqid=forged ip=203.0.113.9 method=POST route=\"/auth/login\" status=200 bytes=0 dur=1ms"

func TestAClientCannotChooseTheCorrelationID(t *testing.T) {
	response, logged := loggedRequest(t, forgedID)

	if got := response.Header().Get("X-Request-Id"); got == forgedID || got == "" {
		t.Errorf("the response echoes the client's own id: %q", got)
	}
	if strings.Contains(logged, "forged") {
		t.Errorf("the client wrote its own access-log line:\n%s", logged)
	}
	if lines := strings.Count(strings.TrimSpace(logged), "\n") + 1; lines != 1 {
		t.Errorf("the request produced %d log lines, want one:\n%s", lines, logged)
	}
}

// The id is still there when the client sends nothing, and the log line and the
// response header carry the SAME one: an id that did not correlate the two
// would be no correlation id at all.
func TestTheGeneratedIDReachesBothTheHeaderAndTheLog(t *testing.T) {
	response, logged := loggedRequest(t, "")

	id := response.Header().Get("X-Request-Id")
	if id == "" {
		t.Fatal("the response carries no correlation id")
	}
	if !strings.Contains(logged, "reqid="+id+" ") {
		t.Errorf("the log line does not carry %q:\n%s", id, logged)
	}
}
