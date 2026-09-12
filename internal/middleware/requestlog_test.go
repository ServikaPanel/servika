package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/logsink"

	"github.com/go-chi/chi/v5"
)

// capturedRows collects what the middleware queued, instead of a database.
func capturedRows(t *testing.T) *[]logsink.RequestRow {
	t.Helper()
	var rows []logsink.RequestRow
	previous := queueRequest
	queueRequest = func(row logsink.RequestRow) { rows = append(rows, row) }
	t.Cleanup(func() { queueRequest = previous })
	return &rows
}

// loggedCall runs one request through the router the panel mounts and returns
// what the handler read from the body.
func loggedCall(t *testing.T, method, pattern, target, contentType, body string) (*[]logsink.RequestRow, string) {
	t.Helper()
	rows := capturedRows(t)
	var seenByHandler string

	router := chi.NewRouter()
	router.Use(RequestID, RequestLog)
	handler := func(w http.ResponseWriter, r *http.Request) {
		read, _ := io.ReadAll(r.Body)
		seenByHandler = string(read)
		w.WriteHeader(http.StatusCreated)
	}
	router.Method(method, pattern, http.HandlerFunc(handler))

	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	request.Header.Set("User-Agent", "curl/8.0")
	router.ServeHTTP(httptest.NewRecorder(), request)
	return rows, seenByHandler
}

// The row carries what a journald line cannot: the user agent, the body and the
// identity. This is the reason the table exists at all.
func TestARequestIsRecordedWithItsOutcome(t *testing.T) {
	rows, _ := loggedCall(t, http.MethodPost, "/api/v1/domains/{id}/ssl",
		"/api/v1/domains/7/ssl", "application/json", `{"force":true}`)

	if len(*rows) != 1 {
		t.Fatalf("%d row(s) were queued, expected 1", len(*rows))
	}
	row := (*rows)[0]
	if row.Method != http.MethodPost {
		t.Errorf("method is %q", row.Method)
	}
	if row.ResponseStatus != http.StatusCreated {
		t.Errorf("status is %d, want 201", row.ResponseStatus)
	}
	if row.UserAgent != "curl/8.0" {
		t.Errorf("user agent is %q", row.UserAgent)
	}
	if row.RequestID == "" {
		t.Error("the row carries no correlation id, so it joins nothing")
	}
	// The PATTERN, not the path: a row per domain id groups with nothing.
	if row.Endpoint != "/api/v1/domains/{id}/ssl" {
		t.Errorf("endpoint is %q, want the route pattern", row.Endpoint)
	}
	if row.Module != "domains" || row.Action != "ssl" {
		t.Errorf("module/action are %q/%q, want domains/ssl", row.Module, row.Action)
	}
}

// The middleware reads the body before the handler does. It must put it back,
// or every write endpoint in the panel receives an empty document.
func TestTheHandlerStillReadsTheWholeBody(t *testing.T) {
	const body = `{"username":"root","password":"hunter2"}`

	_, seenByHandler := loggedCall(t, http.MethodPost, "/api/v1/auth/login",
		"/api/v1/auth/login", "application/json", body)

	if seenByHandler != body {
		t.Errorf("the handler read %q, want the whole body", seenByHandler)
	}
}

// The login body is the case this must never get wrong.
func TestALoggedBodyCarriesNoPassword(t *testing.T) {
	rows, _ := loggedCall(t, http.MethodPost, "/api/v1/auth/login",
		"/api/v1/auth/login", "application/json", `{"username":"root","password":"hunter2"}`)

	stored := (*rows)[0].RequestBody
	if strings.Contains(stored, "hunter2") {
		t.Errorf("the stored body holds the password: %s", stored)
	}
	if !strings.Contains(stored, "root") {
		t.Errorf("the stored body lost the username, which is what makes the row useful: %s", stored)
	}
}

// An upload streams gigabytes. Reading it here to store nothing would hold the
// whole file in memory on the request path.
func TestAnUploadBodyIsNeverRead(t *testing.T) {
	rows, seenByHandler := loggedCall(t, http.MethodPost, "/api/v1/files/upload",
		"/api/v1/files/upload", "multipart/form-data; boundary=x", "--x\r\nbinary\r\n--x--")

	if (*rows)[0].RequestBody != "" {
		t.Errorf("an upload body was stored: %s", (*rows)[0].RequestBody)
	}
	if seenByHandler == "" {
		t.Error("the handler received nothing, so the upload was consumed by the log")
	}
}

// A query string carries a token as readily as a body does.
func TestAQueryStringIsStoredRedacted(t *testing.T) {
	rows, _ := loggedCall(t, http.MethodGet, "/api/v1/domains",
		"/api/v1/domains?page=2&token=abc123", "", "")

	stored := (*rows)[0].QueryParams
	if strings.Contains(stored, "abc123") {
		t.Errorf("the query string holds the token: %s", stored)
	}
	if !strings.Contains(stored, `"page":"2"`) {
		t.Errorf("the ordinary parameter was lost: %s", stored)
	}
}

// Health checks are polled continuously by update and restore automation. They
// would fill the table with the one request that tells an operator nothing.
func TestAHealthCheckIsNotRecorded(t *testing.T) {
	rows := capturedRows(t)
	router := chi.NewRouter()
	router.Use(RequestID, RequestLog)
	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if len(*rows) != 0 {
		t.Errorf("%d health check(s) were recorded", len(*rows))
	}
}

// An unauthenticated request is recorded too, with no identity. A failed login
// is exactly the row an operator comes looking for.
func TestAnAnonymousRequestIsStillRecorded(t *testing.T) {
	rows, _ := loggedCall(t, http.MethodPost, "/api/v1/auth/login",
		"/api/v1/auth/login", "application/json", `{"username":"root"}`)

	row := (*rows)[0]
	if row.UserID != 0 || row.Username != "" {
		t.Errorf("an anonymous request recorded uid=%d user=%q", row.UserID, row.Username)
	}
	if row.Endpoint == "" {
		t.Error("the row was recorded without an endpoint")
	}
}

// A log ingest body is itself a log. Copying a session replay batch into
// request_logs would hold megabytes in memory to store nothing, because the
// batch is far past the capture limit and is dropped right after the copy.
func TestALogIngestBodyIsNotCopiedIntoTheRow(t *testing.T) {
	for _, target := range []string{"/api/v1/ui-events", "/api/v1/replay"} {
		rows, seenByHandler := loggedCall(t, http.MethodPost, target, target,
			"application/json", `{"session_id":"abc","events":[1,2,3]}`)

		row := (*rows)[0]
		if row.RequestBody != "" {
			t.Errorf("%s stored its body in the row: %q", target, row.RequestBody)
		}
		if row.Endpoint != target {
			t.Errorf("%s was not recorded at all: %+v", target, row)
		}
		// The handler must still receive the body it was sent.
		if !strings.Contains(seenByHandler, `"session_id":"abc"`) {
			t.Errorf("%s: the handler read %q, want the whole body", target, seenByHandler)
		}
	}
}

// moduleAction reads the pattern, so the table can be grouped by feature.
func TestTheModuleAndActionComeFromTheRoutePattern(t *testing.T) {
	for _, check := range []struct{ pattern, module, action string }{
		{"/api/v1/domains/{id}/ssl", "domains", "ssl"},
		{"/api/v1/domains", "domains", ""},
		{"/api/v1/domains/{id}", "domains", ""},
		{"/api/v1/system/session-idle", "system", "session-idle"},
		{"/healthz", "healthz", ""},
		{"", "", ""},
	} {
		module, action := moduleAction(check.pattern)
		if module != check.module || action != check.action {
			t.Errorf("%q gave %q/%q, want %q/%q", check.pattern, module, action, check.module, check.action)
		}
	}
}
