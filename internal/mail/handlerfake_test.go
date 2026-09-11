package mail

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/auth"

	"github.com/go-chi/chi/v5"
)

// The reads nearly every mail handler starts with, as script fragments.
const (
	domainLookup = "SELECT system_user FROM domains WHERE id=?"
	mailboxOwned = "SELECT COUNT(*) FROM mailboxes WHERE id=? AND domain_id=?"
	auditInsert  = "INSERT INTO audit_log"
)

// handlerScript answers the domain lookup for domain 1 and the ownership check
// for its mailbox, which is where every mailbox handler begins.
func handlerScript() *sqlScript {
	s := newScript()
	s.rows[domainLookup] = [][]driver.Value{{"c_tenant"}}
	s.rows[mailboxOwned] = [][]driver.Value{{int64(1)}}
	return s
}

// mailRequest builds a request for a mail handler, carrying the chi URL
// parameters the handler reads and, when role is set, the caller's claims.
func mailRequest(method, target, body, role string, params map[string]string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	for key, value := range params {
		routeCtx.URLParams.Add(key, value)
	}
	ctx := context.WithValue(request.Context(), chi.RouteCtxKey, routeCtx)
	if role != "" {
		ctx = auth.WithClaims(ctx, &auth.Claims{UserID: 7, Username: "actor", Role: role})
	}
	return request.WithContext(ctx)
}

// jsonBody decodes a handler's JSON answer.
func jsonBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", recorder.Body.String(), err)
	}
	return body
}

// assertAnswer checks a handler's status and the text its JSON error or body
// carries.
func assertAnswer(t *testing.T, recorder *httptest.ResponseRecorder, status int, contains string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, status, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), contains) {
		t.Fatalf("body = %s, want it to hold %q", recorder.Body.String(), contains)
	}
}

// auditActions returns the action of every audit row the handler wrote.
func auditActions(s *sqlScript) []string {
	var actions []string
	for _, statement := range s.execsContaining(auditInsert) {
		if len(statement.args) > 3 {
			if action, ok := statement.args[3].(string); ok {
				actions = append(actions, action)
			}
		}
	}
	return actions
}
