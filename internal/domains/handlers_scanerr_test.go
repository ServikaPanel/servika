package domains

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// errDBUnavailable stands in for what MariaDB returns while it is restarting or
// its connection pool is exhausted: not sql.ErrNoRows, just "no answer".
var errDBUnavailable = errors.New("connection refused")

type failingConnector struct{}

func (failingConnector) Open(string) (driver.Conn, error) { return nil, errDBUnavailable }

func init() { sql.Register("domains_failing_db", failingConnector{}) }

// failingDB returns a database handle whose every query fails the way a
// temporarily unreachable server does. No network is touched.
func failingDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("domains_failing_db", "")
	if err != nil {
		t.Fatalf("open the failing database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// requestWithParams builds a request carrying the chi URL parameters the
// handler reads, since the handlers run outside the router here.
func requestWithParams(method, body string, params map[string]string) *http.Request {
	r := httptest.NewRequest(method, "/", strings.NewReader(body))
	rc := chi.NewRouteContext()
	for k, v := range params {
		rc.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

func errorMessage(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode the error body %q: %v", recorder.Body.String(), err)
	}
	return body.Error
}

// A Scan error that is not ErrNoRows must stop the request at the read.
//
// Continuing past it is not a cosmetic problem: the scanned identifiers stay
// empty, so each of these handlers would drive the provisioner, the FTP account
// or the database drop with an empty domain name and system user. The assertion
// is on the message rather than the status alone: every one of these handlers
// also answers 500 when the work it should never have started fails, so a
// status-only check would pass against the unfixed code.
func TestHandlersStopOnAReadFailureInsteadOfActingOnEmptyValues(t *testing.T) {
	handlers := &Handlers{DB: failingDB(t)}

	tests := []struct {
		name    string
		request *http.Request
		call    func(http.ResponseWriter, *http.Request)
	}{
		{
			name:    "SSLIssue",
			request: requestWithParams(http.MethodPost, `{"type":"self-signed"}`, map[string]string{"id": "7"}),
			call:    handlers.SSLIssue,
		},
		{
			name:    "SSLDisable",
			request: requestWithParams(http.MethodDelete, "", map[string]string{"id": "7"}),
			call:    handlers.SSLDisable,
		},
		{
			name:    "SetFTPPassword",
			request: requestWithParams(http.MethodPut, `{"password":"Aa1!aaaaaaaaaaaa"}`, map[string]string{"id": "7"}),
			call:    handlers.SetFTPPassword,
		},
		{
			name:    "DeleteDatabase",
			request: requestWithParams(http.MethodDelete, "", map[string]string{"id": "7", "dbid": "3"}),
			call:    handlers.DeleteDatabase,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			test.call(recorder, test.request)

			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", recorder.Code)
			}
			if got := errorMessage(t, recorder); got != "database read failed" {
				t.Errorf("error = %q, want the read to be reported; the handler carried on past it", got)
			}
		})
	}
}
