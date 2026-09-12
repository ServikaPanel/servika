package domains

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

const backendLookup = "SELECT system_user, php_version FROM domains"

// setBackend posts one backend change against the scripted database and reports
// the answer.
func setBackend(t *testing.T, script *sqlScript, backend string) *httptest.ResponseRecorder {
	t.Helper()
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", "42")
	request := httptest.NewRequest(http.MethodPost, "/domains/42/web-backend",
		strings.NewReader(`{"backend":"`+backend+`"}`))
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))

	recorder := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).SetWebBackend(recorder, request)
	return recorder
}

// The lookup must scan exactly the columns it selects. It used to read
// domain_name as well and throw it away with a blank assignment; a SELECT and a
// Scan that disagree fail at runtime as a 500 on a request that should work.
func TestChangingTheBackendReadsOnlyTheColumnsItUses(t *testing.T) {
	script := newScript()
	script.rows[backendLookup] = [][]driver.Value{{"c_example", "83"}}
	var renderedSocket, renderedVersion string
	var renderedID int64
	setForTest(t, &phpSocketFor, func(user, version string) (string, error) {
		return "/run/php-fpm/" + user + "-" + version + ".sock", nil
	})
	setForTest(t, &applyVhostForDomain, func(_ *sql.DB, id int64, socket, version string) error {
		renderedID, renderedSocket, renderedVersion = id, socket, version
		return nil
	})

	recorder := setBackend(t, script, "apache")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	updates := script.execsContaining("UPDATE domains SET web_backend")
	if len(updates) != 1 {
		t.Fatalf("the backend was written %d times, want once", len(updates))
	}
	if updates[0].args[0] != "apache" || updates[0].args[1] != int64(42) {
		t.Errorf("the update bound %v, want the backend and the domain id", updates[0].args)
	}
	// The two scanned values are the ones the render is given, so a column
	// dropped from the SELECT would show up here rather than nowhere.
	if renderedID != 42 || renderedSocket != "/run/php-fpm/c_example-83.sock" || renderedVersion != "83" {
		t.Errorf("the render got id=%d socket=%q version=%q", renderedID, renderedSocket, renderedVersion)
	}
}

// A domain that is not there is a 404, and nothing is written for it.
func TestChangingTheBackendOfAMissingDomainWritesNothing(t *testing.T) {
	script := newScript()
	script.rows[backendLookup] = nil
	setForTest(t, &applyVhostForDomain, func(*sql.DB, int64, string, string) error {
		t.Error("a missing domain reached the vhost render")
		return nil
	})

	recorder := setBackend(t, script, "static")

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", recorder.Code, recorder.Body.String())
	}
	if updates := script.execsContaining("UPDATE domains SET web_backend"); len(updates) != 0 {
		t.Errorf("a missing domain still wrote %d update(s)", len(updates))
	}
}
