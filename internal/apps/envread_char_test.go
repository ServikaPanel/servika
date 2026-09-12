package apps

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// getEnv reads the environment of application 4 on domain 7.
func getEnv(t *testing.T, script *sqlScript) *httptest.ResponseRecorder {
	t.Helper()
	route := chi.NewRouteContext()
	route.URLParams.Add("id", "7")
	route.URLParams.Add("aid", "4")
	r := httptest.NewRequest(http.MethodGet, "/domains/7/apps/4/env", nil)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
	recorder := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).EnvRead(recorder, r)
	return recorder
}

// This endpoint is reachable by the domain's own customer, the lowest privilege
// the panel has. The driver's message names the table and the column it failed
// on, so it belongs in the log, not in the response.
func TestAFailedEnvironmentReadDoesNotNameTheSchema(t *testing.T) {
	script := writable(t, 1)
	script.fail["FROM app_env"] = errors.New("Error 1054 (42S22): Unknown column 'value' in 'field list'")

	recorder := getEnv(t, script)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (%s)", recorder.Code, http.StatusInternalServerError, recorder.Body)
	}
	body := recorder.Body.String()
	for _, leaked := range []string{"app_env", "Unknown column", "42S22"} {
		if strings.Contains(body, leaked) {
			t.Errorf("the response names %q: %s", leaked, body)
		}
	}
	if !strings.Contains(body, "the application environment could not be read") {
		t.Errorf("the generic message is missing: %s", body)
	}
}

// The ordinary read still answers the stored values with the reserved names and
// the allocated port beside them.
func TestAnEnvironmentReadAnswersTheValuesAndThePort(t *testing.T) {
	script := writable(t, 1)
	script.rows["FROM app_env"] = nil

	recorder := getEnv(t, script)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (%s)", recorder.Code, http.StatusOK, recorder.Body)
	}
	for _, want := range []string{`"env":`, `"reserved":`, `"port":`} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Errorf("the response is missing %s: %s", want, recorder.Body)
		}
	}
}
