package apps

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// What an environment write DOES: it replaces every stored value, republishes
// the root-only environment file and restarts a running application.

// putEnv sends an environment write for application 4 on domain 7.
func putEnv(t *testing.T, script *sqlScript, env map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"env": env})
	if err != nil {
		t.Fatalf("build the body: %v", err)
	}
	return putEnvBody(t, script, string(body))
}

// putEnvBody sends a raw body, for the cases a map cannot express.
func putEnvBody(t *testing.T, script *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	route := chi.NewRouteContext()
	route.URLParams.Add("id", "7")
	route.URLParams.Add("aid", "4")
	r := httptest.NewRequest(http.MethodPut, "/domains/7/apps/4/env", strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
	recorder := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).EnvWrite(recorder, r)
	return recorder
}

// writable is a script that answers every query an environment write makes.
func writable(t *testing.T, enabled int64) *sqlScript {
	t.Helper()
	script := newScript()
	domainRow(script)
	scriptAppRow(script, enabled)
	return script
}

// A write stores the values, publishes the file and restarts the application.
func TestAnEnvironmentWritePublishesAndRestarts(t *testing.T) {
	host := fakeHost(t)
	script := writable(t, 1)

	recorder := putEnv(t, script, map[string]string{"DATABASE_URL": "postgres://u:p@h/db"})

	assertStatus(t, recorder, http.StatusOK, `"ok":true`)
	if !script.ran("DELETE FROM app_env WHERE app_id=?") {
		t.Errorf("the old environment was not cleared: %v", script.steps)
	}
	stored := script.argsOf(t, "INSERT INTO app_env(")
	if value, ok := stored[2].(string); !ok || strings.Contains(value, "postgres://") {
		t.Errorf("the value reached the column in the clear: %v", stored[2])
	}
	body := host.envBody(t, 4)
	if !strings.Contains(body, "DATABASE_URL=postgres://u:p@h/db") {
		t.Errorf("the environment file does not carry the value:\n%s", body)
	}
	if !host.ran("restart") {
		t.Errorf("the running application was not restarted: %v", host.calls)
	}
}

// A stopped application stays stopped: a write is not a start.
func TestAnEnvironmentWriteDoesNotStartAStoppedApplication(t *testing.T) {
	host := fakeHost(t)

	recorder := putEnv(t, writable(t, 0), map[string]string{"A": "1"})

	assertStatus(t, recorder, http.StatusOK, `"ok":true`)
	if host.ran("restart") {
		t.Errorf("a stopped application was restarted: %v", host.calls)
	}
}

// Everything an environment write refuses.
func TestAnEnvironmentWriteRefusesWhatMustNotReachTheFile(t *testing.T) {
	for _, tc := range []struct {
		name, message string
		body          string
		env           map[string]string
		script        func(*sqlScript)
		status        int
	}{
		{
			name:   "a domain that is not there",
			env:    map[string]string{"A": "1"},
			script: func(s *sqlScript) { s.rows["FROM domains"] = nil },
			status: http.StatusNotFound, message: "domain not found",
		},
		{
			name:   "an application that is not there",
			env:    map[string]string{"A": "1"},
			script: func(s *sqlScript) { s.rows["FROM apps WHERE id=? AND domain_id=?"] = nil },
			status: http.StatusNotFound, message: "application not found",
		},
		{
			name: "a body that is not JSON", body: `{"env":`,
			status: http.StatusBadRequest, message: "invalid request body",
		},
		{
			name:   "a name that is not a shell variable",
			env:    map[string]string{"9LIVES": "1"},
			status: http.StatusBadRequest, message: "is not a valid environment variable name",
		},
		{
			name:   "a name the panel owns",
			env:    map[string]string{"PORT": "9999"},
			status: http.StatusBadRequest, message: "cannot be overridden",
		},
		{
			name:   "a value carrying a second variable",
			env:    map[string]string{"A": "1\nADMIN=1"},
			status: http.StatusBadRequest, message: "holds a line break or is too long",
		},
		{
			name:   "an environment that cannot be stored",
			env:    map[string]string{"A": "1"},
			script: func(s *sqlScript) { s.fail["INSERT INTO app_env("] = errors.New("disk full") },
			status: http.StatusInternalServerError, message: "the environment could not be saved",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeHost(t)
			script := writable(t, 1)
			if tc.script != nil {
				tc.script(script)
			}
			if tc.body != "" {
				assertStatus(t, putEnvBody(t, script, tc.body), tc.status, tc.message)
				return
			}
			assertStatus(t, putEnv(t, script, tc.env), tc.status, tc.message)
		})
	}
}

// The cap exists so one request cannot write an unbounded EnvironmentFile.
func TestAnEnvironmentWriteRefusesTooManyVariables(t *testing.T) {
	fakeHost(t)
	env := make(map[string]string, 201)
	for i := range 201 {
		env["VAR_"+strconv.Itoa(i)] = "1"
	}

	assertStatus(t, putEnv(t, writable(t, 1), env),
		http.StatusBadRequest, "too many environment variables")
}

// A file that cannot be published is a different answer from one that cannot be
// stored, because the row is already written when it happens.
func TestAnEnvironmentFileThatCannotBePublishedSaysSo(t *testing.T) {
	host := fakeHost(t)
	// A regular file where the directory belongs: MkdirAll then refuses.
	if err := os.RemoveAll(host.envDir); err != nil {
		t.Fatalf("clear the environment directory: %v", err)
	}
	if err := os.WriteFile(host.envDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("plant a file where the directory belongs: %v", err)
	}

	assertStatus(t, putEnv(t, writable(t, 1), map[string]string{"A": "1"}),
		http.StatusInternalServerError, "the environment could not be published")
}

// The environment was saved even when the restart fails, so the answer says
// both rather than reading as a failed write.
func TestARestartFailureAfterAnEnvironmentWriteSaysTheWriteSucceeded(t *testing.T) {
	host := fakeHost(t)
	host.failing["restart"] = true

	assertStatus(t, putEnv(t, writable(t, 1), map[string]string{"A": "1"}),
		http.StatusInternalServerError, "the environment was saved but the application could not be restarted")
}

// A value that cannot be decrypted must not be echoed back as ciphertext.
func TestAnEnvironmentReadRefusesAValueItCannotOpen(t *testing.T) {
	fakeHost(t)
	script := writable(t, 1)
	script.rows["SELECT name, value FROM app_env"] = [][]driver.Value{{"A", "enc:v1:not-a-sealed-value"}}

	if _, err := ReadEnv(context.Background(), scriptDB(t, script), 4); err == nil {
		t.Fatal("a value that cannot be decrypted was returned")
	}
}
