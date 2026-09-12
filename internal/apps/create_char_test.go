package apps

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"servika/internal/appruntime"
)

// What a create DOES, pinned before the handler is split: the row it writes,
// the unit it installs, the systemd state it asks for, and the rollback when
// the host does not take the application.

const createBodyJSON = `{"name":"api","runtime":"node","runtime_version":"22",` +
	`"app_root":"api","start_command":"node server.js","mount_path":"/api"}`

// postCreate sends a create for domain 7.
func postCreate(t *testing.T, script *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	route := chi.NewRouteContext()
	route.URLParams.Add("id", "7")
	r := httptest.NewRequest(http.MethodPost, "/domains/7/apps", strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, route))
	recorder := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).Create(recorder, r)
	return recorder
}

// creatable is a script that answers every query a successful create makes.
func creatable(t *testing.T) *sqlScript {
	t.Helper()
	script := newScript()
	script.insertID = 4
	domainRow(script)
	script.rows["SELECT MAX(port) FROM apps"] = [][]driver.Value{{nil}}
	scriptAppRow(script, 1)
	noEnvironment(script)
	return script
}

// assertStatus checks the status and the message of an answer.
func assertStatus(t *testing.T, recorder *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if recorder.Code != status || !strings.Contains(recorder.Body.String(), message) {
		t.Fatalf("status = %d, body = %s; want %d carrying %q",
			recorder.Code, recorder.Body.String(), status, message)
	}
}

// A create writes the row, publishes the unit and starts the application.
func TestACreatePublishesTheApplication(t *testing.T) {
	host := fakeHost(t)
	script := creatable(t)

	recorder := postCreate(t, script, createBodyJSON)

	assertStatus(t, recorder, http.StatusCreated, `"name":"api"`)
	assertStoredRow(t, script.argsOf(t, "INSERT INTO apps("))
	assertPublished(t, host)
}

// assertStoredRow checks the INSERT arguments: domain_id, subdomain_id, name,
// runtime, runtime_version, app_root, start_command, mount_path, port.
func assertStoredRow(t *testing.T, inserted []driver.Value) {
	t.Helper()
	want := []driver.Value{int64(7), nil, "api", "node", "22", "api", "node server.js", "/api/"}
	for i, value := range want {
		if inserted[i] != value {
			t.Errorf("stored row = %v, column %d is %v, want %v", inserted, i, inserted[i], value)
		}
	}
	if port, ok := inserted[8].(int64); !ok || port < PortMin || port > PortMax {
		t.Errorf("the allocated port is %v, outside %d-%d", inserted[8], PortMin, PortMax)
	}
}

// assertPublished checks what reached the host.
func assertPublished(t *testing.T, host *appHost) {
	t.Helper()
	unit := host.unitBody(t, 4)
	if !strings.Contains(unit, "User="+testUser) || !strings.Contains(unit, "ExecStart=") {
		t.Errorf("the installed unit does not describe the application:\n%s", unit)
	}
	if !strings.Contains(host.envBody(t, 4), "PORT=30001") {
		t.Errorf("the environment file does not carry the port: %q", host.envBody(t, 4))
	}
	if !host.ran("enable --now") || !host.ran("daemon-reload") {
		t.Errorf("systemd was not asked to start the application: %v", host.calls)
	}
}

// A mount path takes its trailing slash before it is stored, or nginx would
// also match a sibling path the tenant did not hand over.
func TestACreateStoresTheNormalizedMount(t *testing.T) {
	fakeHost(t)
	script := creatable(t)

	postCreate(t, script, strings.Replace(createBodyJSON, `"mount_path":"/api"`, `"mount_path":""`, 1))

	if mount := script.argsOf(t, "INSERT INTO apps(")[7]; mount != "/" {
		t.Errorf("stored mount = %v, want the normalized root", mount)
	}
}

// Everything a create refuses, and what it says.
func TestACreateRefusesWhatItMustNotPublish(t *testing.T) {
	for _, tc := range []struct {
		name, body, message string
		script              func(*sqlScript)
		status              int
	}{
		{
			name: "a domain that is not there", body: createBodyJSON,
			script: func(s *sqlScript) {
				s.rows["SELECT system_user, COALESCE(php_version,'8.3') FROM domains"] = nil
			},
			status: http.StatusNotFound, message: "domain not found",
		},
		{
			name: "a body that is not JSON", body: `{"name":`,
			status: http.StatusBadRequest, message: "invalid request body",
		},
		{
			name: "a plan whose application limit is reached", body: createBodyJSON,
			script: func(s *sqlScript) {
				s.rows["SELECT customer_id FROM domains"] = [][]driver.Value{{int64(3)}}
				s.rows["SELECT plan_id FROM customers"] = [][]driver.Value{{int64(2)}}
				s.rows["SELECT COALESCE(max_app,0) FROM service_plans"] = [][]driver.Value{{int64(1)}}
				s.rows["SELECT COUNT(*) FROM apps a JOIN domains d"] = [][]driver.Value{{int64(1)}}
			},
			status: http.StatusForbidden, message: "maximum 1 applications",
		},
		{
			name: "a plan limit that cannot be read", body: createBodyJSON,
			script: func(s *sqlScript) {
				s.rows["SELECT customer_id FROM domains"] = [][]driver.Value{{int64(3)}}
				s.fail["SELECT plan_id FROM customers"] = errors.New("connection lost")
			},
			status: http.StatusInternalServerError, message: "the plan limit could not be verified",
		},
		{
			name:   "a name that is not a name",
			body:   strings.Replace(createBodyJSON, `"name":"api"`, `"name":""`, 1),
			status: http.StatusBadRequest, message: "invalid application name",
		},
		{
			// Measured: the ".." check answers before the join, so the message
			// names the field rather than the home directory.
			name:   "a directory outside the home",
			body:   strings.Replace(createBodyJSON, `"app_root":"api"`, `"app_root":"../other"`, 1),
			status: http.StatusBadRequest, message: "invalid application directory",
		},
		{
			name:   "a start command carrying a second directive",
			body:   strings.Replace(createBodyJSON, `node server.js`, `node %n.js`, 1),
			status: http.StatusBadRequest, message: "systemd expands",
		},
		{
			name: "a domain whose login is not a tenant's", body: createBodyJSON,
			script: func(s *sqlScript) {
				s.rows["SELECT system_user, COALESCE(php_version,'8.3') FROM domains"] =
					[][]driver.Value{{"root", "8.3"}}
			},
			status: http.StatusNotFound, message: "domain not found",
		},
		{
			name:   "a mount path that would leave its location",
			body:   strings.Replace(createBodyJSON, `"mount_path":"/api"`, `"mount_path":"/api/../.."`, 1),
			status: http.StatusBadRequest, message: "invalid mount path",
		},
		{
			name: "a row that cannot be stored", body: createBodyJSON,
			script: func(s *sqlScript) { s.fail["INSERT INTO apps("] = errors.New("connection lost") },
			status: http.StatusInternalServerError, message: "the application could not be created",
		},
		{
			name: "a row that cannot be read back", body: createBodyJSON,
			script: func(s *sqlScript) { s.rows["FROM apps WHERE id=? AND domain_id=?"] = nil },
			status: http.StatusInternalServerError, message: "the application could not be created",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeHost(t)
			script := creatable(t)
			if tc.script != nil {
				tc.script(script)
			}

			assertStatus(t, postCreate(t, script, tc.body), tc.status, tc.message)
		})
	}
}

// A subdomain belonging to another domain must not carry this application, and
// FAIL-CLOSED: a count that cannot be read refuses rather than attaching.
func TestACreateChecksTheSubdomainBelongsToTheDomain(t *testing.T) {
	for _, tc := range []struct {
		name, message string
		script        func(*sqlScript)
	}{
		{
			name:    "the subdomain is on another domain",
			script:  func(s *sqlScript) { s.rows["FROM subdomains WHERE id=?"] = [][]driver.Value{{int64(0)}} },
			message: "does not belong to this domain",
		},
		{
			name:    "the count cannot be read",
			script:  func(s *sqlScript) { s.fail["FROM subdomains WHERE id=?"] = errors.New("connection lost") },
			message: "the subdomain could not be verified",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeHost(t)
			script := creatable(t)
			tc.script(script)

			recorder := postCreate(t, script,
				strings.Replace(createBodyJSON, `"mount_path":"/api"`, `"mount_path":"/api","subdomain_id":9`, 1))

			assertStatus(t, recorder, http.StatusBadRequest, tc.message)
		})
	}
}

// A subdomain of this domain is stored on the row, so the proxy block lands in
// the subdomain's own server block.
func TestACreateStoresAnOwnedSubdomain(t *testing.T) {
	fakeHost(t)
	var rendered int64
	setForTest(t, &RenderSubdomain, func(_ *sql.DB, subdomainID int64) error {
		rendered = subdomainID
		return nil
	})
	script := creatable(t)
	script.rows["FROM subdomains WHERE id=?"] = [][]driver.Value{{int64(1)}}
	script.rows["FROM apps WHERE id=? AND domain_id=?"] = [][]driver.Value{
		{int64(4), int64(7), int64(9), "api", "node", "22", "api", "node server.js", "/api/", int64(30001), int64(1)},
	}

	recorder := postCreate(t, script,
		strings.Replace(createBodyJSON, `"mount_path":"/api"`, `"mount_path":"/api","subdomain_id":9`, 1))

	assertStatus(t, recorder, http.StatusCreated, `"subdomain_id":9`)
	if script.argsOf(t, "INSERT INTO apps(")[1] != int64(9) {
		t.Errorf("the subdomain was not stored: %v", script.argsOf(t, "INSERT INTO apps("))
	}
	if rendered != 9 {
		t.Errorf("the subdomain's own server block was not rewritten (rendered=%d)", rendered)
	}
}

// The whole port range being taken is a different answer from a failed insert,
// because the operator has to widen the range rather than retry.
func TestACreateWithNoFreePortSaysSo(t *testing.T) {
	fakeHost(t)
	setForTest(t, &portFree, func(int) bool { return false })
	script := creatable(t)

	assertStatus(t, postCreate(t, script, createBodyJSON),
		http.StatusServiceUnavailable, "no free application port")
}

// An application is never created against an interpreter that is not there,
// because the unit would be written and would then fail to start for good.
func TestACreateRefusesAMissingRuntime(t *testing.T) {
	fakeHost(t)
	setForTest(t, &resolveRuntimePath, func(appruntime.Kind, string) (string, bool) { return "", false })

	assertStatus(t, postCreate(t, creatable(t), createBodyJSON),
		http.StatusBadRequest, "is not installed on this server")
}

// A rollback that cannot remove the row still reports the create as failed,
// because the application is not running either way.
func TestARollbackThatCannotRemoveTheRowStillFails(t *testing.T) {
	host := fakeHost(t)
	host.failing["enable"] = true
	script := creatable(t)
	script.fail["DELETE FROM apps WHERE id=?"] = errors.New("connection lost")

	assertStatus(t, postCreate(t, script, createBodyJSON),
		http.StatusInternalServerError, "the application could not be started")
}

// The three answers a failed insert maps to. The duplicate-key answer cannot be
// produced through AllocatePort, which retries a duplicate on the next port, so
// the mapping is measured directly.
func TestAFailedInsertIsReportedByItsCause(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		status  int
		message string
	}{
		{"the range is exhausted", ErrNoFreePort, http.StatusServiceUnavailable, "no free application port"},
		{
			"the mount is taken",
			errorString("Error 1062 (23000): Duplicate entry"),
			http.StatusConflict, "already answers on that path",
		},
		{"anything else", errors.New("connection lost"), http.StatusInternalServerError, "could not be created"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/domains/7/apps", nil)

			(&Handlers{}).createRefused(recorder, r, 7, tc.err)

			assertStatus(t, recorder, tc.status, tc.message)
		})
	}
}

// A host that does not take the application leaves no row and no port behind:
// a half-applied create is worse than a failed one.
func TestACreateThatCannotStartRollsTheRowBack(t *testing.T) {
	host := fakeHost(t)
	host.failing["enable"] = true
	script := creatable(t)

	assertStatus(t, postCreate(t, script, createBodyJSON),
		http.StatusInternalServerError, "the application could not be started")

	if !script.ran("DELETE FROM apps WHERE id=?") {
		t.Errorf("the row was not removed: %v", script.steps)
	}
	if !host.ran("disable --now") {
		t.Errorf("the unit was not torn down: %v", host.calls)
	}
	if host.unitBody(t, 4) != "" {
		t.Error("the unit file survived the rollback")
	}
}
