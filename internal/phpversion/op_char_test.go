package phpversion

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The two endpoints that hand work to dnf. Every refusal they make is a refusal
// the operator reads instead of an install, so each one is pinned by its status
// AND by its text: "unavailable" and "could not be verified" mean different
// things to somebody deciding whether to try again.

// countRows answers the one query Remove makes: how many domains hold a version.
type countRows struct {
	count int
	done  bool
}

func (r *countRows) Columns() []string { return []string{"count"} }
func (r *countRows) Close() error      { return nil }

func (r *countRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = int64(r.count)
	return nil
}

// countConn is a database whose only answer is that count, or a failure.
type countConn struct {
	count    int
	queryErr error
	queries  []string
}

func (c *countConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c *countConn) Driver() driver.Driver                        { return countDriver{} }
func (c *countConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c *countConn) Close() error                                 { return nil }
func (c *countConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c *countConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.queries = append(c.queries, query)
	if c.queryErr != nil {
		return nil, c.queryErr
	}
	return &countRows{count: c.count}, nil
}

type countDriver struct{}

func (countDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

func countDB(t *testing.T, conn *countConn) *sql.DB {
	t.Helper()
	db := sql.OpenDB(conn)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// stubLiveProbe answers the install gate's live dnf probe.
func stubLiveProbe(t *testing.T, available, checked bool) {
	t.Helper()
	previous := dnfLiveProbe
	dnfLiveProbe = func(string) (bool, bool) { return available, checked }
	t.Cleanup(func() { dnfLiveProbe = previous })
}

// postOp sends one request to a handler and returns its status and body.
func postOp(t *testing.T, handler http.HandlerFunc, body string) (int, map[string]any) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler(recorder, httptest.NewRequest(http.MethodPost, "/php-versions", strings.NewReader(body)))
	var decoded map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("the response is not JSON: %s", recorder.Body.String())
	}
	return recorder.Code, decoded
}

// errorOf returns the message an httpx refusal carries.
func errorOf(body map[string]any) string {
	message, _ := body["error"].(string)
	return message
}

// A version this server cannot install is refused before dnf is asked, and a
// dnf that could not be asked is NOT reported as an unavailable version: those
// two answers send an operator to completely different places.
func TestAnInstallRefusesBeforeItStartsAnything(t *testing.T) {
	remi := remiVersion(t)
	for _, tc := range []struct {
		name, body       string
		available, check bool
		state            string
		status           int
		message          string
	}{
		{
			name: "the body is not JSON", body: "{", check: true,
			status: http.StatusBadRequest, message: "invalid request body",
		},
		{
			name: "the version is not one this panel knows",
			body: `{"version":"5.6","resource":"remi"}`, check: true,
			status: http.StatusBadRequest, message: "unsupported version",
		},
		{
			name: "the version and the source do not belong together",
			body: `{"version":"` + remi.Version + `","resource":"appstream"}`, check: true,
			status: http.StatusBadRequest, message: "unsupported version",
		},
		{
			name: "dnf says the version is gone",
			body: `{"version":"` + remi.Version + `","resource":"remi"}`, check: true,
			status: http.StatusConflict, message: "is unavailable from the configured repositories",
		},
		{
			name:   "dnf could not be asked",
			body:   `{"version":"` + remi.Version + `","resource":"remi"}`,
			status: http.StatusConflict, message: "could not verify PHP",
		},
		{
			name:      "an operation is already running",
			body:      `{"version":"` + remi.Version + `","resource":"remi"}`,
			available: true, check: true, state: "active",
			status: http.StatusConflict, message: "already running",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opPaths(t)
			var started string
			stubUnit(t, tc.state, &started)
			stubLiveProbe(t, tc.available, tc.check)
			h := &Handlers{}

			status, body := postOp(t, h.Install, tc.body)

			if status != tc.status {
				t.Errorf("status %d, want %d (%v)", status, tc.status, body)
			}
			if !strings.Contains(errorOf(body), tc.message) {
				t.Errorf("message %q does not carry %q", errorOf(body), tc.message)
			}
			if started != "" {
				t.Error("a refused install still started a job")
			}
		})
	}
}

// The install is detached, so the answer says it STARTED rather than that it
// worked: the outcome belongs to the status and log endpoints.
func TestAnAcceptedInstallStartsTheJobAndSaysSo(t *testing.T) {
	opPaths(t)
	remi := remiVersion(t)
	var started string
	stubUnit(t, "inactive", &started)
	stubLiveProbe(t, true, true)
	h := &Handlers{}

	status, body := postOp(t, h.Install,
		`{"version":"`+remi.Version+`","resource":"remi"}`)

	if status != http.StatusAccepted {
		t.Fatalf("status %d, want 202 (%v)", status, body)
	}
	if body["started"] != true || body["version"] != remi.Version || body["source"] != "remi" {
		t.Errorf("body = %v", body)
	}
	if !strings.Contains(started, "dnf install -y") ||
		!strings.Contains(started, "php"+remi.Code+"-php-fpm") {
		t.Errorf("the job does not install the version:\n%s", started)
	}
	if descriptor := readOpDescriptor(); descriptor.Action != "install" ||
		descriptor.Version != remi.Version {
		t.Errorf("descriptor = %+v", descriptor)
	}
}

// A job that will not start is reported as a server failure rather than as an
// install in flight, or the screen polls for something that never began.
func TestAnInstallThatCannotStartIsNotReportedAsStarted(t *testing.T) {
	opPaths(t)
	remi := remiVersion(t)
	stubLiveProbe(t, true, true)
	previousState, previousLaunch := phpOpState, launchPHPOp
	phpOpState = func() string { return "inactive" }
	launchPHPOp = func(string) error { return errors.New("systemd-run: refused") }
	t.Cleanup(func() { phpOpState, launchPHPOp = previousState, previousLaunch })
	h := &Handlers{}

	status, body := postOp(t, h.Install, `{"version":"`+remi.Version+`","resource":"remi"}`)

	if status != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 (%v)", status, body)
	}
	if errorOf(body) != "could not start the installation" {
		t.Errorf("message %q", errorOf(body))
	}
}

// The same on the removal side: a job that will not start must not read as a
// removal in flight.
func TestARemovalThatCannotStartIsNotReportedAsStarted(t *testing.T) {
	opPaths(t)
	remi := remiVersion(t)
	previousState, previousLaunch := phpOpState, launchPHPOp
	phpOpState = func() string { return "inactive" }
	launchPHPOp = func(string) error { return errors.New("systemd-run: refused") }
	t.Cleanup(func() { phpOpState, launchPHPOp = previousState, previousLaunch })
	h := &Handlers{DB: countDB(t, &countConn{})}

	status, body := postOp(t, h.Remove, `{"version":"`+remi.Version+`","resource":"remi"}`)

	if status != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 (%v)", status, body)
	}
	if errorOf(body) != "could not start the removal" {
		t.Errorf("message %q", errorOf(body))
	}
}

// removeCase is one request the removal endpoint turns down.
type removeCase struct {
	name, body string
	count      int
	queryErr   error
	state      string
	status     int
	message    string
}

func removeRefusals(remi VersionMetadata) []removeCase {
	return []removeCase{
		{
			name: "the body is not JSON", body: "{",
			status: http.StatusBadRequest, message: "invalid request body",
		},
		{
			name: "the system PHP cannot be removed",
			body: `{"version":"8.3","resource":"appstream"}`,
			// Refused for BEING appstream, before the version is even matched.
			status: http.StatusForbidden, message: "cannot be removed",
		},
		{
			name:   "the version is not one this panel knows",
			body:   `{"version":"5.6","resource":"remi"}`,
			status: http.StatusBadRequest, message: "unsupported version",
		},
		{
			name: "the count cannot be read", body: `{"version":"` + remi.Version + `","resource":"remi"}`,
			queryErr: errors.New("the table is gone"),
			status:   http.StatusInternalServerError, message: "could not verify version usage",
		},
		{
			name: "a domain still uses the version",
			body: `{"version":"` + remi.Version + `","resource":"remi"}`, count: 3,
			status: http.StatusConflict, message: "3 domains use this version",
		},
		{
			name: "an operation is already running",
			body: `{"version":"` + remi.Version + `","resource":"remi"}`, state: "active",
			status: http.StatusConflict, message: "already running",
		},
	}
}

// A removal is fail-closed on every count it cannot trust: dnf pulling a PHP
// out from under a live tenant is not something a later message can undo.
func TestARemovalRefusesBeforeItStartsAnything(t *testing.T) {
	remi := remiVersion(t)
	for _, tc := range removeRefusals(remi) {
		t.Run(tc.name, func(t *testing.T) {
			opPaths(t)
			var started string
			stubUnit(t, tc.state, &started)
			h := &Handlers{DB: countDB(t, &countConn{count: tc.count, queryErr: tc.queryErr})}

			status, body := postOp(t, h.Remove, tc.body)

			if status != tc.status {
				t.Errorf("status %d, want %d (%v)", status, tc.status, body)
			}
			if !strings.Contains(errorOf(body), tc.message) {
				t.Errorf("message %q does not carry %q", errorOf(body), tc.message)
			}
			if started != "" {
				t.Error("a refused removal still started a job")
			}
		})
	}
}

// The removal job stops the service before dnf, so packages are not pulled from
// under a running pool.
func TestAnAcceptedRemovalStartsTheJobAndSaysSo(t *testing.T) {
	opPaths(t)
	remi := remiVersion(t)
	var started string
	stubUnit(t, "inactive", &started)
	conn := &countConn{}
	h := &Handlers{DB: countDB(t, conn)}

	status, body := postOp(t, h.Remove, `{"version":"`+remi.Version+`","resource":"remi"}`)

	if status != http.StatusAccepted {
		t.Fatalf("status %d, want 202 (%v)", status, body)
	}
	if body["started"] != true || body["version"] != remi.Version {
		t.Errorf("body = %v", body)
	}
	if len(conn.queries) != 1 || !strings.Contains(conn.queries[0], "FROM domains WHERE php_version=?") {
		t.Errorf("queries = %v", conn.queries)
	}
	if !strings.Contains(started, "systemctl disable --now") ||
		!strings.Contains(started, "dnf remove -y 'php"+remi.Code+"-*'") {
		t.Errorf("the job does not remove the version:\n%s", started)
	}
	if descriptor := readOpDescriptor(); descriptor.Action != "remove" {
		t.Errorf("descriptor = %+v", descriptor)
	}
}
