package panelport

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
	"sync"
	"testing"
)

// The port change endpoint. Every refusal it makes has to be a refusal rather
// than a half-applied change, because the screen that would undo one is the
// screen that just went away.

// A scripted database in the shape internal/apps uses, cut down to what this
// package writes: two statements, no reads.
type sqlScript struct {
	mu sync.Mutex
	// insertID is what LastInsertId reports, which is the history row a change
	// closes when it finishes.
	insertID int64
	// fail maps a statement fragment to the error that statement returns.
	fail  map[string]error
	execs []sqlScriptExec
}

type sqlScriptExec struct {
	query string
	args  []driver.Value
}

func newScript() *sqlScript {
	return &sqlScript{insertID: 7, fail: map[string]error{}}
}

func (s *sqlScript) exec(query string, args []driver.NamedValue) (driver.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execs = append(s.execs, sqlScriptExec{query: query, args: plainValues(args)})
	for fragment, failure := range s.fail {
		if strings.Contains(query, fragment) {
			return nil, failure
		}
	}
	return sqlScriptResult{id: s.insertID}, nil
}

// argsOf returns the arguments of the first statement carrying fragment.
func (s *sqlScript) argsOf(t *testing.T, fragment string) []driver.Value {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, statement := range s.execs {
		if strings.Contains(statement.query, fragment) {
			return statement.args
		}
	}
	t.Fatalf("no statement carrying %q ran", fragment)
	return nil
}

// ran reports whether a statement carrying fragment was executed.
func (s *sqlScript) ran(fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, statement := range s.execs {
		if strings.Contains(statement.query, fragment) {
			return true
		}
	}
	return false
}

type sqlScriptResult struct{ id int64 }

func (r sqlScriptResult) LastInsertId() (int64, error) { return r.id, nil }
func (r sqlScriptResult) RowsAffected() (int64, error) { return 1, nil }

type sqlScriptConn struct{ s *sqlScript }

func (c sqlScriptConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c sqlScriptConn) Driver() driver.Driver                        { return sqlScriptDriver{} }
func (c sqlScriptConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c sqlScriptConn) Close() error                                 { return nil }
func (c sqlScriptConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c sqlScriptConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.s.exec(query, args)
}

type sqlScriptDriver struct{}

func (sqlScriptDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// plainValues drops the names and ordinals database/sql attaches to arguments.
func plainValues(args []driver.NamedValue) []driver.Value {
	plain := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		plain = append(plain, arg.Value)
	}
	return plain
}

func scriptDB(t *testing.T, s *sqlScript) *sql.DB {
	t.Helper()
	db := sql.OpenDB(sqlScriptConn{s: s})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// changePort posts one change and returns the recorder.
func changePort(t *testing.T, h *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/system/panel-port", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	h.Change(recorder, request)
	return recorder
}

// answered reads the status, the reason code and the message off a response.
func answered(t *testing.T, recorder *httptest.ResponseRecorder) (int, map[string]any) {
	t.Helper()
	raw, err := io.ReadAll(recorder.Body)
	if err != nil {
		t.Fatalf("read the response: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("the response is not JSON: %s", raw)
	}
	return recorder.Code, body
}

// refusalCase is one request the endpoint turns down before it writes anything.
type refusalCase struct {
	name, body string
	setup      func(*testing.T)
	status     int
	reason     string
	message    string
}

func changeRefusals() []refusalCase {
	return []refusalCase{
		{
			name: "the body is not JSON", body: "{",
			status: http.StatusBadRequest, message: "invalid request body",
		},
		{
			name: "the kind is not one this moves", body: `{"kind":"both","port":9090}`,
			status: http.StatusBadRequest, reason: ReasonUnknownKind, message: "unknown port kind",
		},
		{
			name: "the port belongs to another service", body: `{"kind":"external","port":22}`,
			status: http.StatusConflict, reason: ReasonReservedPort,
			message: "port 22 belongs to SSH on this server",
		},
		{
			name: "the port is in the tenant application range", body: `{"kind":"external","port":30500}`,
			status: http.StatusConflict, reason: ReasonAppPort,
		},
		{
			name: "a change is already running", body: `{"kind":"external","port":9443}`,
			setup: func(t *testing.T) {
				if err := WriteOutcome(Outcome{HistoryID: 1, State: StateRunning}); err != nil {
					t.Fatalf("WriteOutcome: %v", err)
				}
			},
			status: http.StatusConflict, reason: ReasonBusy,
			message: "a port change is already running",
		},
		{
			name: "the panel is already on that port", body: `{"kind":"external","port":8443}`,
			status: http.StatusConflict, reason: ReasonSamePort,
			message: "the panel is already on that port",
		},
		{
			name: "the ports cannot be read", body: `{"kind":"external","port":9443}`,
			setup:  func(t *testing.T) { removeFileFor(t, envPath()) },
			status: http.StatusConflict, reason: ReasonUnreadable,
		},
	}
}

func TestAChangeIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	for _, tc := range changeRefusals() {
		t.Run(tc.name, func(t *testing.T) {
			host := fakePortHost(t)
			if tc.setup != nil {
				tc.setup(t)
			}
			script := newScript()

			status, body := answered(t, changePort(t, &Handlers{DB: scriptDB(t, script)}, tc.body))

			if status != tc.status {
				t.Errorf("status %d, want %d (%v)", status, tc.status, body)
			}
			if got, _ := body["reason"].(string); got != tc.reason {
				t.Errorf("reason %q, want %q", got, tc.reason)
			}
			if tc.message != "" {
				if got, _ := body["error"].(string); got != tc.message {
					t.Errorf("message %q, want %q", got, tc.message)
				}
			}
			if script.ran("INSERT INTO panel_port_history") {
				t.Error("a refused change was still written to the history table")
			}
			if len(host.calls) != 0 {
				t.Errorf("a refused change still ran %v", host.calls)
			}
		})
	}
}

// The history row is written BEFORE the change, so a change that takes the
// panel away still left a record of itself.
func TestAChangeThatCannotBeRecordedIsNotMade(t *testing.T) {
	host := fakePortHost(t)
	script := newScript()
	script.fail["INSERT INTO panel_port_history"] = errors.New("the table is gone")

	status, body := answered(t, changePort(t, &Handlers{DB: scriptDB(t, script)},
		`{"kind":"external","port":9443}`))

	if status != http.StatusInternalServerError {
		t.Errorf("status %d, want 500 (%v)", status, body)
	}
	if got, _ := body["error"].(string); got != "database write failed" {
		t.Errorf("message %q", got)
	}
	if len(host.calls) != 0 {
		t.Errorf("the change ran anyway: %v", host.calls)
	}
}

// An external change is verified in process, so its answer says so and its
// history row is closed as a success.
func TestAnAcceptedExternalChangeIsReportedVerified(t *testing.T) {
	host := fakePortHost(t)
	host.answers[9443] = true
	script := newScript()

	status, body := answered(t, changePort(t, &Handlers{DB: scriptDB(t, script)},
		`{"kind":"external","port":9443}`))

	if status != http.StatusOK {
		t.Fatalf("status %d, want 200 (%v)", status, body)
	}
	if body["verified"] != true || body["kind"] != KindExternal || body["port"] != float64(9443) {
		t.Errorf("body = %v", body)
	}
	assertHistoryOpened(t, script)
	assertHistoryClosedAsSuccess(t, script)
}

// assertHistoryOpened checks the row written before the change is made.
func assertHistoryOpened(t *testing.T, script *sqlScript) {
	t.Helper()
	got := script.argsOf(t, "INSERT INTO panel_port_history")
	if len(got) != 4 || got[0] != KindExternal || got[1] != int64(8443) ||
		got[2] != int64(9443) || got[3] != nil {
		t.Errorf("history insert args = %v", got)
	}
}

// assertHistoryClosedAsSuccess checks the row is closed on the id the insert
// reported.
func assertHistoryClosedAsSuccess(t *testing.T, script *sqlScript) {
	t.Helper()
	got := script.argsOf(t, "UPDATE panel_port_history")
	if len(got) != 4 || got[0] != int64(1) || got[1] != int64(0) ||
		got[2] != "" || got[3] != int64(7) {
		t.Errorf("history close args = %v, want succeeded on row 7", got)
	}
}

// A change that was put back is reported as a conflict, and its history row
// carries the rollback rather than a bare failure.
func TestAnExternalChangeThatWasPutBackIsRecordedAsRolledBack(t *testing.T) {
	host := fakePortHost(t)
	host.answers[8443] = true
	script := newScript()

	status, body := answered(t, changePort(t, &Handlers{DB: scriptDB(t, script)},
		`{"kind":"external","port":9443}`))

	if status != http.StatusConflict {
		t.Fatalf("status %d, want 409 (%v)", status, body)
	}
	if got, _ := body["reason"].(string); got != ReasonRolledBack {
		t.Errorf("reason %q, want %q", got, ReasonRolledBack)
	}
	got := script.argsOf(t, "UPDATE panel_port_history")
	if len(got) != 4 || got[0] != int64(0) || got[1] != int64(1) {
		t.Fatalf("history close args = %v, want a rollback", got)
	}
	if message, _ := got[2].(string); !strings.Contains(message, "port 8443 was put back") {
		t.Errorf("history message = %q", message)
	}
}

// A backend change answers 202 rather than 200: the panel is restarting, so the
// verdict cannot arrive in this response.
func TestAnAcceptedBackendChangeIsReportedAsInFlight(t *testing.T) {
	host := fakePortHost(t)
	script := newScript()

	status, body := answered(t, changePort(t, &Handlers{DB: scriptDB(t, script)},
		`{"kind":"backend","port":9090}`))

	if status != http.StatusAccepted {
		t.Fatalf("status %d, want 202 (%v)", status, body)
	}
	if body["verified"] != false || body["kind"] != KindBackend || body["note"] == nil {
		t.Errorf("body = %v", body)
	}
	if script.ran("UPDATE panel_port_history") {
		t.Error("the history row was closed by the panel that started a detached change")
	}
	if !host.ran("systemd-run") {
		t.Errorf("the helper was not started: %v", host.calls)
	}
	if outcome, ok := ReadOutcome(); !ok || outcome.HistoryID != 7 {
		t.Errorf("outcome = %+v, ok = %v, want the history row it belongs to", outcome, ok)
	}
}

// A backend change that cannot start closes its own history row, because no
// helper is coming to write an outcome for it.
func TestABackendChangeThatWillNotStartClosesItsHistoryRow(t *testing.T) {
	host := fakePortHost(t)
	host.fail["systemd-run"] = true
	script := newScript()

	status, body := answered(t, changePort(t, &Handlers{DB: scriptDB(t, script)},
		`{"kind":"backend","port":9090}`))

	if status != http.StatusConflict {
		t.Fatalf("status %d, want 409 (%v)", status, body)
	}
	if got, _ := body["reason"].(string); got != ReasonVerifyFailed {
		t.Errorf("reason %q, want %q", got, ReasonVerifyFailed)
	}
	if got := script.argsOf(t, "UPDATE panel_port_history"); got[0] != int64(0) || got[1] != int64(0) {
		t.Errorf("history close args = %v, want a plain failure", got)
	}
}

// The status screen reads the ports off the files, so it can never show a port
// the server is not on, and it reports an in-flight change beside them.
func TestTheStatusScreenReadsTheFilesAndTheOutcome(t *testing.T) {
	fakePortHost(t)
	if err := WriteOutcome(Outcome{HistoryID: 3, Kind: KindBackend, State: StateRunning}); err != nil {
		t.Fatalf("WriteOutcome: %v", err)
	}
	h := &Handlers{DB: scriptDB(t, newScript())}

	recorder := httptest.NewRecorder()
	h.Status(recorder, httptest.NewRequest(http.MethodGet, "/system/panel-port", nil))

	status, body := answered(t, recorder)
	if status != http.StatusOK {
		t.Fatalf("status %d (%v)", status, body)
	}
	if body["backend"] != float64(8080) || body["external"] != float64(8443) ||
		body["host"] != "127.0.0.1" {
		t.Errorf("body = %v", body)
	}
	last, ok := body["last_change"].(map[string]any)
	if !ok || last["state"] != StateRunning {
		t.Errorf("last_change = %v", body["last_change"])
	}
}
