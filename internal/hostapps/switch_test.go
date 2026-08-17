package hostapps

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// A recording driver, as used elsewhere in the repository: there is no sqlmock
// dependency, and what these tests need is which statements ran.
//
// The switch answer is modelled as a ROW keyed on the query text, so a gate that
// stopped reading the setting would answer with the zero value rather than keep
// passing.
type recorder struct {
	mu         sync.Mutex
	enabled    int
	statements []string
}

func (r *recorder) saw(fragment string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, statement := range r.statements {
		if strings.Contains(statement, fragment) {
			return true
		}
	}
	return false
}

var (
	stateMu sync.Mutex
	state   = map[string]*recorder{}
	once    sync.Once
)

type hostDriver struct{}

func (hostDriver) Open(name string) (driver.Conn, error) {
	stateMu.Lock()
	defer stateMu.Unlock()
	rec, ok := state[name]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return &hostConn{recorder: rec}, nil
}

type hostConn struct{ recorder *recorder }

func (c *hostConn) Prepare(query string) (driver.Stmt, error) {
	c.recorder.mu.Lock()
	c.recorder.statements = append(c.recorder.statements, query)
	c.recorder.mu.Unlock()
	return &hostStmt{recorder: c.recorder, query: query}, nil
}
func (c *hostConn) Close() error              { return nil }
func (c *hostConn) Begin() (driver.Tx, error) { return nil, io.ErrUnexpectedEOF }

type hostStmt struct {
	recorder *recorder
	query    string
}

func (s *hostStmt) Close() error  { return nil }
func (s *hostStmt) NumInput() int { return -1 }

func (s *hostStmt) Exec([]driver.Value) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

func (s *hostStmt) Query([]driver.Value) (driver.Rows, error) {
	if strings.Contains(s.query, "host_apps_enabled") {
		return &hostRows{columns: []string{"enabled"},
			values: [][]driver.Value{{int64(s.recorder.enabled)}}}, nil
	}
	// Anything else answers no rows, so a catalog read past the gate surfaces as
	// its own refusal rather than as a driver error that could be mistaken for
	// the gate working.
	return &hostRows{columns: []string{"x"}}, nil
}

type hostRows struct {
	columns []string
	values  [][]driver.Value
	at      int
}

func (r *hostRows) Columns() []string { return r.columns }
func (r *hostRows) Close() error      { return nil }
func (r *hostRows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

func openRecorded(t *testing.T, rec *recorder) *sql.DB {
	t.Helper()
	once.Do(func() { sql.Register("hostapps-recorder", hostDriver{}) })

	name := t.Name()
	stateMu.Lock()
	state[name] = rec
	stateMu.Unlock()

	db, err := sql.Open("hostapps-recorder", name)
	if err != nil {
		t.Fatalf("open the recorded database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func postInstall(t *testing.T, db *sql.DB) *httptest.ResponseRecorder {
	t.Helper()
	handlers := &Handlers{DB: db}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/system/host-apps",
		strings.NewReader(`{"code":"gitea"}`))
	handlers.Install(response, request)
	return response
}

// The switch is enforced on the WRITE path, not only where the screen draws the
// button. A gate that lived in the browser would be no gate at all, and this is
// the operation that downloads a program, creates a Linux account and reserves
// a port.
func TestAnInstallIsRefusedWhileTheFeatureIsOff(t *testing.T) {
	rec := &recorder{enabled: 0}
	response := postInstall(t, openRecorded(t, rec))

	if response.Code != http.StatusConflict {
		t.Errorf("answered %d, want %d", response.Code, http.StatusConflict)
	}
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("the refusal is not JSON: %v", err)
	}
	if body["reason"] != ReasonFeatureOff {
		t.Errorf("refused as %q, want %q", body["reason"], ReasonFeatureOff)
	}
	// Nothing was recorded and nothing was reserved. A gate that answered 409
	// after taking the row would leave a phantom application behind.
	for _, statement := range []string{"INSERT INTO host_apps", "host_app_ports", "host_app_jobs"} {
		if rec.saw(statement) {
			t.Errorf("%q ran while the feature was off", statement)
		}
	}
}

// With the switch on the request gets PAST the gate, or the test above proves
// only that the handler refuses everything. It then stops at the catalog, which
// this driver answers empty, with that refusal rather than the switch's.
func TestAnInstallGetsPastTheGateWhileTheFeatureIsOn(t *testing.T) {
	rec := &recorder{enabled: 1}
	response := postInstall(t, openRecorded(t, rec))

	var body map[string]string
	_ = json.Unmarshal(response.Body.Bytes(), &body)
	if body["reason"] == ReasonFeatureOff {
		t.Errorf("the gate refused while the feature was on: %s", response.Body.String())
	}
	if !rec.saw("host_app_catalog") {
		t.Errorf("the catalog was never read, so the request did not get past the gate")
	}
}

// The setting is read from panel_settings rather than from anything the request
// carries, so an operator cannot be talked into installing by a crafted body.
func TestTheSwitchIsReadFromTheDatabase(t *testing.T) {
	rec := &recorder{enabled: 0}
	postInstall(t, openRecorded(t, rec))
	if !rec.saw("host_apps_enabled") {
		t.Errorf("the switch was never read:\n%v", rec.statements)
	}
}
