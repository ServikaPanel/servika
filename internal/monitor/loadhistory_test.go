package monitor

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The load chart used to append a sample only when its row scanned, so a row
// the driver could not read left a gap and nothing else: no error, no log line,
// a shorter array. A gap is what a server too loaded to record a sample looks
// like, so the endpoint drew the incident an operator opened the chart to
// investigate.

// loadScript is the rows the history query answers with.
type loadScript struct{ rows [][]driver.Value }

type loadConn struct{ script *loadScript }

func (c loadConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c loadConn) Driver() driver.Driver                        { return loadDriver{} }
func (c loadConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c loadConn) Close() error                                 { return nil }
func (c loadConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c loadConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &loadRows{rows: c.script.rows}, nil
}

type loadRows struct {
	rows [][]driver.Value
	at   int
}

func (r *loadRows) Columns() []string { return make([]string, 5) }
func (r *loadRows) Close() error      { return nil }
func (r *loadRows) Next(dest []driver.Value) error {
	if r.at >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.at])
	r.at++
	return nil
}

type loadDriver struct{}

func (loadDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

func loadDB(t *testing.T, rows [][]driver.Value) *sql.DB {
	t.Helper()
	db := sql.OpenDB(loadConn{script: &loadScript{rows: rows}})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// readHistory asks for the chart and returns the response.
func readHistory(t *testing.T, rows [][]driver.Value) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handlers := &Handlers{DB: loadDB(t, rows)}
	handlers.LoadHistory(recorder, httptest.NewRequest(http.MethodGet, "/system/load-history?hour=24", nil))
	return recorder
}

// A sample of the right shape reaches the chart.
func TestTheReadableSamplesReachTheChart(t *testing.T) {
	recorder := readHistory(t, [][]driver.Value{
		{"2026-09-12 10:00:00", 0.5, 0.4, 0.3, 41.5},
		{"2026-09-12 10:05:00", 0.7, 0.6, 0.5, 42.0},
	})

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}
	var body struct {
		Points []LoadPoint `json:"points"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("the answer is not JSON: %s", recorder.Body.String())
	}
	if len(body.Points) != 2 || body.Points[1].Load1 != 0.7 {
		t.Errorf("the chart carries %v", body.Points)
	}
}

// A sample that cannot be read is refused rather than left out: the chart has
// no way to show that a point is missing rather than absent.
func TestASampleThatCannotBeReadIsRefusedRatherThanDropped(t *testing.T) {
	recorder := readHistory(t, [][]driver.Value{
		{"2026-09-12 10:00:00", 0.5, 0.4, 0.3, 41.5},
		{"2026-09-12 10:05:00", "not a load average", 0.6, 0.5, 42.0},
	})

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body)
	}
}
