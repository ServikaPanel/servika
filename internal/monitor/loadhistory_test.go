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

func (r *loadRows) Columns() []string { return make([]string, 10) }
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

// A sample of the right shape reaches the chart, with every series the row
// carries. A point that answered only the load average and the memory would
// render the CPU, swap, disk and network charts as a flat zero line.
func TestTheReadableSamplesReachTheChart(t *testing.T) {
	recorder := readHistory(t, [][]driver.Value{
		{"2026-09-12 10:00:00", 0.5, 0.4, 0.3, 41.5, 17.0, 2.5, 63.0, int64(120000), int64(45000)},
		{"2026-09-12 10:05:00", 0.7, 0.6, 0.5, 42.0, 31.5, 3.0, 63.1, int64(980000), int64(76000)},
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
	if len(body.Points) != 2 {
		t.Fatalf("the chart carries %v", body.Points)
	}
	assertSecondPoint(t, body.Points[1])
}

// assertSecondPoint checks every series of the later bucket.
func assertSecondPoint(t *testing.T, point LoadPoint) {
	t.Helper()
	for _, field := range []struct {
		name string
		got  float64
		want float64
	}{
		{name: "load1", got: point.Load1, want: 0.7},
		{name: "memory", got: point.Memory, want: 42.0},
		{name: "cpu", got: point.CPU, want: 31.5},
		{name: "swap", got: point.Swap, want: 3.0},
		{name: "disk", got: point.Disk, want: 63.1},
		{name: "net_rx_bps", got: float64(point.NetRx), want: 980000},
		{name: "net_tx_bps", got: float64(point.NetTx), want: 76000},
	} {
		if field.got != field.want {
			t.Errorf("%s = %v, want %v", field.name, field.got, field.want)
		}
	}
}

// A sample that cannot be read is refused rather than left out: the chart has
// no way to show that a point is missing rather than absent.
func TestASampleThatCannotBeReadIsRefusedRatherThanDropped(t *testing.T) {
	recorder := readHistory(t, [][]driver.Value{
		{"2026-09-12 10:00:00", 0.5, 0.4, 0.3, 41.5, 17.0, 2.5, 63.0, int64(120000), int64(45000)},
		{"2026-09-12 10:05:00", "not a load average", 0.6, 0.5, 42.0, 17.0, 2.5, 63.0, int64(1), int64(2)},
	})

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body)
	}
}
