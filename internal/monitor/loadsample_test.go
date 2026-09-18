package monitor

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
)

// One sample is one row, and the row carries every series the chart draws. The
// reading itself is taken from /proc and statfs, so it is replaced here: the
// question is what reaches the INSERT, not what the host reports.

// sampleScript records the statement the sampler ran.
type sampleScript struct {
	query string
	args  []driver.Value
	fail  error
}

type sampleConn struct{ script *sampleScript }

func (c sampleConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c sampleConn) Driver() driver.Driver                        { return sampleDriver{} }
func (c sampleConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c sampleConn) Close() error                                 { return nil }
func (c sampleConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c sampleConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.script.query = query
	c.script.args = nil
	for _, a := range args {
		c.script.args = append(c.script.args, a.Value)
	}
	if c.script.fail != nil {
		return nil, c.script.fail
	}
	return sampleResult{}, nil
}

type sampleResult struct{}

func (sampleResult) LastInsertId() (int64, error) { return 1, nil }
func (sampleResult) RowsAffected() (int64, error) { return 1, nil }

type sampleDriver struct{}

func (sampleDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// The whole reading reaches one row, in the order the statement names the
// columns. A series left out of the INSERT is stored as the column default and
// draws as a flat zero line for ever after.
func TestOneSampleCarriesEverySeries(t *testing.T) {
	script := &sampleScript{}
	db := sql.OpenDB(sampleConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	previous := hostSample
	t.Cleanup(func() { hostSample = previous })
	hostSample = func() loadSample {
		return loadSample{
			load1: 1.5, load5: 1.25, load15: 1, memPercent: 42.5,
			cpuPercent: 31.5, swapPercent: 3, diskPercent: 63.1,
			netRxPerSecond: 980000, netTxPerSecond: 76000,
		}
	}

	sampleLoad(db)

	for _, column := range []string{"cpu_percent", "swap_percent", "disk_percent", "net_rx_bps", "net_tx_bps"} {
		if !strings.Contains(script.query, column) {
			t.Errorf("the statement does not write %s: %s", column, script.query)
		}
	}
	want := []driver.Value{1.5, 1.25, 1.0, 42.5, 31.5, 3.0, 63.1, int64(980000), int64(76000)}
	if len(script.args) != len(want) {
		t.Fatalf("the row carries %v", script.args)
	}
	for i, value := range want {
		if script.args[i] != value {
			t.Errorf("argument %d = %v, want %v", i, script.args[i], value)
		}
	}
}
