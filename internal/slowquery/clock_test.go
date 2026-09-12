package slowquery

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// bucket_hour is written from a Go time.Time. The pool is opened with no `loc`,
// so go-sql-driver/mysql converts the value to UTC on the wire and the column
// holds a UTC wall clock. Both readers compared it against NOW(), which answers
// in the session timezone: on a +03:00 server the "last 24 hours" screen showed
// 21 hours and the 14 day retention deleted rows three hours early. The error is
// silent and grows with the offset.

// clockScript records every statement the package sends.
type clockScript struct {
	statements []string
	args       [][]driver.NamedValue
}

type clockConn struct{ script *clockScript }

func (c clockConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c clockConn) Driver() driver.Driver                        { return clockDriver{} }
func (c clockConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c clockConn) Close() error                                 { return nil }
func (c clockConn) Begin() (driver.Tx, error)                    { return clockTx{}, nil }

func (c clockConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return clockTx{}, nil
}

func (c clockConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.script.statements = append(c.script.statements, query)
	c.script.args = append(c.script.args, args)
	return driver.RowsAffected(0), nil
}

func (c clockConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.script.statements = append(c.script.statements, query)
	c.script.args = append(c.script.args, args)
	return emptyRows{}, nil
}

type clockTx struct{}

func (clockTx) Commit() error   { return nil }
func (clockTx) Rollback() error { return nil }

type emptyRows struct{}

func (emptyRows) Columns() []string         { return make([]string, 15) }
func (emptyRows) Close() error              { return nil }
func (emptyRows) Next([]driver.Value) error { return io.EOF }

type clockDriver struct{}

func (clockDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// recordingDB opens a pool over the recorder. One connection only, so the
// statements arrive in the order the package sent them.
func recordingDB(t *testing.T) (*sql.DB, *clockScript) {
	t.Helper()
	script := &clockScript{}
	db := sql.OpenDB(clockConn{script: script})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db, script
}

// statementWith returns the recorded statement that carries a fragment.
func statementWith(t *testing.T, script *clockScript, fragment string) (string, []driver.NamedValue) {
	t.Helper()
	for i, statement := range script.statements {
		if strings.Contains(statement, fragment) {
			return statement, script.args[i]
		}
	}
	t.Fatalf("no statement carries %q; the pass sent %v", fragment, script.statements)
	return "", nil
}

// storeOneBucket runs a pass that writes a single row for one hour.
func storeOneBucket(t *testing.T, db *sql.DB, hour time.Time) {
	t.Helper()
	buckets := map[bucketKey]*bucket{
		{digest: "d", hour: hour, dbUser: "alice"}: {schema: "alice_db", normalized: "SELECT ?"},
	}
	if err := storeBuckets(context.Background(), db, buckets, 10, 20); err != nil {
		t.Fatalf("storeBuckets: %v", err)
	}
}

// Both windows are measured against the clock the column is written in, so the
// window is the one the operator asked for whatever the session timezone is.
func TestBothBucketHourWindowsUseTheDatabaseUTCClock(t *testing.T) {
	db, script := recordingDB(t)
	at := time.Date(2026, 9, 12, 8, 15, 0, 0, time.FixedZone("+03:00", 3*3600))

	storeOneBucket(t, db, at.Truncate(time.Hour))
	handlers := &Handlers{DB: db}
	if _, err := handlers.query(context.Background(), 0, 24, 50); err != nil {
		t.Fatalf("query: %v", err)
	}

	for _, fragment := range []string{"DELETE FROM slow_query_stats", "FROM slow_query_stats s"} {
		statement, _ := statementWith(t, script, fragment)
		if !strings.Contains(statement, "UTC_TIMESTAMP()") {
			t.Errorf("%q compares bucket_hour against a session clock:\n%s", fragment, statement)
		}
		if strings.Contains(statement, "NOW()") {
			t.Errorf("%q still uses NOW():\n%s", fragment, statement)
		}
	}
}

// The other half of the pair: the value the driver sends is the UTC wall clock
// of the moment, which is what makes UTC_TIMESTAMP() the right comparator.
func TestTheStoredBucketHourIsTheUTCWallClock(t *testing.T) {
	db, script := recordingDB(t)
	at := time.Date(2026, 9, 12, 11, 0, 0, 0, time.FixedZone("+03:00", 3*3600))

	storeOneBucket(t, db, at)

	_, args := statementWith(t, script, "INSERT INTO slow_query_stats")
	var stored time.Time
	for _, arg := range args {
		if value, ok := arg.Value.(time.Time); ok {
			stored = value
		}
	}
	if stored.IsZero() {
		t.Fatalf("no time was bound: %v", args)
	}
	if got := stored.UTC().Format("2006-01-02 15:04:05"); got != "2026-09-12 08:00:00" {
		t.Errorf("the bound hour reads %s in UTC, want 2026-09-12 08:00:00", got)
	}
}
