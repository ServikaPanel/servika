package dbmigrate

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

// database/sql reports a connection drop, a driver error or a context deadline
// that arrives MID-ITERATION only through rows.Err(). Without that check the
// applied map comes back SHORT, every migration whose row was not read counts as
// unapplied, and the runner re-applies it.
//
// MariaDB gives DDL an implicit commit, so the statements that succeed before
// the first duplicate-object error are applied for good, the schema_migrations
// INSERT never runs, and cmd/server calls log.Fatalf. The panel then refuses to
// start on every later boot, naming a migration file that is in fact correct.
var errRowsBrokeMidRead = errors.New("invalid connection")

// brokenRows hands back one row and then fails, which is the shape a connection
// lost half way through a result set produces.
type brokenRows struct{ served bool }

func (r *brokenRows) Columns() []string { return []string{"filename", "checksum"} }
func (r *brokenRows) Close() error      { return nil }
func (r *brokenRows) Next(dest []driver.Value) error {
	if r.served {
		return errRowsBrokeMidRead
	}
	r.served = true
	dest[0] = "0001_first.sql"
	dest[1] = "aaaa"
	return nil
}

// wholeRows serves two rows and ends cleanly.
type wholeRows struct{ served int }

func (r *wholeRows) Columns() []string { return []string{"filename", "checksum"} }
func (r *wholeRows) Close() error      { return nil }
func (r *wholeRows) Next(dest []driver.Value) error {
	if r.served >= 2 {
		return io.EOF
	}
	r.served++
	dest[0] = "000" + string(rune('0'+r.served)) + "_file.sql"
	dest[1] = "sum"
	return nil
}

type migrateConn struct{ breakRead bool }

func (c migrateConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c migrateConn) Driver() driver.Driver                        { return migrateDriver{} }
func (c migrateConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c migrateConn) Close() error                                 { return nil }
func (c migrateConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c migrateConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(query, "FROM schema_migrations") {
		return nil, errors.New("the test script has no answer for: " + query)
	}
	if c.breakRead {
		return &brokenRows{}, nil
	}
	return &wholeRows{}, nil
}

type migrateDriver struct{}

func (migrateDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

func migrateDB(t *testing.T, breakRead bool) *sql.DB {
	t.Helper()
	db := sql.OpenDB(migrateConn{breakRead: breakRead})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestAReadThatBrokeMidWayRefusesInsteadOfReportingAShortList(t *testing.T) {
	applied, err := appliedChecksums(migrateDB(t, true))
	if err == nil {
		t.Fatalf("appliedChecksums returned %d entries with no error after the read broke", len(applied))
	}
	if applied != nil {
		t.Errorf("appliedChecksums returned a map alongside its error: %v", applied)
	}
}

// The opposite direction, so the test above is not merely watching a function
// that always fails.
func TestACompleteReadReturnsEveryAppliedMigration(t *testing.T) {
	applied, err := appliedChecksums(migrateDB(t, false))
	if err != nil {
		t.Fatalf("appliedChecksums() = %v, want the applied list", err)
	}
	if len(applied) != 2 {
		t.Errorf("appliedChecksums returned %d entries, want 2", len(applied))
	}
}
