package stats

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The cursor read used to discard its error, so sql.ErrNoRows (the legitimate
// first pass) and a genuine read failure both left the offset at zero. The pass
// then re-parsed the whole access log and ADDED it to what was already stored,
// because the merge is bytes=bytes+VALUES(bytes).
//
// That figure is not cosmetic: it becomes domains.traffic_kb, which a reseller's
// contracted traffic ceiling is measured against, so one transient failure
// during a MariaDB restart inflated a month's traffic by the full size of the
// log and could push a reseller over a quota they never used.
func TestAnUnreadableCursorSkipsTheDomainInsteadOfRecounting(t *testing.T) {
	logged := captureTrafficLog(t)
	script := &trafficScript{cursorErr: errors.New("too many connections")}
	db := trafficDB(t, script)

	if aggregateDomain(db, 7, "example.com") {
		t.Error("an unreadable cursor was reported as a completed pass")
	}
	if got := script.inserts(); got != 0 {
		t.Errorf("the pass wrote %d traffic rows from a cursor it could not read", got)
	}
	body := logged.String()
	if !strings.Contains(body, "traffic cursor read domain=7") {
		t.Errorf("the skipped domain was not named: %s", body)
	}
	if !strings.Contains(body, "not accounted") {
		t.Errorf("the line does not say what did not happen: %s", body)
	}
}

// An absent cursor is an ANSWER, not a failure: a domain counted for the first
// time has to start at zero, and it must not be logged as a problem.
func TestAnAbsentCursorStillCountsFromTheStart(t *testing.T) {
	logged := captureTrafficLog(t)
	script := &trafficScript{cursorErr: sql.ErrNoRows}
	db := trafficDB(t, script)

	if !aggregateDomain(db, 7, "example.com") {
		t.Fatal("a first pass was refused")
	}
	if got := script.inserts(); got == 0 {
		t.Error("a first pass counted nothing")
	}
	if strings.Contains(logged.String(), "traffic cursor read") {
		t.Errorf("a first pass was reported as a failure: %s", logged.String())
	}
}

// captureTrafficLog redirects the logger and points the aggregator at a
// temporary access log, so no test depends on /var/log/nginx.
func captureTrafficLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previousOutput, previousFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
	})

	dir := t.TempDir()
	line := `1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 4096 "-" "-"` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "example.com.access.log"), []byte(strings.Repeat(line, 4)), 0o600); err != nil {
		t.Fatalf("write the access log: %v", err)
	}
	previousRoot := trafficLogRoot
	trafficLogRoot = dir + "/"
	t.Cleanup(func() { trafficLogRoot = previousRoot })
	return &buf
}

// A scripted driver: the repository carries no sqlmock dependency.
type trafficScript struct {
	mu        sync.Mutex
	cursorErr error
	written   int
}

func (s *trafficScript) countInsert() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.written++
}

func (s *trafficScript) inserts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.written
}

func trafficDB(t *testing.T, script *trafficScript) *sql.DB {
	t.Helper()
	db := sql.OpenDB(trafficConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type trafficConn struct{ script *trafficScript }

func (c trafficConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c trafficConn) Driver() driver.Driver                        { return trafficDriver{} }
func (c trafficConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c trafficConn) Close() error                                 { return nil }
func (c trafficConn) Begin() (driver.Tx, error)                    { return trafficTx{}, nil }

func (c trafficConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "domain_traffic_cursor") {
		if c.script.cursorErr != nil && !errors.Is(c.script.cursorErr, sql.ErrNoRows) {
			return nil, c.script.cursorErr
		}
		return &trafficRows{columns: 2, empty: true}, nil // no cursor row
	}
	return &trafficRows{columns: 1, empty: true}, nil
}

func (c trafficConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "INSERT INTO domain_traffic(") {
		c.script.countInsert()
	}
	return trafficResult{}, nil
}

type trafficRows struct {
	columns int
	empty   bool
	done    bool
}

func (r *trafficRows) Columns() []string { return make([]string, r.columns) }
func (r *trafficRows) Close() error      { return nil }
func (r *trafficRows) Next([]driver.Value) error {
	if r.empty || r.done {
		return io.EOF
	}
	r.done = true
	return nil
}

type trafficTx struct{}

func (trafficTx) Commit() error   { return nil }
func (trafficTx) Rollback() error { return nil }

type trafficResult struct{}

func (trafficResult) LastInsertId() (int64, error) { return 1, nil }
func (trafficResult) RowsAffected() (int64, error) { return 1, nil }

type trafficDriver struct{}

func (trafficDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }
