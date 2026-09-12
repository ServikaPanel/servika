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
	script := newTrafficScript()
	script.cursorErr = errors.New("too many connections")
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
	script := newTrafficScript()
	script.cursorErr = sql.ErrNoRows
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
	if err := os.WriteFile(filepath.Join(dir, "example.com.access.log"),
		[]byte(strings.Repeat(trafficLine, 4)), 0o600); err != nil {
		t.Fatalf("write the access log: %v", err)
	}
	previousRoot := trafficLogRoot
	trafficLogRoot = dir + "/"
	t.Cleanup(func() { trafficLogRoot = previousRoot })
	return &buf
}

// trafficLine is one combined access log line worth 4096 bytes in January 2026.
const trafficLine = `1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 4096 "-" "-"` + "\n"

// A scripted driver: the repository carries no sqlmock dependency.
type trafficScript struct {
	mu sync.Mutex
	// cursorErr is what the cursor read reports. sql.ErrNoRows answers "no row".
	cursorErr error
	// cursor is the stored offset and size, served when cursorErr is nil.
	offset, size int64
	// fail maps a statement fragment to the error that statement returns.
	fail map[string]error
	// beginErr and commitErr fail the transaction itself.
	beginErr, commitErr error
	// domains is what the domain list query answers, id and name per row.
	domains [][]driver.Value

	written int
	execs   []trafficExec
}

type trafficExec struct {
	query string
	args  []driver.Value
}

func newTrafficScript() *trafficScript {
	return &trafficScript{fail: map[string]error{}}
}

func (s *trafficScript) record(query string, args []driver.Value) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execs = append(s.execs, trafficExec{query: query, args: args})
	if strings.Contains(query, "INSERT INTO domain_traffic(") {
		s.written++
	}
	for fragment, failure := range s.fail {
		if strings.Contains(query, fragment) {
			return failure
		}
	}
	return nil
}

func (s *trafficScript) inserts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.written
}

// argsOf returns the arguments of the first statement carrying fragment.
func (s *trafficScript) argsOf(t *testing.T, fragment string) []driver.Value {
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
func (s *trafficScript) ran(fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, statement := range s.execs {
		if strings.Contains(statement.query, fragment) {
			return true
		}
	}
	return false
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

func (c trafficConn) Begin() (driver.Tx, error) {
	if c.script.beginErr != nil {
		return nil, c.script.beginErr
	}
	return trafficTx{commitErr: c.script.commitErr}, nil
}

func (c trafficConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "domain_traffic_cursor") {
		return c.cursorRows()
	}
	if strings.Contains(query, "domain_name FROM domains") {
		return &trafficRows{columns: 2, rows: c.script.domains}, nil
	}
	return &trafficRows{columns: 1}, nil
}

// cursorRows answers the cursor read: an error, no row, or the stored pair.
func (c trafficConn) cursorRows() (driver.Rows, error) {
	switch {
	case c.script.cursorErr != nil && !errors.Is(c.script.cursorErr, sql.ErrNoRows):
		return nil, c.script.cursorErr
	case c.script.cursorErr != nil:
		return &trafficRows{columns: 2}, nil // no cursor row
	default:
		return &trafficRows{columns: 2,
			rows: [][]driver.Value{{c.script.offset, c.script.size}}}, nil
	}
}

func (c trafficConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	plain := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		plain = append(plain, arg.Value)
	}
	if err := c.script.record(query, plain); err != nil {
		return nil, err
	}
	return trafficResult{}, nil
}

type trafficRows struct {
	columns int
	rows    [][]driver.Value
	at      int
}

func (r *trafficRows) Columns() []string { return make([]string, r.columns) }
func (r *trafficRows) Close() error      { return nil }
func (r *trafficRows) Next(dest []driver.Value) error {
	if r.at >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.at])
	r.at++
	return nil
}

type trafficTx struct{ commitErr error }

func (t trafficTx) Commit() error { return t.commitErr }
func (trafficTx) Rollback() error { return nil }

type trafficResult struct{}

func (trafficResult) LastInsertId() (int64, error) { return 1, nil }
func (trafficResult) RowsAffected() (int64, error) { return 1, nil }

type trafficDriver struct{}

func (trafficDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }
