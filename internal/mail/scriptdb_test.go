package mail

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
)

// A scripted database, in the shape internal/backups uses, with the transaction
// and prepared-statement support the delivery-log collector and the send policy
// need. A query is answered by the fragment of its text that the script names, a
// result set can end in an error instead of io.EOF, and every statement is
// recorded with its arguments.
//
// A query matched by more than one fragment is refused by name, unless one of
// them is the whole query. Go ranges over a map in random order, so letting the
// first match win would make a test pass or fail from one run to the next.
type sqlScript struct {
	mu sync.Mutex
	// rows maps a query fragment to the rows it answers, each in SELECT order.
	// An empty slice answers no rows, which is what makes QueryRow report
	// sql.ErrNoRows.
	rows map[string][][]driver.Value
	// fail maps a fragment to the error the statement itself returns.
	fail map[string]error
	// endWith maps a query fragment to the error its result set ends with once
	// its rows are exhausted.
	endWith map[string]error
	// insertID is what every statement reports as its last insert id.
	insertID int64
	// affected maps a statement fragment to the row count it reports; any other
	// statement reports one row.
	affected map[string]int64
	// affectedFail maps a statement fragment to the error RowsAffected returns.
	affectedFail map[string]error
	// prepareFail maps a statement fragment to the error its preparation returns.
	prepareFail map[string]error
	// failBegin and failCommit fail the two transaction steps.
	failBegin, failCommit error
	// onExec, when set, runs after a statement is recorded, for a test that has
	// to act at one exact step of a sequence.
	onExec func(query string)
	// steps records every query, statement and transaction step in order.
	steps []string
	execs []sqlScriptExec
	reads []sqlScriptExec
}

type sqlScriptExec struct {
	query string
	args  []driver.Value
}

// fragmentFor returns the one fragment that answers query. The caller holds mu.
func (s *sqlScript) fragmentFor(query string) (string, error) {
	seen := map[string]bool{}
	var matched []string
	consider := func(fragment string) {
		if !seen[fragment] && strings.Contains(query, fragment) {
			seen[fragment] = true
			matched = append(matched, fragment)
		}
	}
	for fragment := range s.fail {
		consider(fragment)
	}
	for fragment := range s.rows {
		consider(fragment)
	}
	for fragment := range s.endWith {
		consider(fragment)
	}
	switch {
	case len(matched) == 0:
		return "", errors.New("the test script has no answer for: " + query)
	case len(matched) == 1:
		return matched[0], nil
	case seen[query]:
		return query, nil
	default:
		sort.Strings(matched)
		return "", fmt.Errorf("the test script answers %q with more than one fragment: %v", query, matched)
	}
}

func (s *sqlScript) query(query string, args []driver.NamedValue) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps = append(s.steps, query)
	s.reads = append(s.reads, sqlScriptExec{query: query, args: plainValues(args)})
	fragment, err := s.fragmentFor(query)
	if err != nil {
		return nil, err
	}
	if failure := s.fail[fragment]; failure != nil {
		return nil, failure
	}
	return &sqlScriptRows{rows: s.rows[fragment], end: s.endWith[fragment]}, nil
}

// exec records the statement and fails it only when the script says so; a
// statement nobody scripted succeeds.
func (s *sqlScript) exec(query string, args []driver.NamedValue) (driver.Result, error) {
	result, hook, err := s.recordExec(query, args)
	if hook != nil {
		hook(query)
	}
	return result, err
}

func (s *sqlScript) recordExec(query string, args []driver.NamedValue) (driver.Result, func(string), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps = append(s.steps, query)
	s.execs = append(s.execs, sqlScriptExec{query: query, args: plainValues(args)})
	if fragment, err := s.fragmentFor(query); err == nil && s.fail[fragment] != nil {
		return nil, s.onExec, s.fail[fragment]
	}
	result := sqlScriptResult{id: s.insertID, rows: 1}
	for fragment, count := range s.affected {
		if strings.Contains(query, fragment) {
			result.rows = count
		}
	}
	for fragment, failure := range s.affectedFail {
		if strings.Contains(query, fragment) {
			result.rowsErr = failure
		}
	}
	return result, s.onExec, nil
}

func (s *sqlScript) prepare(query string) (driver.Stmt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, failure := range s.prepareFail {
		if strings.Contains(query, fragment) {
			return nil, failure
		}
	}
	return sqlScriptStmt{s: s, query: query}, nil
}

func (s *sqlScript) record(step string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps = append(s.steps, step)
}

// stepIndex returns where the first recorded step holding fragment ran, or -1.
func (s *sqlScript) stepIndex(fragment string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, step := range s.steps {
		if strings.Contains(step, fragment) {
			return i
		}
	}
	return -1
}

// execsContaining returns every recorded statement whose text holds fragment,
// in the order they ran.
func (s *sqlScript) execsContaining(fragment string) []sqlScriptExec {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []sqlScriptExec
	for _, statement := range s.execs {
		if strings.Contains(statement.query, fragment) {
			out = append(out, statement)
		}
	}
	return out
}

// onlyExec returns the one statement holding fragment and fails the test when
// there is not exactly one.
func (s *sqlScript) onlyExec(t *testing.T, fragment string) sqlScriptExec {
	t.Helper()
	found := s.execsContaining(fragment)
	if len(found) != 1 {
		t.Fatalf("%d statements hold %q, want 1", len(found), fragment)
	}
	return found[0]
}

// onlyRead returns the one query holding fragment and fails the test when there
// is not exactly one.
func (s *sqlScript) onlyRead(t *testing.T, fragment string) sqlScriptExec {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var found []sqlScriptExec
	for _, read := range s.reads {
		if strings.Contains(read.query, fragment) {
			found = append(found, read)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d queries hold %q, want 1", len(found), fragment)
	}
	return found[0]
}

func plainValues(args []driver.NamedValue) []driver.Value {
	plain := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		plain = append(plain, arg.Value)
	}
	return plain
}

type sqlScriptResult struct {
	id, rows int64
	rowsErr  error
}

func (r sqlScriptResult) LastInsertId() (int64, error) { return r.id, nil }
func (r sqlScriptResult) RowsAffected() (int64, error) { return r.rows, r.rowsErr }

type sqlScriptRows struct {
	rows [][]driver.Value
	end  error
	at   int
}

func (r *sqlScriptRows) Columns() []string {
	if len(r.rows) == 0 {
		return nil
	}
	return make([]string, len(r.rows[0]))
}

func (r *sqlScriptRows) Close() error { return nil }

func (r *sqlScriptRows) Next(dest []driver.Value) error {
	if r.at >= len(r.rows) {
		if r.end != nil {
			return r.end
		}
		return io.EOF
	}
	copy(dest, r.rows[r.at])
	r.at++
	return nil
}

type sqlScriptStmt struct {
	s     *sqlScript
	query string
}

func (st sqlScriptStmt) Close() error  { return nil }
func (st sqlScriptStmt) NumInput() int { return -1 }

func (st sqlScriptStmt) Exec(args []driver.Value) (driver.Result, error) {
	return st.s.exec(st.query, namedValues(args))
}

func (st sqlScriptStmt) ExecContext(_ context.Context, args []driver.NamedValue) (driver.Result, error) {
	return st.s.exec(st.query, args)
}

func (st sqlScriptStmt) Query(args []driver.Value) (driver.Rows, error) {
	return st.s.query(st.query, namedValues(args))
}

func namedValues(args []driver.Value) []driver.NamedValue {
	named := make([]driver.NamedValue, len(args))
	for i, value := range args {
		named[i] = driver.NamedValue{Ordinal: i + 1, Value: value}
	}
	return named
}

type sqlScriptTx struct{ s *sqlScript }

func (tx sqlScriptTx) Commit() error {
	tx.s.record("COMMIT")
	return tx.s.failCommit
}

func (tx sqlScriptTx) Rollback() error {
	tx.s.record("ROLLBACK")
	return nil
}

type sqlScriptConn struct{ s *sqlScript }

func (c sqlScriptConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c sqlScriptConn) Driver() driver.Driver                        { return sqlScriptDriver{} }
func (c sqlScriptConn) Prepare(query string) (driver.Stmt, error)    { return c.s.prepare(query) }
func (c sqlScriptConn) Close() error                                 { return nil }

func (c sqlScriptConn) Begin() (driver.Tx, error) {
	c.s.record("BEGIN")
	if c.s.failBegin != nil {
		return nil, c.s.failBegin
	}
	return sqlScriptTx(c), nil
}

func (c sqlScriptConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.s.query(query, args)
}

func (c sqlScriptConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.s.exec(query, args)
}

type sqlScriptDriver struct{}

func (sqlScriptDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// scriptDB opens a database the script answers, for one test.
func scriptDB(t *testing.T, s *sqlScript) *sql.DB {
	t.Helper()
	db := sql.OpenDB(sqlScriptConn{s: s})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newScript returns an empty script whose maps are ready to fill.
func newScript() *sqlScript {
	return &sqlScript{
		rows:         map[string][][]driver.Value{},
		fail:         map[string]error{},
		endWith:      map[string]error{},
		affected:     map[string]int64{},
		affectedFail: map[string]error{},
		prepareFail:  map[string]error{},
	}
}

var errScripted = errors.New("scripted failure")
