package laravel

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

// A scripted database, in the shape the other packages use. A query is answered
// by the fragment of its text that the script names, and every statement is
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
	// beginErr and commitErr fail a transaction's BEGIN and COMMIT.
	beginErr  error
	commitErr error
	// steps records every query, statement and transaction boundary in order.
	steps []string
	execs []sqlScriptExec
}

type sqlScriptExec struct {
	query string
	args  []driver.Value
}

// fragmentFor returns the one fragment that answers query. The caller holds mu.
func (s *sqlScript) fragmentFor(query string) (string, error) {
	seen := map[string]bool{}
	var matched []string
	for _, fragments := range []map[string]bool{keysOf(s.fail), keysOf(s.rows), keysOf(s.endWith)} {
		for fragment := range fragments {
			if !seen[fragment] && strings.Contains(query, fragment) {
				seen[fragment] = true
				matched = append(matched, fragment)
			}
		}
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

// keysOf returns the keys of a fragment map as a set.
func keysOf[V any](m map[string]V) map[string]bool {
	keys := make(map[string]bool, len(m))
	for key := range m {
		keys[key] = true
	}
	return keys
}

func (s *sqlScript) query(query string, _ []driver.NamedValue) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps = append(s.steps, query)
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps = append(s.steps, query)
	s.execs = append(s.execs, sqlScriptExec{query: query, args: plainValues(args)})
	if fragment, err := s.fragmentFor(query); err == nil && s.fail[fragment] != nil {
		return nil, s.fail[fragment]
	}
	return sqlScriptResult{id: s.insertID, rows: 1}, nil
}

// boundary records a transaction step and returns the error scripted for it.
func (s *sqlScript) boundary(step string, failure error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps = append(s.steps, step)
	return failure
}

type sqlScriptResult struct{ id, rows int64 }

func (r sqlScriptResult) LastInsertId() (int64, error) { return r.id, nil }
func (r sqlScriptResult) RowsAffected() (int64, error) { return r.rows, nil }

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

type sqlScriptConn struct{ s *sqlScript }

func (c sqlScriptConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c sqlScriptConn) Driver() driver.Driver                        { return sqlScriptDriver{} }
func (c sqlScriptConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c sqlScriptConn) Close() error                                 { return nil }

func (c sqlScriptConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c sqlScriptConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	if err := c.s.boundary("BEGIN", c.s.beginErr); err != nil {
		return nil, err
	}
	return sqlScriptTx(c), nil
}

type sqlScriptTx struct{ s *sqlScript }

func (t sqlScriptTx) Commit() error   { return t.s.boundary("COMMIT", t.s.commitErr) }
func (t sqlScriptTx) Rollback() error { return t.s.boundary("ROLLBACK", nil) }

func (c sqlScriptConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.s.query(query, args)
}

func (c sqlScriptConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.s.exec(query, args)
}

// plainValues drops the names and ordinals database/sql attaches to arguments.
func plainValues(args []driver.NamedValue) []driver.Value {
	plain := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		plain = append(plain, arg.Value)
	}
	return plain
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
		rows:    map[string][][]driver.Value{},
		fail:    map[string]error{},
		endWith: map[string]error{},
	}
}

var errScripted = errors.New("scripted failure")

// setForTest replaces a package variable for one test.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}
