package apps

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

// A scripted database, in the shape internal/git uses. A query is answered by
// the fragment of its text that the script names, and every statement is
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
	// insertID is what LastInsertId reports, which is how a create learns the
	// id of the row it just wrote.
	insertID int64
	// steps records every query and statement in order.
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
	for _, fragments := range []map[string]bool{keysOf(s.fail), keysOf(s.rows)} {
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
	return &sqlScriptRows{rows: s.rows[fragment]}, nil
}

// exec records the statement and fails it only when the script says so; a
// statement nobody scripted succeeds.
func (s *sqlScript) exec(query string, args []driver.NamedValue) (driver.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps = append(s.steps, query)
	s.execs = append(s.execs, sqlScriptExec{query: query, args: plainValues(args)})
	fragment, err := s.fragmentFor(query)
	if err == nil && s.fail[fragment] != nil {
		return nil, s.fail[fragment]
	}
	return sqlScriptResult{id: s.insertID, rows: 1}, nil
}

// ran reports whether a statement carrying fragment was executed.
func (s *sqlScript) ran(fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, exec := range s.execs {
		if strings.Contains(exec.query, fragment) {
			return true
		}
	}
	return false
}

// argsOf returns the arguments of the first statement carrying fragment.
func (s *sqlScript) argsOf(t *testing.T, fragment string) []driver.Value {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, exec := range s.execs {
		if strings.Contains(exec.query, fragment) {
			return exec.args
		}
	}
	t.Fatalf("no statement carrying %q ran: %v", fragment, s.steps)
	return nil
}

type sqlScriptResult struct{ id, rows int64 }

func (r sqlScriptResult) LastInsertId() (int64, error) { return r.id, nil }
func (r sqlScriptResult) RowsAffected() (int64, error) { return r.rows, nil }

type sqlScriptRows struct {
	rows [][]driver.Value
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

// Begin is a no-op transaction: ReplaceEnv writes inside one, and what the
// tests read back is the recorded statements, not a committed state.
func (c sqlScriptConn) Begin() (driver.Tx, error) { return sqlScriptTx{}, nil }

type sqlScriptTx struct{}

func (sqlScriptTx) Commit() error   { return nil }
func (sqlScriptTx) Rollback() error { return nil }

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
		rows: map[string][][]driver.Value{},
		fail: map[string]error{},
	}
}
