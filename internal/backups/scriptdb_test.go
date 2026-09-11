package backups

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
	"time"
)

// A scripted database, in the shape internal/provisioner uses: a query is
// answered by the fragment of its text that the script names, a result set can
// end in an error instead of io.EOF, and every statement is recorded with its
// arguments.
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
	// fail maps a query fragment to the error the statement itself returns.
	fail map[string]error
	// endWith maps a query fragment to the error its result set ends with once
	// its rows are exhausted.
	endWith map[string]error
	// insertID is what every statement reports as its last insert id.
	insertID int64
	// affected maps a statement fragment to the row count it reports; any other
	// statement reports one row.
	affected map[string]int64
	queries  []string
	// onExec, when set, runs after a statement is recorded, for a test that has
	// to act at one exact step of a sequence running on another goroutine.
	onExec func(query string)
	execs  []sqlScriptExec
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
		// A fragment that is the whole query wins, because one query can be a
		// part of another and no shorter fragment then tells them apart.
		return query, nil
	default:
		sort.Strings(matched)
		return "", fmt.Errorf("the test script answers %q with more than one fragment: %v", query, matched)
	}
}

func (s *sqlScript) query(query string) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, query)
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
	plain := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		plain = append(plain, arg.Value)
	}
	s.execs = append(s.execs, sqlScriptExec{query: query, args: plain})
	var failure error
	rows := int64(1)
	if fragment, err := s.fragmentFor(query); err == nil {
		failure = s.fail[fragment]
	}
	for fragment, count := range s.affected {
		if strings.Contains(query, fragment) {
			rows = count
		}
	}
	result, hook := sqlScriptResult{id: s.insertID, rows: rows}, s.onExec
	s.mu.Unlock()
	if hook != nil {
		hook(query)
	}
	if failure != nil {
		return nil, failure
	}
	return result, nil
}

type sqlScriptResult struct{ id, rows int64 }

func (r sqlScriptResult) LastInsertId() (int64, error) { return r.id, nil }
func (r sqlScriptResult) RowsAffected() (int64, error) { return r.rows, nil }

// queriesContaining counts the recorded queries whose text holds fragment.
func (s *sqlScript) queriesContaining(fragment string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, query := range s.queries {
		if strings.Contains(query, fragment) {
			n++
		}
	}
	return n
}

// waitForQuery waits until a query holding fragment has run.
func (s *sqlScript) waitForQuery(t *testing.T, fragment string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s.queriesContaining(fragment) > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no query holding %q ran", fragment)
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
func (c sqlScriptConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c sqlScriptConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.s.query(query)
}

func (c sqlScriptConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.s.exec(query, args)
}

// waitForExec waits until a statement holding fragment has run, for work that
// finishes on a goroutine the test does not own.
func (s *sqlScript) waitForExec(t *testing.T, fragment string) []sqlScriptExec {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if found := s.execsContaining(fragment); len(found) > 0 {
			return found
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no statement holding %q ran", fragment)
	return nil
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
