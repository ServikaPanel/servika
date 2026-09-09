package quota

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

// CheckAppAllowed asks the database four questions in order, and the answer to
// the last one is the whole gate. A driver that fails every query would only
// prove the first lookup is checked; these tests need the count to fail AFTER
// the limit has already been read, which is the state a busy or restarting
// MariaDB actually produces.
//
// The scripted driver below answers by matching a fragment of the query text,
// so a test can let three queries succeed and break the fourth.

var errCountUnavailable = errors.New("lost connection to MySQL server during query")

// script maps a query fragment to what the driver should answer with. A nil
// slice with a non-nil error makes that query fail.
type script struct {
	rows map[string][]driver.Value
	fail map[string]error
}

// scriptedConn is its own connector: the script is the entire per-connection
// state, so a separate connector type would just be the same struct again.
type scriptedConn struct{ s *script }

func (c scriptedConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c scriptedConn) Driver() driver.Driver                        { return scriptedDriver{} }

func (c scriptedConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c scriptedConn) Close() error                        { return nil }
func (c scriptedConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }

func (c scriptedConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	for fragment, err := range c.s.fail {
		if strings.Contains(query, fragment) {
			return nil, err
		}
	}
	for fragment, values := range c.s.rows {
		if strings.Contains(query, fragment) {
			return &scriptedRows{values: values}, nil
		}
	}
	return nil, errors.New("the test script has no answer for: " + query)
}

type scriptedRows struct {
	values []driver.Value
	done   bool
}

func (r *scriptedRows) Columns() []string { return make([]string, len(r.values)) }
func (r *scriptedRows) Close() error      { return nil }
func (r *scriptedRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

type scriptedDriver struct{}

func (scriptedDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// scriptedDB opens a handle straight from the connector, so each test gets its
// own script without a globally registered driver name to collide over.
func scriptedDB(t *testing.T, s *script) *sql.DB {
	t.Helper()
	db := sql.OpenDB(scriptedConn{s: s})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// baseScript answers the three lookups that precede the count: the domain
// belongs to customer 7, that customer is on plan 3, and the plan allows two
// applications.
func baseScript() *script {
	return &script{
		rows: map[string][]driver.Value{
			"customer_id FROM domains": {int64(7)},
			"plan_id FROM customers":   {int64(3)},
			"max_app":                  {int64(2)},
		},
		fail: map[string]error{},
	}
}

// The gate must deny when the count cannot be read. A guard that returned nil
// here would hand out an unlimited number of resident processes to every
// customer for as long as the database was unwell, which is exactly when the
// host can least afford them.
func TestAnUnreadableCountDeniesTheApplication(t *testing.T) {
	s := baseScript()
	s.fail["COUNT(*) FROM apps"] = errCountUnavailable

	err := CheckAppAllowed(context.Background(), scriptedDB(t, s), 42)
	if err == nil {
		t.Fatal("a failed count was treated as permission to create the application")
	}
	if _, ok := errors.AsType[*LimitError](err); ok {
		t.Fatalf("a database failure was reported as a plan limit: %v", err)
	}
}

// The opposite direction: with the same script and a working count below the
// limit the gate must pass, so the test above is not merely watching a guard
// that always denies.
func TestAnApplicationUnderTheLimitIsAllowed(t *testing.T) {
	s := baseScript()
	s.rows["COUNT(*) FROM apps"] = []driver.Value{int64(1)}

	if err := CheckAppAllowed(context.Background(), scriptedDB(t, s), 42); err != nil {
		t.Fatalf("a customer with 1 of 2 applications was refused: %v", err)
	}
}

func TestReachingTheLimitIsReportedAsAPlanLimit(t *testing.T) {
	s := baseScript()
	s.rows["COUNT(*) FROM apps"] = []driver.Value{int64(2)}

	err := CheckAppAllowed(context.Background(), scriptedDB(t, s), 42)
	var limit *LimitError
	if !errors.As(err, &limit) {
		t.Fatalf("want a LimitError at the limit, got %v", err)
	}
	if !strings.Contains(limit.Error(), "2") {
		t.Errorf("the message does not name the limit: %q", limit.Error())
	}
}

// Zero means unlimited, and the count must not even be asked for. Scripting the
// count to fail proves the query never runs rather than merely that its answer
// is ignored.
func TestAZeroLimitSkipsTheCountEntirely(t *testing.T) {
	s := baseScript()
	s.rows["max_app"] = []driver.Value{int64(0)}
	s.fail["COUNT(*) FROM apps"] = errCountUnavailable

	if err := CheckAppAllowed(context.Background(), scriptedDB(t, s), 42); err != nil {
		t.Fatalf("an unlimited plan was refused: %v", err)
	}
}

// A domain with no customer belongs to an administrator, who has no plan.
func TestADomainWithoutACustomerIsUnlimited(t *testing.T) {
	s := &script{
		rows: map[string][]driver.Value{"customer_id FROM domains": {nil}},
		fail: map[string]error{"plan_id FROM customers": errCountUnavailable},
	}

	if err := CheckAppAllowed(context.Background(), scriptedDB(t, s), 42); err != nil {
		t.Fatalf("an administrator-owned domain was refused: %v", err)
	}
}
