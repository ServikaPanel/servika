package appinstall

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// A scripted driver, because what has to be asserted is that the installer
// consults the plan BEFORE it writes anything: an installation that creates its
// schema first has already spent the entitlement. The repository carries no
// sqlmock dependency.
type quotaScript struct {
	mu    sync.Mutex
	rows  map[string][]driver.Value
	execs []string
}

func (s *quotaScript) answerQuery(query string) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, values := range s.rows {
		if strings.Contains(query, fragment) {
			return &quotaRows{values: values}, nil
		}
	}
	return nil, fmt.Errorf("the test script has no answer for: %s", query)
}

func (s *quotaScript) recordExec(query string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execs = append(s.execs, query)
}

// wrote reports whether any statement contained the fragment.
func (s *quotaScript) wrote(fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, query := range s.execs {
		if strings.Contains(query, fragment) {
			return true
		}
	}
	return false
}

type quotaRows struct {
	values []driver.Value
	done   bool
}

func (r *quotaRows) Columns() []string { return make([]string, len(r.values)) }
func (r *quotaRows) Close() error      { return nil }
func (r *quotaRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

type quotaConn struct{ script *quotaScript }

func (c quotaConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c quotaConn) Driver() driver.Driver                        { return quotaDriver{} }
func (c quotaConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c quotaConn) Close() error                                 { return nil }
func (c quotaConn) Begin() (driver.Tx, error)                    { return quotaTx{}, nil }

func (c quotaConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.script.answerQuery(query)
}

func (c quotaConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.script.recordExec(query)
	return quotaResult{}, nil
}

type quotaTx struct{}

func (quotaTx) Commit() error   { return nil }
func (quotaTx) Rollback() error { return nil }

type quotaResult struct{}

func (quotaResult) LastInsertId() (int64, error) { return 1, nil }
func (quotaResult) RowsAffected() (int64, error) { return 1, nil }

type quotaDriver struct{}

func (quotaDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// planScript answers every read the plan gate makes: the domain belongs to
// customer 7 on plan 3, whose max_db is `maximum`, and the customer already owns
// `owned` databases.
func planScript(maximum, owned int) *quotaScript {
	return &quotaScript{
		rows: map[string][]driver.Value{
			// Each fragment must match ONE query, or map order (which is random)
			// would answer a different query on every run.
			"customer_id FROM domains":    {int64(7)},
			"plan_id FROM customers":      {int64(3)},
			"max_db FROM service_plans":   {int64(maximum)},
			"COUNT(*) FROM db_accounts a": {int64(owned)},
			// The creation reuses the tenant's existing database account, so it
			// reads that account's password before it writes anything.
			"db_pass_plain FROM db_accounts": {"stored-password"},
			// The account is granted from every host the tenant registered.
			"mysql_host FROM db_remote_hosts": {"203.0.113.9"},
		},
	}
}

func quotaDB(t *testing.T, script *quotaScript) *sql.DB {
	t.Helper()
	db := sql.OpenDB(quotaConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// max_db is a billed tier boundary. The one-click installer reached
// credentials.MySQLCreateDBForUser directly, so a customer on max_db=1 could
// create an unbounded number of schemas by installing catalog applications into
// different subdirectories with different suffixes.
func TestAnInstallationCannotCreateADatabasePastThePlanLimit(t *testing.T) {
	script := planScript(1, 1)

	err := createDatabaseWithinPlan(context.Background(), quotaDB(t, script), 5, "c_t_shop", "c_t_db")

	if got := ReasonOf(err); got != ReasonDatabaseLimit {
		t.Fatalf("reason = %q, want %q (error: %v)", got, ReasonDatabaseLimit, err)
	}
	if script.wrote("CREATE DATABASE") {
		t.Fatal("the schema was created even though the plan refused it")
	}
	if script.wrote("INSERT INTO db_accounts") {
		t.Fatal("a db_accounts row was written even though the plan refused it")
	}
}

// The gate must not refuse an installation the plan does allow, or the whole
// feature stops working on every plan that has any limit at all.
//
// The assertion is that the call reaches the creation primitive, not that the
// schema appears: MySQLCreateDBForUser shells out to the mysql client, which is
// not present where the tests run. Reaching it means the gate passed, and the
// refusal test above proves the gate stops the call when it does not.
func TestAnInstallationUnderThePlanLimitReachesTheCreation(t *testing.T) {
	script := planScript(3, 1)

	err := createDatabaseWithinPlan(context.Background(), quotaDB(t, script), 5, "c_t_shop", "c_t_db")

	if got := ReasonOf(err); got == ReasonDatabaseLimit {
		t.Fatalf("an installation within the plan was refused as over the limit: %v", err)
	}
	if !script.wrote("INSERT INTO db_accounts") && !strings.Contains(fmt.Sprint(err), "mysql") {
		t.Fatalf("the call never reached the creation primitive: %v", err)
	}
}

// A plan refusal is the customer's own subscription answering a well-formed
// request, so it is a 403 rather than the 400 every other refusal carries.
func TestThePlanLimitIsReportedAsForbidden(t *testing.T) {
	if got := statusForReason(ReasonDatabaseLimit); got != http.StatusForbidden {
		t.Fatalf("statusForReason(%q) = %d, want %d", ReasonDatabaseLimit, got, http.StatusForbidden)
	}
	// The codes that were already mapped keep their status.
	if got := statusForReason(ReasonTargetNotEmpty); got != http.StatusConflict {
		t.Fatalf("statusForReason(%q) = %d, want %d", ReasonTargetNotEmpty, got, http.StatusConflict)
	}
	if got := statusForReason(ReasonDatabaseExists); got != http.StatusConflict {
		t.Fatalf("statusForReason(%q) = %d, want %d", ReasonDatabaseExists, got, http.StatusConflict)
	}
	if got := statusForReason(ReasonChecksum); got != http.StatusBadRequest {
		t.Fatalf("statusForReason(%q) = %d, want %d", ReasonChecksum, got, http.StatusBadRequest)
	}
}

// A read the gate cannot complete is not evidence that the plan allows another
// database, and the error must reach the caller rather than becoming a refusal
// code that reads as a plan decision.
func TestAnUnreadablePlanBlocksTheDatabase(t *testing.T) {
	script := planScript(1, 1)
	delete(script.rows, "COUNT(*) FROM db_accounts a")

	err := createDatabaseWithinPlan(context.Background(), quotaDB(t, script), 5, "c_t_shop", "c_t_db")

	if err == nil {
		t.Fatal("an unreadable plan count created the database anyway")
	}
	if got := ReasonOf(err); got != "" {
		t.Fatalf("reason = %q, want the underlying error rather than a refusal code", got)
	}
	if script.wrote("CREATE DATABASE") {
		t.Fatal("the schema was created even though the plan could not be read")
	}
}
