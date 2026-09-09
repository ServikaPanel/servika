package tenantaccount

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// A recording driver rather than a mock library: the repository has no sqlmock
// dependency, and what has to be asserted here is which statements ran and with
// which values.
type recorder struct {
	mu sync.Mutex
	// existingUser and existingCustomer decide whether the two lookups find a
	// row, which is what separates the "create" path from the idempotent one.
	existingUser     int64
	existingCustomer int64
	statements       []string
	args             map[string][]driver.Value
}

func (r *recorder) record(query string, values []driver.NamedValue) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statements = append(r.statements, query)
	if r.args == nil {
		r.args = map[string][]driver.Value{}
	}
	plain := make([]driver.Value, 0, len(values))
	for _, value := range values {
		plain = append(plain, value.Value)
	}
	r.args[query] = plain
}

func (r *recorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.statements...)
}

func (r *recorder) ran(fragment string) bool {
	for _, statement := range r.recorded() {
		if strings.Contains(statement, fragment) {
			return true
		}
	}
	return false
}

func (r *recorder) argsFor(fragment string) []driver.Value {
	r.mu.Lock()
	defer r.mu.Unlock()
	for query, values := range r.args {
		if strings.Contains(query, fragment) {
			return values
		}
	}
	return nil
}

var (
	stateMu sync.Mutex
	state   = map[string]*recorder{}
)

type recordingDriver struct{}

func (recordingDriver) Open(name string) (driver.Conn, error) {
	stateMu.Lock()
	defer stateMu.Unlock()
	rec, ok := state[name]
	if !ok {
		return nil, fmt.Errorf("no recorder registered for %q", name)
	}
	return &recordingConn{rec: rec}, nil
}

func init() { sql.Register("tenantaccount_recorder", recordingDriver{}) }

type recordingConn struct{ rec *recorder }

func (c *recordingConn) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("prepare is not used by this test")
}
func (c *recordingConn) Close() error { return nil }
func (c *recordingConn) Begin() (driver.Tx, error) {
	c.rec.record("BEGIN", nil)
	return &recordingTx{rec: c.rec}, nil
}

func (c *recordingConn) ExecContext(_ context.Context, query string, values []driver.NamedValue) (driver.Result, error) {
	c.rec.record(query, values)
	// driver.RowsAffected refuses LastInsertId, and the code under test needs the
	// generated id to link the two rows together.
	return insertResult{id: 1001}, nil
}

type insertResult struct{ id int64 }

func (r insertResult) LastInsertId() (int64, error) { return r.id, nil }
func (r insertResult) RowsAffected() (int64, error) { return 1, nil }

func (c *recordingConn) QueryContext(_ context.Context, query string, values []driver.NamedValue) (driver.Rows, error) {
	c.rec.record(query, values)
	switch {
	case strings.Contains(query, "FROM users") && c.rec.existingUser > 0:
		return &idRow{id: c.rec.existingUser}, nil
	case strings.Contains(query, "FROM customers") && c.rec.existingCustomer > 0:
		return &idRow{id: c.rec.existingCustomer}, nil
	}
	return &idRow{}, nil // no rows: surfaces as sql.ErrNoRows
}

type idRow struct {
	id   int64
	done bool
}

func (r *idRow) Columns() []string { return []string{"id"} }
func (r *idRow) Close() error      { return nil }
func (r *idRow) Next(dest []driver.Value) error {
	if r.id == 0 || r.done {
		return io.EOF
	}
	dest[0] = r.id
	r.done = true
	return nil
}

type recordingTx struct{ rec *recorder }

func (t *recordingTx) Commit() error   { t.rec.record("COMMIT", nil); return nil }
func (t *recordingTx) Rollback() error { t.rec.record("ROLLBACK", nil); return nil }

func harness(t *testing.T, existingUser, existingCustomer int64) (*sql.DB, *recorder) {
	t.Helper()
	rec := &recorder{existingUser: existingUser, existingCustomer: existingCustomer}
	name := t.Name()

	stateMu.Lock()
	state[name] = rec
	stateMu.Unlock()
	t.Cleanup(func() {
		stateMu.Lock()
		delete(state, name)
		stateMu.Unlock()
	})

	db, err := sql.Open("tenantaccount_recorder", name)
	if err != nil {
		t.Fatalf("open the recording database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, rec
}

// A domain row with no system user identifies no tenant, so there is nothing to
// attach an account to. Creating one anyway would leave an account named after
// nobody that an operator then has to explain.
func TestNoTenantMeansNoDatabaseWork(t *testing.T) {
	db, rec := harness(t, 0, 0)

	account, err := Ensure(context.Background(), db, "", "example.com", nil)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if account.CustomerID != 0 {
		t.Errorf("CustomerID = %d, want 0", account.CustomerID)
	}
	if steps := rec.recorded(); len(steps) > 0 {
		t.Errorf("the database was touched for an empty tenant: %v", steps)
	}
}

// Ensure runs on every domain creation and on every boot through the backfill,
// so it has to be safe to repeat. Reusing the rows is what makes that true.
func TestExistingRowsAreReusedRatherThanDuplicated(t *testing.T) {
	db, rec := harness(t, 42, 7)

	account, err := Ensure(context.Background(), db, "c_example", "example.com", nil)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if account.CustomerID != 7 {
		t.Errorf("CustomerID = %d, want the existing 7", account.CustomerID)
	}
	if !account.Reused {
		t.Error("an existing customer was not reported as reused")
	}
	if rec.ran("INSERT INTO users") {
		t.Error("a second panel account was created for a tenant that already had one")
	}
	if rec.ran("INSERT INTO customers") {
		t.Error("a second customer record was created for a tenant that already had one")
	}
}

// The account exists but the customer record does not, which is the state a
// half-finished earlier run leaves behind. Only the missing half is created.
func TestOnlyTheMissingHalfIsCreated(t *testing.T) {
	db, rec := harness(t, 42, 0)

	if _, err := Ensure(context.Background(), db, "c_example", "example.com", nil); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if rec.ran("INSERT INTO users") {
		t.Error("the existing panel account was duplicated")
	}
	if !rec.ran("INSERT INTO customers") {
		t.Error("the missing customer record was not created")
	}
	if !rec.ran("COMMIT") {
		t.Error("the work was not committed")
	}
}

// An empty hash matches no password at all, so the account cannot be signed into
// until somebody assigns one. A generated password nobody is told would instead
// leave an account that has a password no one knows, which no screen can flag.
func TestTheCreatedAccountHasNoUsablePassword(t *testing.T) {
	db, rec := harness(t, 0, 0)

	if _, err := Ensure(context.Background(), db, "c_example", "example.com", nil); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !rec.ran("INSERT INTO users") {
		t.Fatal("no panel account was created")
	}
	statement := ""
	for _, step := range rec.recorded() {
		if strings.Contains(step, "INSERT INTO users") {
			statement = step
		}
	}
	if !strings.Contains(statement, "'', '', 'user'") {
		t.Errorf("the account was not created with an empty password hash: %q", statement)
	}
	// The tenant name and the display name are the only values bound, so a
	// password can never arrive through an argument either.
	if got := rec.argsFor("INSERT INTO users"); len(got) != 2 {
		t.Errorf("INSERT INTO users bound %d values, want 2 (tenant, display name)", len(got))
	}
}

func owner(v int64) *int64 { return new(v) }

// The owner is half of the ownership chain middleware.ScopeSQL walks. Written on
// creation, the reseller sees the domain; dropped, the record is unowned and the
// reseller it was meant for sees nothing.
func TestTheOwnerIsWrittenWhenTheCustomerIsCreated(t *testing.T) {
	db, rec := harness(t, 0, 0)

	account, err := Ensure(context.Background(), db, "c_example", "Example", owner(9))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if account.Reused {
		t.Error("a freshly created customer was reported as reused")
	}
	got := rec.argsFor("INSERT INTO customers")
	if len(got) != 3 {
		t.Fatalf("INSERT INTO customers bound %d values, want 3 (name, user, owner)", len(got))
	}
	if got[2] != int64(9) {
		t.Errorf("owner_user_id bound as %#v, want 9", got[2])
	}
}

// A customer with no reseller belongs directly to an administrator, which is
// what the startup backfill and every unattributed create produce. Binding
// anything but NULL there would invent an owner.
func TestNoOwnerBindsNull(t *testing.T) {
	db, rec := harness(t, 0, 0)

	if _, err := Ensure(context.Background(), db, "c_example", "Example", nil); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	got := rec.argsFor("INSERT INTO customers")
	if len(got) != 3 {
		t.Fatalf("INSERT INTO customers bound %d values, want 3 (name, user, owner)", len(got))
	}
	if got[2] != nil {
		t.Errorf("owner_user_id bound as %#v, want NULL", got[2])
	}
}

// Two long domain names truncate to the same 26-character system user, so a
// second create can land on a tenant that already has a customer. Rewriting the
// owner there would move an account in use, so the row is left alone and the
// caller is told the owner it asked for was not applied.
func TestAnExistingCustomerKeepsItsOwner(t *testing.T) {
	db, rec := harness(t, 42, 7)

	account, err := Ensure(context.Background(), db, "c_example", "Example", owner(9))
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !account.Reused {
		t.Error("the caller was not told the existing customer was reused")
	}
	if rec.ran("UPDATE customers") {
		t.Error("the owner of a customer already in use was rewritten")
	}
	if rec.ran("INSERT INTO customers") {
		t.Error("a second customer record was created")
	}
}
