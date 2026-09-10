package domains

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"
)

// A recording driver, as used in internal/mail, internal/users and
// internal/tenantaccount: no sqlmock dependency, and what matters is the exact
// statement the handler builds.
type ownerRecorder struct {
	mu sync.Mutex
	// ownsCustomer decides what the reseller ownership lookup answers.
	ownsCustomer bool
	statements   []string
	values       [][]driver.Value
}

func (r *ownerRecorder) record(query string, args []driver.NamedValue) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statements = append(r.statements, query)
	plain := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		plain = append(plain, arg.Value)
	}
	r.values = append(r.values, plain)
}

// matching returns every recorded statement containing the fragment, with its
// bound values.
func (r *ownerRecorder) matching(fragment string) (statements []string, values [][]driver.Value) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, statement := range r.statements {
		if strings.Contains(statement, fragment) {
			statements = append(statements, statement)
			values = append(values, r.values[i])
		}
	}
	return statements, values
}

func (r *ownerRecorder) update() (string, []driver.Value) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, statement := range r.statements {
		if strings.HasPrefix(statement, "UPDATE domains") {
			return statement, r.values[i]
		}
	}
	return "", nil
}

var (
	ownerStateMu sync.Mutex
	ownerState   = map[string]*ownerRecorder{}
)

type ownerDriver struct{}

func (ownerDriver) Open(name string) (driver.Conn, error) {
	ownerStateMu.Lock()
	defer ownerStateMu.Unlock()
	rec, ok := ownerState[name]
	if !ok {
		return nil, fmt.Errorf("no recorder registered for %q", name)
	}
	return &ownerConn{rec: rec}, nil
}

func init() { sql.Register("domains_owner_recorder", ownerDriver{}) }

type ownerConn struct{ rec *ownerRecorder }

func (c *ownerConn) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("prepare is not used by this test")
}
func (c *ownerConn) Close() error { return nil }
func (c *ownerConn) Begin() (driver.Tx, error) {
	return nil, fmt.Errorf("transactions are not used here")
}

func (c *ownerConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.rec.record(query, args)
	return driver.RowsAffected(1), nil
}

func (c *ownerConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.rec.record(query, args)
	switch {
	case strings.Contains(query, "FROM customers WHERE id = ? AND owner_user_id = ?"):
		return &countRow{n: boolToInt(c.rec.ownsCustomer)}, nil
	case strings.Contains(query, "COUNT(*) FROM customers WHERE id=?"):
		return &countRow{n: 1}, nil // the target customer exists
	case strings.Contains(query, "SELECT domain_name, system_user, is_demo"):
		return &staticRows{
			columns: []string{"domain_name", "system_user", "is_demo"},
			rows:    [][]driver.Value{{"parent.example", "c_parent", int64(0)}},
		}, nil
	case strings.Contains(query, "parent_domain_id=?"):
		// A parent that is active and an addon that was suspended on its own
		// earlier. The two differ deliberately: a rollback must put each row back
		// as it was found.
		return &staticRows{
			columns: []string{"id", "suspended", "status"},
			rows: [][]driver.Value{
				{int64(7), int64(0), "active"},
				{int64(8), int64(1), "passive"},
			},
		}, nil
	case strings.Contains(query, "php_version"):
		// RerenderVhost's own read. Refusing it here fails the render
		// deterministically, which is the rollback path the suspension tests
		// measure; it is unreachable from the owner tests.
		return nil, fmt.Errorf("the vhost render is refused in this test")
	}
	return &countRow{n: 0}, nil
}

// staticRows answers a fixed result set of any width, unlike countRow.
type staticRows struct {
	columns []string
	rows    [][]driver.Value
	next    int
}

func (r *staticRows) Columns() []string { return r.columns }
func (r *staticRows) Close() error      { return nil }
func (r *staticRows) Next(dest []driver.Value) error {
	if r.next >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.next])
	r.next++
	return nil
}

func boolToInt(v bool) int64 {
	if v {
		return 1
	}
	return 0
}

type countRow struct {
	n    int64
	done bool
}

func (r *countRow) Columns() []string { return []string{"n"} }
func (r *countRow) Close() error      { return nil }
func (r *countRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	dest[0] = r.n
	r.done = true
	return nil
}

func ownerHarness(t *testing.T, ownsCustomer bool) (*Handlers, *ownerRecorder) {
	t.Helper()
	rec := &ownerRecorder{ownsCustomer: ownsCustomer}
	name := t.Name()

	ownerStateMu.Lock()
	ownerState[name] = rec
	ownerStateMu.Unlock()
	t.Cleanup(func() {
		ownerStateMu.Lock()
		delete(ownerState, name)
		ownerStateMu.Unlock()
	})

	db, err := sql.Open("domains_owner_recorder", name)
	if err != nil {
		t.Fatalf("open the recording database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// ResellerOwnsCustomer reads through the middleware's own handle.
	middleware.Init(db)
	t.Cleanup(func() { middleware.Init(nil) })

	return &Handlers{DB: db}, rec
}

func ownerRequest(actor *auth.Claims, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/domains/bulk/owner", strings.NewReader(body))
	return request.WithContext(auth.WithClaims(request.Context(), actor))
}

var (
	adminActor    = &auth.Claims{UserID: 1, Username: "admin", Role: middleware.RoleAdmin}
	resellerActor = &auth.Claims{UserID: 9, Username: "reseller", Role: middleware.RoleReseller}
)

// The ids arrive in the request body, so a reseller could name any domain on the
// server. Narrowing the statement itself, rather than checking row by row, is
// what makes a hand-built body harmless: an unowned id matches nothing.
func TestAResellerCanOnlyMoveItsOwnDomains(t *testing.T) {
	handlers, recorder := ownerHarness(t, true)
	response := httptest.NewRecorder()
	handlers.BulkOwner(response, ownerRequest(resellerActor, `{"ids":[1,2],"customer_id":5}`))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (%s)", response.Code, http.StatusOK, response.Body.String())
	}
	statement, args := recorder.update()
	if statement == "" {
		t.Fatal("no UPDATE ran")
	}
	if !strings.Contains(statement, "owner_user_id = ?") {
		t.Errorf("the statement is not narrowed to the reseller's own domains: %q", statement)
	}
	// customer_id, the two ids for d.id, the same two again for
	// d.parent_domain_id, then the reseller's own user id for the scope.
	if len(args) != 6 || args[5] != int64(9) {
		t.Errorf("bound values = %v, want the reseller id last", args)
	}
}

// An administrator sees every domain, so the same statement must stay unnarrowed
// for them; adding a scope clause would quietly stop admin transfers working.
func TestAnAdministratorsStatementIsNotNarrowed(t *testing.T) {
	handlers, recorder := ownerHarness(t, false)
	response := httptest.NewRecorder()
	handlers.BulkOwner(response, ownerRequest(adminActor, `{"ids":[1,2],"customer_id":5}`))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (%s)", response.Code, http.StatusOK, response.Body.String())
	}
	statement, args := recorder.update()
	if strings.Contains(statement, "owner_user_id") {
		t.Errorf("an administrator's statement was narrowed: %q", statement)
	}
	if len(args) != 5 {
		t.Errorf("bound values = %v, want customer id plus the two domain ids twice", args)
	}
}

// An addon domain copied its parent's customer_id AND its system_user, and
// nothing re-derives either afterwards. Moving the parent alone left a row owned
// by the previous customer whose system_user is the account the new owner now
// holds, so the old owner reached the new owner's home directory, databases and
// backups through that row's id.
func TestATransferTakesTheAddonRowsWithIt(t *testing.T) {
	handlers, recorder := ownerHarness(t, true)
	response := httptest.NewRecorder()
	handlers.BulkOwner(response, ownerRequest(adminActor, `{"ids":[1,2],"customer_id":5}`))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (%s)", response.Code, http.StatusOK, response.Body.String())
	}
	statement, _ := recorder.update()
	if !strings.Contains(statement, "d.parent_domain_id IN (?,?)") {
		t.Fatalf("the transfer does not reach addon rows: %q", statement)
	}
	// The two id conditions must be bracketed together, or a scope fragment binds
	// to the second alternative alone and a reseller moves an addon row of a
	// domain they do not own.
	if !strings.Contains(statement, "WHERE (d.id IN (?,?) OR d.parent_domain_id IN (?,?))") {
		t.Errorf("the two id conditions are not bracketed together: %q", statement)
	}
}

// Handing a domain to a customer the reseller does not own would push it out of
// its own scope and into another's.
func TestAResellerCannotHandADomainToAnotherResellersCustomer(t *testing.T) {
	handlers, recorder := ownerHarness(t, false)
	response := httptest.NewRecorder()
	handlers.BulkOwner(response, ownerRequest(resellerActor, `{"ids":[1],"customer_id":5}`))

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if statement, _ := recorder.update(); statement != "" {
		t.Errorf("the refusal still ran an UPDATE: %q", statement)
	}
}

// Detaching moves the domain to admin, out of the reseller's scope for good. It
// could not undo that, so it stays an administrator's call.
func TestOnlyAnAdministratorCanDetachADomain(t *testing.T) {
	t.Run("a reseller is refused", func(t *testing.T) {
		handlers, recorder := ownerHarness(t, true)
		response := httptest.NewRecorder()
		handlers.BulkOwner(response, ownerRequest(resellerActor, `{"ids":[1],"customer_id":null}`))

		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
		}
		if statement, _ := recorder.update(); statement != "" {
			t.Errorf("the refusal still ran an UPDATE: %q", statement)
		}
	})

	t.Run("an administrator may", func(t *testing.T) {
		handlers, recorder := ownerHarness(t, false)
		response := httptest.NewRecorder()
		handlers.BulkOwner(response, ownerRequest(adminActor, `{"ids":[1],"customer_id":null}`))

		if response.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (%s)", response.Code, http.StatusOK, response.Body.String())
		}
		_, args := recorder.update()
		if len(args) == 0 || args[0] != nil {
			t.Errorf("customer_id was not cleared: %v", args)
		}
	})
}
