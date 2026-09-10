package accounts

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

// A scripted driver, because what has to be asserted is that no customers row is
// written with a plan_id that names no plan. The repository carries no sqlmock
// dependency.
type accountScript struct {
	mu    sync.Mutex
	rows  map[string][]driver.Value
	execs []string
}

func (s *accountScript) answerQuery(query string) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, values := range s.rows {
		if strings.Contains(query, fragment) {
			return &accountRows{values: values}, nil
		}
	}
	return nil, fmt.Errorf("the test script has no answer for: %s", query)
}

func (s *accountScript) recordExec(query string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execs = append(s.execs, query)
}

// wrote reports whether any statement contained the fragment.
func (s *accountScript) wrote(fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, query := range s.execs {
		if strings.Contains(query, fragment) {
			return true
		}
	}
	return false
}

type accountRows struct {
	values []driver.Value
	done   bool
}

func (r *accountRows) Columns() []string { return make([]string, len(r.values)) }
func (r *accountRows) Close() error      { return nil }
func (r *accountRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

type accountConn struct{ script *accountScript }

func (c accountConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c accountConn) Driver() driver.Driver                        { return accountDriver{} }
func (c accountConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c accountConn) Close() error                                 { return nil }
func (c accountConn) Begin() (driver.Tx, error)                    { return accountTx{}, nil }

func (c accountConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.script.answerQuery(query)
}

func (c accountConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.script.recordExec(query)
	return accountResult{}, nil
}

type accountTx struct{}

func (accountTx) Commit() error   { return nil }
func (accountTx) Rollback() error { return nil }

type accountResult struct{}

func (accountResult) LastInsertId() (int64, error) { return 7, nil }
func (accountResult) RowsAffected() (int64, error) { return 1, nil }

type accountDriver struct{}

func (accountDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// planScript answers the existence check with `found` matching plans.
func planScript(found int64) *accountScript {
	return &accountScript{
		rows: map[string][]driver.Value{
			"FROM service_plans WHERE id=?": {found},
		},
	}
}

func adminRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "7")
	ctx := context.WithValue(request.Context(), chi.RouteCtxKey, routeCtx)
	ctx = auth.WithClaims(ctx, &auth.Claims{UserID: 1, Username: "admin", Role: middleware.RoleAdmin})
	return request.WithContext(ctx)
}

func runCreate(t *testing.T, script *accountScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	db := sql.OpenDB(accountConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	recorder := httptest.NewRecorder()
	(&Handlers{DB: db}).CreateCustomer(recorder, adminRequest(http.MethodPost, "/customers", body))
	return recorder
}

// customers.plan_id carries no foreign key, so an id naming no plan is stored
// happily. Every count quota then reads that customer's plan, finds nothing, and
// answers 500, so the customer permanently cannot create a database, a mailbox,
// an application or an addon domain.
func TestACustomerCannotBeCreatedOnAPlanThatDoesNotExist(t *testing.T) {
	script := planScript(0)

	recorder := runCreate(t, script, `{"name":"Acme","email":"a@b.c","plan_id":4242}`)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	if script.wrote("INSERT INTO customers") {
		t.Fatal("a customer row was written with a plan id that names no plan")
	}
}

// The same question on the update path, which wrote plan_id with no check at
// all.
func TestACustomerCannotBeMovedToAPlanThatDoesNotExist(t *testing.T) {
	script := planScript(0)
	db := sql.OpenDB(accountConn{script: script})
	t.Cleanup(func() { _ = db.Close() })

	recorder := httptest.NewRecorder()
	(&Handlers{DB: db}).UpdateCustomer(recorder,
		adminRequest(http.MethodPut, "/customers/7", `{"name":"Acme","email":"a@b.c","plan_id":4242}`))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	if script.wrote("UPDATE customers") {
		t.Fatal("a customer was moved to a plan id that names no plan")
	}
}

// A plan that exists is still accepted, so the check is not simply refusing
// every assignment.
func TestACustomerOnARealPlanIsCreated(t *testing.T) {
	script := planScript(1)

	recorder := runCreate(t, script, `{"name":"Acme","email":"a@b.c","plan_id":3}`)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	if !script.wrote("INSERT INTO customers") {
		t.Fatal("a customer on a real plan was not written")
	}
}

// A null plan means "on no plan", which every count gate passes through. It must
// not be turned into a refusal, and it must not cost a lookup for an id that is
// not there.
func TestACustomerOnNoPlanIsCreated(t *testing.T) {
	script := &accountScript{rows: map[string][]driver.Value{}}

	recorder := runCreate(t, script, `{"name":"Acme","email":"a@b.c","plan_id":null}`)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	if !script.wrote("INSERT INTO customers") {
		t.Fatal("a customer on no plan was not written")
	}
}

// A lookup the check cannot complete is not evidence that the plan exists.
func TestAnUnreadablePlanLookupRefusesTheWrite(t *testing.T) {
	script := &accountScript{rows: map[string][]driver.Value{}}

	recorder := runCreate(t, script, `{"name":"Acme","email":"a@b.c","plan_id":3}`)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusInternalServerError, recorder.Body.String())
	}
	if script.wrote("INSERT INTO customers") {
		t.Fatal("a customer was written although the plan could not be verified")
	}
}
