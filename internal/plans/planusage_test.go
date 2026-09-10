package plans

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

	"github.com/go-chi/chi/v5"
)

// A scripted driver, because what has to be asserted is which TABLES the guard
// counts before it deletes. The repository carries no sqlmock dependency.
type planScript struct {
	mu sync.Mutex
	// rows answers a read whose query contains the fragment.
	rows map[string][]driver.Value
	// queries and execs record what the handler asked, in order.
	queries []string
	execs   []string
}

func (s *planScript) answerQuery(query string) (driver.Rows, error) {
	s.mu.Lock()
	s.queries = append(s.queries, query)
	defer s.mu.Unlock()
	for fragment, values := range s.rows {
		if strings.Contains(query, fragment) {
			return &planRows{values: values}, nil
		}
	}
	return nil, fmt.Errorf("the test script has no answer for: %s", query)
}

func (s *planScript) recordExec(query string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execs = append(s.execs, query)
}

func (s *planScript) deleted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, query := range s.execs {
		if strings.Contains(query, "DELETE FROM service_plans") {
			return true
		}
	}
	return false
}

type planRows struct {
	values []driver.Value
	done   bool
}

func (r *planRows) Columns() []string { return make([]string, len(r.values)) }
func (r *planRows) Close() error      { return nil }
func (r *planRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

type planConn struct{ script *planScript }

func (c planConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c planConn) Driver() driver.Driver                        { return planDriver{} }
func (c planConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c planConn) Close() error                                 { return nil }
func (c planConn) Begin() (driver.Tx, error)                    { return planTx{}, nil }

func (c planConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.script.answerQuery(query)
}

func (c planConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.script.recordExec(query)
	return planResult{}, nil
}

type planTx struct{}

func (planTx) Commit() error   { return nil }
func (planTx) Rollback() error { return nil }

type planResult struct{}

func (planResult) LastInsertId() (int64, error) { return 1, nil }
func (planResult) RowsAffected() (int64, error) { return 1, nil }

type planDriver struct{}

func (planDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// usageScript answers the guard's single read with the two counts it asks for.
func usageScript(domains, customers int64) *planScript {
	return &planScript{
		rows: map[string][]driver.Value{
			"FROM customers WHERE plan_id=?": {domains, customers},
		},
	}
}

func runDelete(t *testing.T, script *planScript) *httptest.ResponseRecorder {
	t.Helper()
	db := sql.OpenDB(planConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	request := httptest.NewRequest(http.MethodDelete, "/plans/4", nil)
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "4")
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeCtx))
	recorder := httptest.NewRecorder()
	(&Handlers{DB: db}).Delete(recorder, request)
	return recorder
}

// customers.plan_id is a second, independent reference to service_plans with no
// foreign key. The guard counted domains only, so a plan that only customers
// referenced could be deleted, leaving those rows pointing at nothing. Every
// count quota then answers 500 and the customer permanently cannot create a
// database, a mailbox, an application or an addon domain.
func TestAPlanReferencedOnlyByCustomersCannotBeDeleted(t *testing.T) {
	script := usageScript(0, 3)

	recorder := runDelete(t, script)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}
	if script.deleted() {
		t.Fatal("the plan was deleted while customers still referenced it")
	}
}

// The guard must count both references, so the refusal names the real number.
func TestTheInUseCountSumsBothReferences(t *testing.T) {
	script := usageScript(2, 3)

	recorder := runDelete(t, script)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusConflict)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "5") {
		t.Fatalf("the refusal reported %q, want the sum of both references", body)
	}
	script.mu.Lock()
	defer script.mu.Unlock()
	joined := strings.Join(script.queries, "\n")
	if !strings.Contains(joined, "FROM customers WHERE plan_id=?") {
		t.Fatalf("the guard never counted customers:\n%s", joined)
	}
	if !strings.Contains(joined, "FROM domains   WHERE plan_id=?") {
		t.Fatalf("the guard stopped counting domains:\n%s", joined)
	}
}

// A plan nothing references is still deletable, so the guard is not simply
// refusing everything.
func TestAnUnreferencedPlanIsDeleted(t *testing.T) {
	script := usageScript(0, 0)

	recorder := runDelete(t, script)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if !script.deleted() {
		t.Fatal("an unreferenced plan was not deleted")
	}
}

// A count the guard cannot read is not evidence that nothing references the
// plan.
func TestAnUnreadableCountRefusesTheDelete(t *testing.T) {
	script := usageScript(0, 0)
	delete(script.rows, "FROM customers WHERE plan_id=?")

	recorder := runDelete(t, script)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
	if script.deleted() {
		t.Fatal("the plan was deleted although the guard could not count its references")
	}
}
