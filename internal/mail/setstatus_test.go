package mail

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

// A scripted driver that records the statements SetStatus writes, because what
// has to be asserted is the SQL guard itself: whether the UPDATE that resumes a
// mailbox refuses to match a row the spam policy is holding. The repository
// carries no sqlmock dependency.
type statusScript struct {
	mu sync.Mutex
	// rows answers a read whose query contains the fragment.
	rows map[string][]driver.Value
	// rowsAffected answers an UPDATE whose query contains the fragment.
	rowsAffected map[string]int64
	// execs records every statement in order, with its arguments.
	execs []statusExec
}

type statusExec struct {
	query string
	args  []driver.Value
}

func (s *statusScript) answerQuery(query string) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, values := range s.rows {
		if strings.Contains(query, fragment) {
			return &statusRows{values: values}, nil
		}
	}
	return nil, fmt.Errorf("the test script has no answer for: %s", query)
}

func (s *statusScript) recordExec(query string, args []driver.Value) driver.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execs = append(s.execs, statusExec{query: query, args: args})
	for fragment, affected := range s.rowsAffected {
		if strings.Contains(query, fragment) {
			return statusResult(affected)
		}
	}
	return statusResult(1)
}

// updateStatement returns the one UPDATE against mailboxes, and fails when the
// handler wrote none.
func (s *statusScript) updateStatement(t *testing.T) statusExec {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.execs {
		if strings.Contains(e.query, "UPDATE mailboxes") {
			return e
		}
	}
	t.Fatal("the handler wrote no UPDATE against mailboxes")
	return statusExec{}
}

type statusRows struct {
	values []driver.Value
	done   bool
}

func (r *statusRows) Columns() []string { return make([]string, len(r.values)) }
func (r *statusRows) Close() error      { return nil }
func (r *statusRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

type statusConn struct{ script *statusScript }

func (c statusConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c statusConn) Driver() driver.Driver                        { return statusDriver{} }
func (c statusConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c statusConn) Close() error                                 { return nil }
func (c statusConn) Begin() (driver.Tx, error)                    { return statusTx{}, nil }

func (c statusConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.script.answerQuery(query)
}

func (c statusConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	plain := make([]driver.Value, 0, len(args))
	for _, a := range args {
		plain = append(plain, a.Value)
	}
	return c.script.recordExec(query, plain), nil
}

type statusTx struct{}

func (statusTx) Commit() error   { return nil }
func (statusTx) Rollback() error { return nil }

type statusResult int64

func (statusResult) LastInsertId() (int64, error)   { return 1, nil }
func (r statusResult) RowsAffected() (int64, error) { return int64(r), nil }

type statusDriver struct{}

func (statusDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// clearStatusScript answers every read SetStatus makes for an ordinary mailbox
// that the spam policy is NOT holding.
func clearStatusScript() *statusScript {
	return &statusScript{
		rows: map[string][]driver.Value{
			// Each fragment must match ONE query, or map order (which is random)
			// would answer a different query on every run.
			"FROM domains WHERE id=?":              {"c_tenant"},
			"SELECT email FROM mailboxes":          {"box@example.com"},
			"SELECT spam_suspended_at IS NOT NULL": {false},
		},
		rowsAffected: map[string]int64{},
	}
}

// setStatusRequest builds a request for POST /domains/1/mail/2/status, carrying
// the chi URL params the handler reads and the caller's claims.
func setStatusRequest(role, status string) *http.Request {
	body := strings.NewReader(`{"status":"` + status + `"}`)
	request := httptest.NewRequest(http.MethodPost, "/domains/1/mail/2/status", body)
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "1")
	routeCtx.URLParams.Add("mid", "2")
	ctx := context.WithValue(request.Context(), chi.RouteCtxKey, routeCtx)
	if role != "" {
		ctx = auth.WithClaims(ctx, &auth.Claims{UserID: 1, Username: "actor", Role: role})
	}
	return request.WithContext(ctx)
}

func runSetStatus(t *testing.T, script *statusScript, role, status string) *httptest.ResponseRecorder {
	t.Helper()
	db := sql.OpenDB(statusConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	recorder := httptest.NewRecorder()
	(&Handlers{DB: db}).SetStatus(recorder, setStatusRequest(role, status))
	return recorder
}

// The spam policy is the panel's only automatic answer to a mailbox that is
// sending abusively. It writes mailboxes.status='suspended' and stamps
// spam_suspended_at; the resume route is mounted under CustomerScope, so the
// account that triggered the containment reached the same UPDATE and cleared
// both the status and the evidence in one statement.
func TestACustomerCannotResumeAMailboxTheSpamPolicySuspended(t *testing.T) {
	script := clearStatusScript()

	runSetStatus(t, script, middleware.RoleUser, "active")

	update := script.updateStatement(t)
	if !strings.Contains(update.query, "spam_suspended_at IS NULL") {
		t.Fatalf("a customer's resume ran without the containment guard:\n%s", update.query)
	}
}

// The guard must not spread to the owner's own switch: a customer may still
// suspend and resume a mailbox the spam policy never touched. That is the same
// UPDATE, and it matches because spam_suspended_at is NULL.
func TestACustomerMaySuspendItsOwnMailbox(t *testing.T) {
	script := clearStatusScript()

	recorder := runSetStatus(t, script, middleware.RoleUser, "suspended")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	update := script.updateStatement(t)
	if strings.Contains(update.query, "spam_suspended_at IS NULL") {
		t.Fatalf("suspending carried the resume guard:\n%s", update.query)
	}
}

// An operator is the party that did not trigger the containment, so the lift is
// theirs to make, and it clears the timestamp deliberately.
func TestAnOperatorMayResumeAContainedMailbox(t *testing.T) {
	for _, role := range []string{middleware.RoleAdmin, middleware.RoleReseller} {
		t.Run(role, func(t *testing.T) {
			script := clearStatusScript()

			recorder := runSetStatus(t, script, role, "active")

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
			}
			update := script.updateStatement(t)
			if strings.Contains(update.query, "spam_suspended_at IS NULL") {
				t.Fatalf("an operator's resume carried the customer's guard:\n%s", update.query)
			}
		})
	}
}

// An operator lifting a containment must be findable later, so it is not audited
// as an ordinary resume.
func TestLiftingAContainmentIsAuditedUnderItsOwnAction(t *testing.T) {
	script := clearStatusScript()

	runSetStatus(t, script, middleware.RoleAdmin, "active")

	script.mu.Lock()
	defer script.mu.Unlock()
	var actions []string
	for _, e := range script.execs {
		if !strings.Contains(e.query, "audit_log") {
			continue
		}
		for _, a := range e.args {
			if text, ok := a.(string); ok {
				actions = append(actions, text)
			}
		}
	}
	if !slices.Contains(actions, "mail.status.spam_resume") {
		t.Fatalf("the audit line recorded %v, want the containment lift named separately", actions)
	}
}

// A customer whose resume matched no row must be told the spam policy is holding
// the mailbox, not that the mailbox does not exist.
func TestAContainedMailboxRefusesTheResumeWithItsReason(t *testing.T) {
	script := clearStatusScript()
	script.rows["SELECT spam_suspended_at IS NOT NULL"] = []driver.Value{true}
	script.rowsAffected["UPDATE mailboxes"] = 0

	recorder := runSetStatus(t, script, middleware.RoleUser, "active")

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
}

// A row the refusal read cannot reach is not evidence that the containment is
// gone, so it must not fall through to a 404 that reads as "nothing to protect".
func TestAnUnreadableRefusalReadFailsClosed(t *testing.T) {
	script := clearStatusScript()
	delete(script.rows, "SELECT spam_suspended_at IS NOT NULL")
	script.rowsAffected["UPDATE mailboxes"] = 0

	recorder := runSetStatus(t, script, middleware.RoleUser, "active")

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusInternalServerError, recorder.Body.String())
	}
}
