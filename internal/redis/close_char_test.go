package redis

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

	"github.com/go-chi/chi/v5"
)

// A scripted driver, as used in internal/domains and internal/mail: no sqlmock
// dependency, and each statement is answered by the fragment it contains.
type closeScript struct {
	mu sync.Mutex
	// siblings is what the top-level sibling count answers.
	siblings int64
	// countErr fails the sibling lookup.
	countErr bool
	// execErr fails the row delete.
	execErr bool
	// systemUser is what the domain row carries.
	systemUser string
	statements []string
}

func (s *closeScript) record(query string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statements = append(s.statements, query)
}

func (s *closeScript) ran(fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, statement := range s.statements {
		if strings.Contains(statement, fragment) {
			return true
		}
	}
	return false
}

var (
	closeStateMu sync.Mutex
	closeState   = map[string]*closeScript{}
)

type closeDriver struct{}

func (closeDriver) Open(name string) (driver.Conn, error) {
	closeStateMu.Lock()
	defer closeStateMu.Unlock()
	script, ok := closeState[name]
	if !ok {
		return nil, fmt.Errorf("no script registered for %q", name)
	}
	return &closeConn{script: script}, nil
}

func init() { sql.Register("redis_close_script", closeDriver{}) }

type closeConn struct{ script *closeScript }

func (c *closeConn) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("prepare is not used by this test")
}
func (c *closeConn) Close() error { return nil }
func (c *closeConn) Begin() (driver.Tx, error) {
	return nil, fmt.Errorf("transactions are not used here")
}

func (c *closeConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.script.record(query)
	if c.script.execErr {
		return nil, fmt.Errorf("the row delete is refused in this test")
	}
	return driver.RowsAffected(1), nil
}

func (c *closeConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.script.record(query)
	switch {
	case strings.Contains(query, "SELECT system_user FROM domains"):
		return &scriptRows{columns: []string{"system_user"}, values: []driver.Value{c.script.systemUser}}, nil
	case strings.Contains(query, "COUNT(*) FROM domains"):
		if c.script.countErr {
			return nil, fmt.Errorf("the sibling lookup is refused in this test")
		}
		return &scriptRows{columns: []string{"n"}, values: []driver.Value{c.script.siblings}}, nil
	}
	return nil, fmt.Errorf("unexpected query: %s", query)
}

type scriptRows struct {
	columns []string
	values  []driver.Value
	done    bool
}

func (r *scriptRows) Columns() []string { return r.columns }
func (r *scriptRows) Close() error      { return nil }
func (r *scriptRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	copy(dest, r.values)
	r.done = true
	return nil
}

// closeHarness wires the scripted database and records what the host seams were
// asked to do.
func closeHarness(t *testing.T, script *closeScript) (*Handlers, *[]string) {
	t.Helper()
	if script.systemUser == "" {
		script.systemUser = "c_alice"
	}
	name := t.Name()
	closeStateMu.Lock()
	closeState[name] = script
	closeStateMu.Unlock()
	t.Cleanup(func() {
		closeStateMu.Lock()
		delete(closeState, name)
		closeStateMu.Unlock()
	})

	db, err := sql.Open("redis_close_script", name)
	if err != nil {
		t.Fatalf("open the scripted database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var hostCalls []string
	previousRevoke, previousDetach := revokeACL, detachWordPress
	revokeACL = func(systemUser string) error {
		hostCalls = append(hostCalls, "revoke:"+systemUser)
		return nil
	}
	detachWordPress = func(systemUser string) {
		hostCalls = append(hostCalls, "detach:"+systemUser)
	}
	t.Cleanup(func() { revokeACL, detachWordPress = previousRevoke, previousDetach })

	return &Handlers{DB: db}, &hostCalls
}

func closeRequest(id string) *http.Request {
	request := httptest.NewRequest(http.MethodDelete, "/domains/"+id+"/redis", nil)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", id)
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
}

// The Valkey account is named after the system user. A panel upgraded from a
// database that predates the unique constraint, or edited outside the panel, can
// carry two top-level domains on one system user and two different customers.
// One customer switching their own cache off must not revoke the other's
// credentials or rewrite their WordPress configuration.
func TestASharedSystemUserKeepsItsACLAccount(t *testing.T) {
	script := &closeScript{siblings: 1}
	handlers, hostCalls := closeHarness(t, script)

	response := httptest.NewRecorder()
	handlers.Close(response, closeRequest("7"))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (%s)", response.Code, http.StatusOK, response.Body.String())
	}
	if len(*hostCalls) != 0 {
		t.Errorf("the shared host artefacts were touched: %v", *hostCalls)
	}
	if !script.ran("DELETE FROM domain_redis") {
		t.Error("the domain_redis row was not removed")
	}
}

// The ordinary case: the system user belongs to this domain alone, so the
// account and the drop-in go with it. The drop-in is removed FIRST, while the
// credentials still open.
func TestASoleOwnerLosesItsACLAccount(t *testing.T) {
	script := &closeScript{siblings: 0}
	handlers, hostCalls := closeHarness(t, script)

	response := httptest.NewRecorder()
	handlers.Close(response, closeRequest("7"))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (%s)", response.Code, http.StatusOK, response.Body.String())
	}
	want := []string{"detach:c_alice", "revoke:c_alice"}
	if strings.Join(*hostCalls, ",") != strings.Join(want, ",") {
		t.Errorf("host calls = %v, want %v", *hostCalls, want)
	}
	if !script.ran("DELETE FROM domain_redis") {
		t.Error("the domain_redis row was not removed")
	}
}

// A lookup that fails answers nothing about sharing. Keeping a live account
// costs a stale credential; revoking a shared one takes another tenant's cache
// down, so the failure counts as shared.
func TestAFailedSiblingLookupKeepsTheACLAccount(t *testing.T) {
	script := &closeScript{countErr: true}
	handlers, hostCalls := closeHarness(t, script)

	response := httptest.NewRecorder()
	handlers.Close(response, closeRequest("7"))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (%s)", response.Code, http.StatusOK, response.Body.String())
	}
	if len(*hostCalls) != 0 {
		t.Errorf("a failed lookup still revoked the account: %v", *hostCalls)
	}
}

// A row delete that fails must be reported, not answered as a success: the
// account is gone and the row would claim the cache is still on.
func TestAFailedRowDeleteIsReported(t *testing.T) {
	script := &closeScript{execErr: true}
	handlers, _ := closeHarness(t, script)

	response := httptest.NewRecorder()
	handlers.Close(response, closeRequest("7"))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (%s)", response.Code, http.StatusInternalServerError, response.Body.String())
	}
}

// An unusable system user resolves to no tenant at all.
func TestAnUnknownDomainIsRefused(t *testing.T) {
	script := &closeScript{systemUser: "not a system user"}
	handlers, hostCalls := closeHarness(t, script)

	response := httptest.NewRecorder()
	handlers.Close(response, closeRequest("7"))

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
	if len(*hostCalls) != 0 {
		t.Errorf("a refused request still reached the host: %v", *hostCalls)
	}
}
