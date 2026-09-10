package nginxset

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

// A scripted driver, because what has to be asserted is the ARGUMENT the write
// carries: the plan's ceiling must be the stored value whatever the customer
// sent. The repository carries no sqlmock dependency.
type settingsScript struct {
	mu sync.Mutex
	// rows answers a read whose query contains the fragment.
	rows map[string][]driver.Value
	// execs records every statement in order, with its arguments.
	execs []settingsExec
}

type settingsExec struct {
	query string
	args  []driver.Value
}

func (s *settingsScript) answerQuery(query string) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, values := range s.rows {
		if strings.Contains(query, fragment) {
			return &settingsRows{values: values}, nil
		}
	}
	return nil, fmt.Errorf("the test script has no answer for: %s", query)
}

func (s *settingsScript) recordExec(query string, args []driver.Value) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execs = append(s.execs, settingsExec{query: query, args: args})
}

// settingsWrite returns the one INSERT against nginx_settings.
func (s *settingsScript) settingsWrite(t *testing.T) settingsExec {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.execs {
		if strings.Contains(e.query, "INSERT INTO nginx_settings") {
			return e
		}
	}
	t.Fatal("the handler wrote no INSERT against nginx_settings")
	return settingsExec{}
}

// carriesArgument reports whether any bound argument equals want.
func (e settingsExec) carriesArgument(want string) bool {
	for _, a := range e.args {
		if text, ok := a.(string); ok && text == want {
			return true
		}
	}
	return false
}

type settingsRows struct {
	values []driver.Value
	done   bool
}

func (r *settingsRows) Columns() []string { return make([]string, len(r.values)) }
func (r *settingsRows) Close() error      { return nil }
func (r *settingsRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

type settingsConn struct{ script *settingsScript }

func (c settingsConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c settingsConn) Driver() driver.Driver                        { return settingsDriver{} }
func (c settingsConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c settingsConn) Close() error                                 { return nil }
func (c settingsConn) Begin() (driver.Tx, error)                    { return settingsTx{}, nil }

func (c settingsConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.script.answerQuery(query)
}

func (c settingsConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	plain := make([]driver.Value, 0, len(args))
	for _, a := range args {
		plain = append(plain, a.Value)
	}
	c.script.recordExec(query, plain)
	return settingsResult{}, nil
}

type settingsTx struct{}

func (settingsTx) Commit() error   { return nil }
func (settingsTx) Rollback() error { return nil }

type settingsResult struct{}

func (settingsResult) LastInsertId() (int64, error) { return 1, nil }
func (settingsResult) RowsAffected() (int64, error) { return 1, nil }

type settingsDriver struct{}

func (settingsDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// storedScript answers the reads Save makes for a domain whose stored ceiling is
// `ceiling`. The order of columns matches the SELECT in Get.
func storedScript(ceiling string) *settingsScript {
	return &settingsScript{
		rows: map[string][]driver.Value{
			// Each fragment must match ONE query, or map order (which is random)
			// would answer a different query on every run.
			"FROM nginx_settings WHERE domain_id=? AND subdomain_id=?": {
				int64(1), int64(1), int64(1), int64(1), int64(1), int64(1),
				int64(31536000), int64(1), int64(0),
				"add_header X-Test safe;", int64(0), int64(60), int64(1), int64(30),
				ceiling,
			},
			"SELECT domain_name FROM domains":       {"example.com"},
			"php_version, system_user FROM domains": {"8.3", "c_tenant"},
		},
	}
}

func saveRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPut, "/domains/1/nginx-settings", strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "1")
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeCtx))
}

func runSave(t *testing.T, script *settingsScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	db := sql.OpenDB(settingsConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	recorder := httptest.NewRecorder()
	(&Handlers{DB: db}).Save(recorder, saveRequest(body))
	return recorder
}

// The plan's ceiling is a billed tier boundary. It used to live inside
// extra_directives, which this route replaces wholesale with the customer's own
// text, so a customer could raise it to any value in one request.
func TestACustomerCannotRaiseThePlansUploadCeiling(t *testing.T) {
	script := storedScript("8192m")

	runSave(t, script, `{"settings":{"client_max_body":"102400m","extra_directives":""}}`)

	write := script.settingsWrite(t)
	if write.carriesArgument("102400m") {
		t.Fatal("the customer's own ceiling reached the write")
	}
	if !write.carriesArgument("8192m") {
		t.Fatalf("the stored ceiling was not written back; arguments were %v", write.args)
	}
}

// Nor lower it: a value the customer chose is not the plan's, in either
// direction, and an empty one would drop the domain to nginx's own 1m default.
func TestACustomerCannotClearThePlansUploadCeiling(t *testing.T) {
	script := storedScript("8192m")

	runSave(t, script, `{"settings":{"client_max_body":"","extra_directives":""}}`)

	write := script.settingsWrite(t)
	if !write.carriesArgument("8192m") {
		t.Fatalf("the stored ceiling was not written back; arguments were %v", write.args)
	}
}

// The directive itself is refused in the customer's text, so deleting the column
// is not the only way to reach nginx: stating a second one there would let nginx
// prefer the later value.
func TestACustomerCannotStateTheDirectiveInTheirOwnBlock(t *testing.T) {
	script := storedScript("8192m")

	recorder := runSave(t, script, `{"settings":{"extra_directives":"client_max_body_size 10240m;"}}`)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	script.mu.Lock()
	defer script.mu.Unlock()
	for _, e := range script.execs {
		if strings.Contains(e.query, "INSERT INTO nginx_settings") {
			t.Fatal("a refused directive block still reached the write")
		}
	}
}

// A read the save cannot complete is not evidence that the plan states no
// ceiling, so it must not fall through to a write that stores an empty one.
func TestAnUnreadableStoredCeilingBlocksTheSave(t *testing.T) {
	script := storedScript("8192m")
	delete(script.rows, "FROM nginx_settings WHERE domain_id=? AND subdomain_id=?")

	recorder := runSave(t, script, `{"settings":{"extra_directives":""}}`)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusInternalServerError, recorder.Body.String())
	}
	script.mu.Lock()
	defer script.mu.Unlock()
	for _, e := range script.execs {
		if strings.Contains(e.query, "INSERT INTO nginx_settings") {
			t.Fatal("the save wrote a row without knowing the stored ceiling")
		}
	}
}
