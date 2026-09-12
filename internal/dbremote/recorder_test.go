package dbremote

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
)

// A recording driver, as used elsewhere in the repository: there is no sqlmock
// dependency, and what these tests need is which query ran and what it was told.
//
// The answers are modelled as ROWS rather than as "does the lookup succeed",
// so the query text decides the outcome. A recorder that answered regardless of
// the conditions would keep passing if the domain narrowing were dropped from
// the SQL, which is exactly what one of these tests exists to catch.
type statusRecorder struct {
	mu sync.Mutex
	// enabled is panel_settings.db_remote_enabled.
	enabled bool
	// portRules is how many firewall_rules rows target the database port.
	portRules int
	// accounts maps db_user to the domain that owns it.
	accounts map[string]int64
	queries  []string
	// execErr and queryErr fail the statement whose text carries the fragment,
	// so a test can drive the failure branch of one write or one read.
	execErr  map[string]error
	queryErr map[string]error
	// execArgs records what each executed statement was told, keyed by the
	// fragment the test looks for.
	execArgs map[string][]driver.Value
	// hostRow is the db_user and mysql_host a withdrawal looks up. A nil entry
	// means the entry is not there.
	hostRow []driver.Value
}

// failureFor returns the injected error for a statement, if there is one.
func failureFor(table map[string]error, query string) error {
	for fragment, err := range table {
		if strings.Contains(query, fragment) {
			return err
		}
	}
	return nil
}

// execArgsOf returns the arguments of the executed statement carrying the
// fragment, and whether it ran at all.
func (r *statusRecorder) execArgsOf(fragment string) ([]driver.Value, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for recorded, args := range r.execArgs {
		if strings.Contains(recorded, fragment) {
			return args, true
		}
	}
	return nil, false
}

func (r *statusRecorder) saw(fragment string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, query := range r.queries {
		if strings.Contains(query, fragment) {
			return true
		}
	}
	return false
}

var (
	statusStateMu sync.Mutex
	statusState   = map[string]*statusRecorder{}
	statusOnce    sync.Once
)

type statusDriver struct{}

func (statusDriver) Open(name string) (driver.Conn, error) {
	statusStateMu.Lock()
	defer statusStateMu.Unlock()
	recorder, ok := statusState[name]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return &statusConn{recorder: recorder}, nil
}

type statusConn struct{ recorder *statusRecorder }

func (c *statusConn) Prepare(query string) (driver.Stmt, error) {
	c.recorder.mu.Lock()
	c.recorder.queries = append(c.recorder.queries, query)
	c.recorder.mu.Unlock()
	return &statusStmt{recorder: c.recorder, query: query}, nil
}
func (c *statusConn) Close() error              { return nil }
func (c *statusConn) Begin() (driver.Tx, error) { return nil, io.ErrUnexpectedEOF }

type statusStmt struct {
	recorder *statusRecorder
	query    string
}

func (s *statusStmt) Close() error  { return nil }
func (s *statusStmt) NumInput() int { return -1 }
func (s *statusStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.recorder.mu.Lock()
	if s.recorder.execArgs == nil {
		s.recorder.execArgs = map[string][]driver.Value{}
	}
	s.recorder.execArgs[s.query] = args
	s.recorder.mu.Unlock()
	if err := failureFor(s.recorder.execErr, s.query); err != nil {
		return nil, err
	}
	return driver.RowsAffected(1), nil
}

// storedHost answers the lookup a withdrawal makes.
func (s *statusStmt) storedHost() *statusRows {
	columns := []string{"db_user", "mysql_host"}
	if s.recorder.hostRow == nil {
		return &statusRows{columns: columns}
	}
	return &statusRows{columns: columns, values: [][]driver.Value{s.recorder.hostRow}}
}

// account answers the db_accounts lookup as a real table would, so the QUERY
// decides the outcome. The arguments are read by kind rather than by position,
// and the domain is only applied when the query actually narrows by it: a query
// that dropped that condition returns the neighbour's row here exactly as
// MariaDB would.
func (s *statusStmt) account(args []driver.Value) *statusRows {
	columns := []string{"db_name", "db_pass_plain"}
	wantUser, wantDomain := firstOfEachKind(args)
	owner, known := s.recorder.accounts[wantUser]
	scoped := strings.Contains(s.query, "domain_id=?")
	if known && (!scoped || owner == wantDomain) {
		return &statusRows{
			columns: columns,
			values:  [][]driver.Value{{wantUser + "_db", "ZxcvbnmAsdfgh234"}},
		}
	}
	return &statusRows{columns: columns}
}

// firstOfEachKind returns the first string and the first number among the
// arguments.
func firstOfEachKind(args []driver.Value) (string, int64) {
	var text string
	var number int64
	for _, arg := range args {
		switch value := arg.(type) {
		case string:
			if text == "" {
				text = value
			}
		case int64:
			if number == 0 {
				number = value
			}
		}
	}
	return text, number
}

func (s *statusStmt) Query(args []driver.Value) (driver.Rows, error) {
	if err := failureFor(s.recorder.queryErr, s.query); err != nil {
		return nil, err
	}
	switch {
	case strings.Contains(s.query, "COUNT(*) FROM firewall_rules"):
		return &statusRows{columns: []string{"c"}, values: [][]driver.Value{{int64(s.recorder.portRules)}}}, nil
	case strings.Contains(s.query, "db_remote_enabled") && strings.Contains(s.query, "db_remote_last_error"):
		return &statusRows{
			columns: []string{"enabled", "last_error", "applied_at"},
			values:  [][]driver.Value{{int64(boolToInt(s.recorder.enabled)), "", ""}},
		}, nil
	case strings.Contains(s.query, "db_remote_enabled"):
		return &statusRows{columns: []string{"enabled"}, values: [][]driver.Value{{int64(boolToInt(s.recorder.enabled))}}}, nil
	case strings.Contains(s.query, "SELECT db_user, mysql_host"):
		return s.storedHost(), nil
	case strings.Contains(s.query, "FROM db_accounts"):
		return s.account(args), nil
	case strings.Contains(s.query, "FROM db_remote_hosts"):
		return &statusRows{columns: []string{
			"id", "domain_id", "domain_name", "db_user", "host_cidr", "label", "created_at",
		}}, nil
	}
	return &statusRows{columns: []string{"x"}}, nil
}

type statusRows struct {
	columns []string
	values  [][]driver.Value
	at      int
}

func (r *statusRows) Columns() []string { return r.columns }
func (r *statusRows) Close() error      { return nil }
func (r *statusRows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

func statusDB(t *testing.T, recorder *statusRecorder) *sql.DB {
	t.Helper()
	statusOnce.Do(func() { sql.Register("dbremote-status", statusDriver{}) })
	if recorder.accounts == nil {
		// One account, owned by domain 1, so a test naming another domain's user
		// exercises the ownership check rather than a missing fixture.
		recorder.accounts = map[string]int64{"c_site_app": 1}
	}
	name := t.Name()
	statusStateMu.Lock()
	statusState[name] = recorder
	statusStateMu.Unlock()
	t.Cleanup(func() {
		statusStateMu.Lock()
		delete(statusState, name)
		statusStateMu.Unlock()
	})
	db, err := sql.Open("dbremote-status", name)
	if err != nil {
		t.Fatalf("open recording database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// withDomainParam puts the {id} route parameter where chi.URLParam reads it.
func withDomainParam(r *http.Request, id string) *http.Request {
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
}

// withHostParam adds the {hid} route parameter a withdrawal reads.
func withHostParam(r *http.Request, hid string) *http.Request {
	ctx, ok := r.Context().Value(chi.RouteCtxKey).(*chi.Context)
	if !ok {
		ctx = chi.NewRouteContext()
	}
	ctx.URLParams.Add("hid", hid)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
}
