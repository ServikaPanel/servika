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
func (s *statusStmt) Exec([]driver.Value) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

func (s *statusStmt) Query(args []driver.Value) (driver.Rows, error) {
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
	case strings.Contains(s.query, "FROM db_accounts"):
		// Modelled as a real table would answer, so the QUERY decides the
		// outcome. The arguments are read by kind rather than by position, and
		// the domain is only applied when the query actually narrows by it: a
		// query that dropped that condition returns the neighbour's row here
		// exactly as MariaDB would.
		var wantUser string
		var wantDomain int64
		for _, arg := range args {
			switch value := arg.(type) {
			case string:
				if wantUser == "" {
					wantUser = value
				}
			case int64:
				if wantDomain == 0 {
					wantDomain = value
				}
			}
		}
		owner, known := s.recorder.accounts[wantUser]
		scoped := strings.Contains(s.query, "domain_id=?")
		if known && (!scoped || owner == wantDomain) {
			return &statusRows{
				columns: []string{"db_name", "db_pass_plain"},
				values:  [][]driver.Value{{wantUser + "_db", "ZxcvbnmAsdfgh234"}},
			}, nil
		}
		return &statusRows{columns: []string{"db_name", "db_pass_plain"}}, nil
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
