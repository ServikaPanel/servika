package sitesecurity

import (
	"database/sql"
	"database/sql/driver"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"
)

// deriveStatus is the whole badge logic, and each state has to be reachable and
// distinct. The two that matter most are the ones the CLAUDE.md invariant is
// about: "clean" (an app was inspected and had no finding) must never read the
// same as "pending" (nothing has ever been scanned), and "no_app" (a sweep
// finished and found no app) is a THIRD thing again.
func TestDeriveStatus(t *testing.T) {
	scanningSet := map[int64]bool{7: true}
	cases := []struct {
		name         string
		running      bool
		scanning     map[int64]bool
		domainID     int64
		hasApp       bool
		findingCount int
		everScanned  bool
		want         string
	}{
		{"whole-server sweep marks every domain scanning", true, map[int64]bool{}, 7, false, 0, true, "scanning"},
		{"a single-domain scan marks only that domain", true, scanningSet, 7, true, 3, true, "scanning"},
		{"another domain during a single-domain scan is not scanning", true, scanningSet, 9, true, 0, true, "clean"},
		{"an app with findings is open", false, nil, 7, true, 2, true, "open"},
		{"an app with no finding is clean", false, nil, 7, true, 0, true, "clean"},
		{"no app after a completed sweep is no_app", false, nil, 7, false, 0, true, "no_app"},
		{"no app and no sweep ever is pending", false, nil, 7, false, 0, false, "pending"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := deriveStatus(c.running, c.scanning, c.domainID, c.hasApp, c.findingCount, c.everScanned)
			if got != c.want {
				t.Fatalf("deriveStatus = %q, want %q", got, c.want)
			}
		})
	}
}

// scanning must WIN over a stored open count: a domain being rescanned reads
// "scanning" even while its last findings are still on the row.
func TestDeriveStatusScanningBeatsAStoredCount(t *testing.T) {
	if got := deriveStatus(true, map[int64]bool{7: true}, 7, true, 5, true); got != "scanning" {
		t.Fatalf("a domain being scanned read %q, want scanning", got)
	}
}

// The domain-driven list is narrowed by ScopeSQL: a reseller's request must
// carry their own id into the query args, or they would read every domain on the
// server. The everScanned probe runs too.
func TestDomainsIsNarrowedToTheCaller(t *testing.T) {
	recorder := &domainsRecorder{ever: true}
	handlers := NewHandlers(domainsDB(t, recorder))

	handlers.Domains(httptest.NewRecorder(), domainsRequest(middleware.RoleReseller, 42))

	stmt := recorder.matching("LEFT JOIN security_apps a ON a.domain_id = d.id")
	if stmt == "" {
		t.Fatal("the domain-driven query never ran")
	}
	if !strings.Contains(stmt, "EXISTS") {
		t.Fatalf("a reseller's query was not scoped: %q", stmt)
	}
	if args := recorder.argsFor("LEFT JOIN security_apps"); !slices.Contains(args, driver.Value(int64(42))) {
		t.Fatalf("the reseller's own id was not bound into the query: %v", args)
	}
	if recorder.matching("last_success IS NOT NULL") == "" {
		t.Fatal("the everScanned probe never ran")
	}
}

// An admin gets one well-formed WHERE, not a dangling "WHERE  AND".
func TestDomainsAdminHasOneWellFormedWhere(t *testing.T) {
	recorder := &domainsRecorder{}
	handlers := NewHandlers(domainsDB(t, recorder))

	handlers.Domains(httptest.NewRecorder(), domainsRequest(middleware.RoleAdmin, 1))

	stmt := recorder.matching("LEFT JOIN security_apps a ON a.domain_id = d.id")
	if !strings.Contains(stmt, " WHERE d.parent_domain_id IS NULL") {
		t.Fatalf("the admin query is not well formed: %q", stmt)
	}
	if strings.Contains(stmt, "WHERE  AND") || strings.Contains(stmt, "WHERE  d") {
		t.Fatalf("the admin query has a malformed WHERE: %q", stmt)
	}
}

// The admin findings list takes an optional domain_id, which the per-domain
// detail page uses. It is ADDED to the scope, so the value is bound and the
// scope condition still applies.
func TestListDomainIDFilterIsBoundAndScoped(t *testing.T) {
	recorder := &domainsRecorder{}
	handlers := NewHandlers(domainsDB(t, recorder))

	r := httptest.NewRequest(http.MethodGet, "/admin/site-security?domain_id=7", nil)
	r = r.WithContext(auth.WithClaims(r.Context(),
		&auth.Claims{UserID: 42, Username: "t", Role: middleware.RoleReseller}))
	handlers.List(httptest.NewRecorder(), r)

	stmt := recorder.matching("FROM security_findings f JOIN domains d")
	if !strings.Contains(stmt, "f.domain_id = ?") {
		t.Fatalf("domain_id was not applied to the list query: %q", stmt)
	}
	args := recorder.argsFor("FROM security_findings f JOIN domains d")
	if !slices.Contains(args, driver.Value(int64(7))) || !slices.Contains(args, driver.Value(int64(42))) {
		t.Fatalf("the query must bind both the scope id and the domain filter: %v", args)
	}
}

// --- a small recording driver, self-contained for the domain queries ---

type domainsRecorder struct {
	mu         sync.Mutex
	ever       bool
	statements []string
	args       [][]driver.Value
}

func (r *domainsRecorder) matching(fragment string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.statements {
		if strings.Contains(s, fragment) {
			return s
		}
	}
	return ""
}

func (r *domainsRecorder) argsFor(fragment string) []driver.Value {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, s := range r.statements {
		if strings.Contains(s, fragment) {
			return r.args[i]
		}
	}
	return nil
}

var (
	domainsStateMu sync.Mutex
	domainsState   = map[string]*domainsRecorder{}
	domainsOnce    sync.Once
)

type domainsDriver struct{}

func (domainsDriver) Open(name string) (driver.Conn, error) {
	domainsStateMu.Lock()
	defer domainsStateMu.Unlock()
	rec, ok := domainsState[name]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return &domainsConn{rec: rec}, nil
}

type domainsConn struct{ rec *domainsRecorder }

func (c *domainsConn) Prepare(query string) (driver.Stmt, error) {
	return &domainsStmt{rec: c.rec, query: query}, nil
}
func (c *domainsConn) Close() error              { return nil }
func (c *domainsConn) Begin() (driver.Tx, error) { return nil, io.ErrUnexpectedEOF }

type domainsStmt struct {
	rec   *domainsRecorder
	query string
}

func (s *domainsStmt) Close() error  { return nil }
func (s *domainsStmt) NumInput() int { return -1 }

func (s *domainsStmt) record(args []driver.Value) {
	s.rec.mu.Lock()
	s.rec.statements = append(s.rec.statements, s.query)
	s.rec.args = append(s.rec.args, args)
	s.rec.mu.Unlock()
}

func (s *domainsStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.record(args)
	return driver.RowsAffected(1), nil
}

func (s *domainsStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.record(args)
	if strings.Contains(s.query, "last_success IS NOT NULL") {
		return &domainsRows{columns: []string{"ever"}, values: [][]driver.Value{{s.rec.ever}}}, nil
	}
	return &domainsRows{columns: []string{"x"}}, nil
}

type domainsRows struct {
	columns []string
	values  [][]driver.Value
	at      int
}

func (r *domainsRows) Columns() []string { return r.columns }
func (r *domainsRows) Close() error      { return nil }
func (r *domainsRows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

func domainsDB(t *testing.T, rec *domainsRecorder) *sql.DB {
	t.Helper()
	domainsOnce.Do(func() { sql.Register("sitesecurity-domains", domainsDriver{}) })
	name := t.Name()
	domainsStateMu.Lock()
	domainsState[name] = rec
	domainsStateMu.Unlock()
	t.Cleanup(func() {
		domainsStateMu.Lock()
		delete(domainsState, name)
		domainsStateMu.Unlock()
	})
	db, err := sql.Open("sitesecurity-domains", name)
	if err != nil {
		t.Fatalf("open recording database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func domainsRequest(role string, userID int64) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/admin/site-security/domains", nil)
	return r.WithContext(auth.WithClaims(r.Context(),
		&auth.Claims{UserID: userID, Username: "t", Role: role}))
}
