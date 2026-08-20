package sitesecurity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"
)

// A recording driver, as used elsewhere in the repository: there is no sqlmock
// dependency, and what these tests need is which statement ran and what it was
// told. The answers are modelled as ROWS so the query text decides the outcome;
// a recorder that answered regardless of the conditions would keep passing if
// the scope narrowing were dropped from the SQL, which is what one of these
// tests exists to catch.
type appRecorder struct {
	mu sync.Mutex
	// inventory is what security_apps holds, one row per entry.
	inventory [][]driver.Value
	// unscanned is what the domains query answers with.
	unscanned []string
	// breakAfter makes the inventory result set fail after that many rows, the
	// way a connection dropped mid-read does.
	breakAfter int
	statements []string
	args       [][]driver.Value
}

func (r *appRecorder) matching(fragment string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, statement := range r.statements {
		if strings.Contains(statement, fragment) {
			out = append(out, statement)
		}
	}
	return out
}

func (r *appRecorder) argsFor(fragment string) []driver.Value {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, statement := range r.statements {
		if strings.Contains(statement, fragment) {
			return r.args[i]
		}
	}
	return nil
}

var (
	appStateMu sync.Mutex
	appState   = map[string]*appRecorder{}
	appOnce    sync.Once
)

type appDriver struct{}

func (appDriver) Open(name string) (driver.Conn, error) {
	appStateMu.Lock()
	defer appStateMu.Unlock()
	recorder, ok := appState[name]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return &appConn{recorder: recorder}, nil
}

type appConn struct{ recorder *appRecorder }

func (c *appConn) Prepare(query string) (driver.Stmt, error) {
	return &appStmt{recorder: c.recorder, query: query}, nil
}
func (c *appConn) Close() error              { return nil }
func (c *appConn) Begin() (driver.Tx, error) { return nil, io.ErrUnexpectedEOF }

type appStmt struct {
	recorder *appRecorder
	query    string
}

func (s *appStmt) Close() error  { return nil }
func (s *appStmt) NumInput() int { return -1 }

func (s *appStmt) record(args []driver.Value) {
	s.recorder.mu.Lock()
	s.recorder.statements = append(s.recorder.statements, s.query)
	s.recorder.args = append(s.recorder.args, args)
	s.recorder.mu.Unlock()
}

func (s *appStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.record(args)
	return driver.RowsAffected(1), nil
}

func (s *appStmt) Query(args []driver.Value) (driver.Rows, error) {
	s.record(args)
	switch {
	case strings.Contains(s.query, "FROM security_apps a JOIN domains d"):
		return &appRows{
			columns: []string{"domain_id", "domain_name", "app_type", "install_path",
				"app_version", "package_count", "finding_count", "last_scanned"},
			values:     s.recorder.inventory,
			breakAfter: s.recorder.breakAfter,
		}, nil
	case strings.Contains(s.query, "SELECT d.domain_name FROM domains d"):
		values := make([][]driver.Value, 0, len(s.recorder.unscanned))
		for _, name := range s.recorder.unscanned {
			values = append(values, []driver.Value{name})
		}
		return &appRows{columns: []string{"domain_name"}, values: values}, nil
	}
	return &appRows{columns: []string{"x"}}, nil
}

// errReadCutShort is what a connection dropped mid-result-set looks like: rows
// arrive, then the read stops. It is NOT io.EOF, which would read as a complete
// short list.
var errReadCutShort = errors.New("connection lost while reading")

type appRows struct {
	columns    []string
	values     [][]driver.Value
	breakAfter int
	at         int
}

func (r *appRows) Columns() []string { return r.columns }
func (r *appRows) Close() error      { return nil }
func (r *appRows) Next(dest []driver.Value) error {
	if r.breakAfter > 0 && r.at >= r.breakAfter {
		return errReadCutShort
	}
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

func appDB(t *testing.T, recorder *appRecorder) *sql.DB {
	t.Helper()
	appOnce.Do(func() { sql.Register("sitesecurity-apps", appDriver{}) })
	name := t.Name()
	appStateMu.Lock()
	appState[name] = recorder
	appStateMu.Unlock()
	t.Cleanup(func() {
		appStateMu.Lock()
		delete(appState, name)
		appStateMu.Unlock()
	})
	db, err := sql.Open("sitesecurity-apps", name)
	if err != nil {
		t.Fatalf("open recording database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// A clean installation must still be written, because that row is the whole
// point: without it "everything is clean" and "nothing was scanned" draw the
// same empty screen.
func TestAnInstallationWithNoFindingIsStillRecorded(t *testing.T) {
	recorder := &appRecorder{}
	collector := &Collector{DB: appDB(t, recorder)}

	err := collector.recordInventory(context.Background(), 7, []Inventory{
		{AppType: AppWordPress, InstallPath: "/", Version: "6.5.2", Packages: 24, Findings: 0},
	}, true)
	if err != nil {
		t.Fatalf("recordInventory: %v", err)
	}

	inserts := recorder.matching("INSERT INTO security_apps")
	if len(inserts) != 1 {
		t.Fatalf("INSERT statements = %d, want 1; a clean installation was not recorded", len(inserts))
	}
	args := recorder.argsFor("INSERT INTO security_apps")
	if len(args) != 6 || args[0] != int64(7) || args[1] != AppWordPress || args[2] != "/" {
		t.Fatalf("insert arguments = %v, want the domain, type and path of the clean installation", args)
	}
	if args[5] != int64(0) {
		t.Errorf("finding_count = %v, want 0 written rather than the row skipped", args[5])
	}
}

// The prune must name the installations that survive, and it must not run at
// all after a pass that reported an error.
func TestTheStalePruneOnlyRunsAfterACompletePass(t *testing.T) {
	apps := []Inventory{
		{AppType: AppWordPress, InstallPath: "/", Version: "6.5.2", Packages: 24},
		{AppType: AppNodeJS, InstallPath: "/app", Packages: 310},
	}

	t.Run("complete", func(t *testing.T) {
		recorder := &appRecorder{}
		collector := &Collector{DB: appDB(t, recorder)}
		if err := collector.recordInventory(context.Background(), 7, apps, true); err != nil {
			t.Fatalf("recordInventory: %v", err)
		}
		deletes := recorder.matching("DELETE FROM security_apps")
		if len(deletes) != 1 {
			t.Fatalf("DELETE statements = %d, want 1", len(deletes))
		}
		if !strings.Contains(deletes[0], "NOT IN ((?,?),(?,?))") {
			t.Errorf("delete = %q, want the two surviving installations named", deletes[0])
		}
		args := recorder.argsFor("DELETE FROM security_apps")
		want := []driver.Value{int64(7), AppWordPress, "/", AppNodeJS, "/app"}
		if len(args) != len(want) {
			t.Fatalf("delete arguments = %v, want %v", args, want)
		}
		for i := range want {
			if args[i] != want[i] {
				t.Fatalf("delete arguments = %v, want %v", args, want)
			}
		}
	})

	t.Run("incomplete", func(t *testing.T) {
		recorder := &appRecorder{}
		collector := &Collector{DB: appDB(t, recorder)}
		if err := collector.recordInventory(context.Background(), 7, apps, false); err != nil {
			t.Fatalf("recordInventory: %v", err)
		}
		if deletes := recorder.matching("DELETE FROM security_apps"); len(deletes) != 0 {
			t.Fatalf("a pass that reported an error pruned anyway: %v", deletes)
		}
		if inserts := recorder.matching("INSERT INTO security_apps"); len(inserts) != 2 {
			t.Errorf("INSERT statements = %d, want 2; what WAS inspected must still be recorded", len(inserts))
		}
	})

	t.Run("nothing found", func(t *testing.T) {
		recorder := &appRecorder{}
		collector := &Collector{DB: appDB(t, recorder)}
		if err := collector.recordInventory(context.Background(), 7, nil, true); err != nil {
			t.Fatalf("recordInventory: %v", err)
		}
		deletes := recorder.matching("DELETE FROM security_apps")
		if len(deletes) != 1 {
			t.Fatalf("DELETE statements = %d, want 1; a domain whose last application was removed keeps a stale row", len(deletes))
		}
		if strings.Contains(deletes[0], "NOT IN") {
			t.Errorf("delete = %q, want no exclusion list when nothing survives", deletes[0])
		}
	})
}

// The path written and the path the prune protects must be the SAME string.
// Truncating them separately lets the delete remove the row the insert above it
// has just written, and the domain then reads as never scanned.
func TestALongPathIsTruncatedOnceForBothStatements(t *testing.T) {
	long := "/" + strings.Repeat("a", 600)
	recorder := &appRecorder{}
	collector := &Collector{DB: appDB(t, recorder)}
	if err := collector.recordInventory(context.Background(), 7,
		[]Inventory{{AppType: AppWordPress, InstallPath: long}}, true); err != nil {
		t.Fatalf("recordInventory: %v", err)
	}

	inserted := recorder.argsFor("INSERT INTO security_apps")[2]
	pruned := recorder.argsFor("DELETE FROM security_apps")[2]
	if inserted != pruned {
		t.Fatalf("insert wrote %q but the prune protects %q", inserted, pruned)
	}
	if len(inserted.(string)) != 512 {
		t.Errorf("stored path length = %d, want it bounded to the column at 512", len(inserted.(string)))
	}
}

func requestAs(role string, userID int64) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/admin/site-security/apps", nil)
	return r.WithContext(auth.WithClaims(r.Context(),
		&auth.Claims{UserID: userID, Username: "t", Role: role}))
}

// BOTH queries must be narrowed. Narrowing only the inventory leaves the
// unscanned list naming every domain on the server, so a reseller reads their
// neighbours' domain names off a screen built to reassure them about their own.
func TestBothHalvesOfTheAnswerAreNarrowedToTheCaller(t *testing.T) {
	recorder := &appRecorder{}
	handlers := &Handlers{DB: appDB(t, recorder)}

	handlers.Apps(httptest.NewRecorder(), requestAs(middleware.RoleReseller, 5))

	for _, fragment := range []string{
		"FROM security_apps a JOIN domains d",
		"SELECT d.domain_name FROM domains d",
	} {
		statements := recorder.matching(fragment)
		if len(statements) != 1 {
			t.Fatalf("%q ran %d times, want 1", fragment, len(statements))
		}
		if !strings.Contains(statements[0], "sc.owner_user_id = ?") {
			t.Errorf("%q is NOT narrowed to the caller: %s", fragment, statements[0])
		}
		args := recorder.argsFor(fragment)
		if len(args) != 1 || args[0] != int64(5) {
			t.Errorf("%q was given %v, want the caller's user id bound", fragment, args)
		}
	}
}

// An administrator has no narrowing, so the second query must still be a valid
// statement: ScopeSQL answers with an empty fragment, and the handler has to
// open the WHERE itself rather than emit two of them or none.
func TestAnAdministratorGetsOneWellFormedWhereClause(t *testing.T) {
	recorder := &appRecorder{unscanned: []string{"example.com"}}
	response := httptest.NewRecorder()
	handlers := &Handlers{DB: appDB(t, recorder)}

	handlers.Apps(response, requestAs(middleware.RoleAdmin, 1))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	statement := recorder.matching("SELECT d.domain_name FROM domains d")[0]
	if strings.Count(statement, "WHERE") != 2 {
		// One for the statement itself and one inside the NOT EXISTS subquery.
		t.Fatalf("statement has %d WHERE keywords, want exactly 2: %s",
			strings.Count(statement, "WHERE"), statement)
	}
	if strings.Contains(statement, "WHERE  AND") || strings.Contains(statement, "WHEREd") {
		t.Errorf("the clause is malformed for an unnarrowed caller: %s", statement)
	}

	var body AppsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", response.Body.String(), err)
	}
	if len(body.Unscanned) != 1 || body.Unscanned[0] != "example.com" {
		t.Errorf("unscanned = %v, want the one domain that has never been inspected", body.Unscanned)
	}
}

// A read that stops half way must be reported, not answered as a short list.
// "Fewer installations than expected" is exactly the reading this screen exists
// to prevent, so a truncated answer is worse here than an error.
func TestAReadCutShortIsReportedRatherThanAnsweredAsAShortList(t *testing.T) {
	recorder := &appRecorder{
		inventory: [][]driver.Value{
			{int64(1), "example.com", AppWordPress, "/", "6.5.2", int64(24), int64(0), "2026-08-20 10:00"},
			{int64(2), "other.example", AppNodeJS, "/app", "", int64(310), int64(2), "2026-08-20 10:01"},
		},
		breakAfter: 1,
	}
	response := httptest.NewRecorder()
	handlers := &Handlers{DB: appDB(t, recorder)}

	handlers.Apps(response, requestAs(middleware.RoleAdmin, 1))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; the handler answered with the rows it managed to read", response.Code)
	}
}
