package provisioner

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
)

// A recording driver, as used elsewhere in the repository: there is no sqlmock
// dependency, and what these tests need is a `domains` table that answers the
// way MariaDB would.
//
// The rows are filtered by the QUERY TEXT, not by the test's intent, so dropping
// `parent_domain_id IS NULL` or `domain_name<>?` from the SQL changes the answer
// here exactly as it would against a real server. A recorder that answered from
// a fixture regardless of the conditions would keep passing through both of
// those mutations.
type domainRow struct {
	id         int64
	domainName string
	systemUser string
	topLevel   bool
}

type domainsRecorder struct {
	rows []domainRow
	// failWith, when set, is returned instead of any result.
	failWith error
	mu       sync.Mutex
	queries  []string
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
	recorder, ok := domainsState[name]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return &domainsConn{recorder: recorder}, nil
}

type domainsConn struct{ recorder *domainsRecorder }

func (c *domainsConn) Prepare(query string) (driver.Stmt, error) {
	c.recorder.mu.Lock()
	c.recorder.queries = append(c.recorder.queries, query)
	c.recorder.mu.Unlock()
	return &domainsStmt{recorder: c.recorder, query: query}, nil
}
func (c *domainsConn) Close() error              { return nil }
func (c *domainsConn) Begin() (driver.Tx, error) { return nil, io.ErrUnexpectedEOF }

type domainsStmt struct {
	recorder *domainsRecorder
	query    string
}

func (s *domainsStmt) Close() error  { return nil }
func (s *domainsStmt) NumInput() int { return -1 }
func (s *domainsStmt) Exec([]driver.Value) (driver.Result, error) {
	return driver.RowsAffected(0), nil
}

func (s *domainsStmt) Query(args []driver.Value) (driver.Rows, error) {
	if s.recorder.failWith != nil {
		return nil, s.recorder.failWith
	}
	if strings.Contains(s.query, "GROUP BY system_user") {
		return s.grouped(), nil
	}
	var wantUser, exceptName string
	for _, arg := range args {
		if value, ok := arg.(string); ok {
			if wantUser == "" {
				wantUser = value
				continue
			}
			if exceptName == "" {
				exceptName = value
			}
		}
	}
	onlyTopLevel := strings.Contains(s.query, "parent_domain_id IS NULL")
	excepts := strings.Contains(s.query, "domain_name<>?")

	result := &domainsRows{columns: []string{"id"}}
	for _, row := range s.recorder.rows {
		if row.systemUser != wantUser {
			continue
		}
		if onlyTopLevel && !row.topLevel {
			continue
		}
		if excepts && row.domainName == exceptName {
			continue
		}
		result.values = append(result.values, []driver.Value{row.id})
	}
	return result, nil
}

// grouped answers the collision report the way MariaDB's GROUP BY would.
//
// The HAVING is applied only when the QUERY carries it, exactly like the other
// conditions here: a report that dropped it would name every tenant on the
// server as a collision, and a recorder that filtered on its own would keep
// passing through that.
func (s *domainsStmt) grouped() *domainsRows {
	onlyTopLevel := strings.Contains(s.query, "parent_domain_id IS NULL")
	moreThanOne := strings.Contains(s.query, "HAVING COUNT(*) > 1")

	order := []string{}
	names := map[string][]string{}
	for _, row := range s.recorder.rows {
		if row.systemUser == "" || (onlyTopLevel && !row.topLevel) {
			continue
		}
		if _, seen := names[row.systemUser]; !seen {
			order = append(order, row.systemUser)
		}
		names[row.systemUser] = append(names[row.systemUser], row.domainName)
	}
	result := &domainsRows{columns: []string{"system_user", "domain_names"}}
	for _, systemUser := range order {
		if moreThanOne && len(names[systemUser]) < 2 {
			continue
		}
		result.values = append(result.values,
			[]driver.Value{systemUser, strings.Join(names[systemUser], ", ")})
	}
	return result
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

// withDomains points the package database at a recording driver for one test.
func withDomains(t *testing.T, recorder *domainsRecorder) {
	t.Helper()
	domainsOnce.Do(func() { sql.Register("provisioner-domains", domainsDriver{}) })
	name := t.Name()
	domainsStateMu.Lock()
	domainsState[name] = recorder
	domainsStateMu.Unlock()

	db, err := sql.Open("provisioner-domains", name)
	if err != nil {
		t.Fatalf("open recording database: %v", err)
	}
	previous := packageDB
	packageDB = db
	t.Cleanup(func() {
		packageDB = previous
		_ = db.Close()
		domainsStateMu.Lock()
		delete(domainsState, name)
		domainsStateMu.Unlock()
	})
}

// The domain being torn down is not counted as its own sibling, and one that
// shares the system user is. Both halves matter: the first would keep every
// deletion from ever removing a user, the second is the data loss this exists
// to prevent.
func TestASiblingSharingTheSystemUserIsFound(t *testing.T) {
	withDomains(t, &domainsRecorder{rows: []domainRow{
		{id: 1, domainName: "blog.example.com", systemUser: "c_blog_example_com", topLevel: true},
		{id: 2, domainName: "blog-example.com", systemUser: "c_blog_example_com", topLevel: true},
	}})

	siblings, err := OtherTopLevelDomainsUsing("c_blog_example_com", "blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(siblings) != 1 || siblings[0] != 2 {
		t.Fatalf("siblings = %v, want [2]", siblings)
	}

	alone, err := OtherTopLevelDomainsUsing("c_only_example_com", "only.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(alone) != 0 {
		t.Errorf("a domain with no sibling reported %v", alone)
	}
}

// An addon domain carries its parent's system user and is removed with it, so
// counting it would make every parent look shared and no tenant would ever be
// torn down.
func TestAnAddonDomainIsNotASibling(t *testing.T) {
	withDomains(t, &domainsRecorder{rows: []domainRow{
		{id: 1, domainName: "example.com", systemUser: "c_example_com", topLevel: true},
		{id: 2, domainName: "addon.example.net", systemUser: "c_example_com", topLevel: false},
	}})

	siblings, err := OtherTopLevelDomainsUsing("c_example_com", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(siblings) != 0 {
		t.Errorf("the addon domain was counted as a sibling: %v", siblings)
	}
}

// A read that fails is reported. Deprovision turns that into "keep the user",
// which is only safe because the error actually arrives here.
func TestAFailedLookupIsReported(t *testing.T) {
	wanted := errors.New("database is down")
	withDomains(t, &domainsRecorder{failWith: wanted})

	if _, err := OtherTopLevelDomainsUsing("c_example_com", "example.com"); err == nil {
		t.Fatal("a failed read was reported as no siblings")
	}
}

// Without the panel database the question cannot be answered at all, and the
// answer must not default to "nobody else is using it".
func TestAMissingDatabaseIsAnError(t *testing.T) {
	previous := packageDB
	packageDB = nil
	t.Cleanup(func() { packageDB = previous })

	if _, err := OtherTopLevelDomainsUsing("c_example_com", "example.com"); err == nil {
		t.Fatal("a missing database was reported as no siblings")
	}
}

// The report names a collided pair and stays silent otherwise. An operator who
// is never told cannot act on a pair that only a person can separate.
func TestTheCollisionReportOnlySpeaksWhenThereIsACollision(t *testing.T) {
	var written strings.Builder
	previousOutput := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&written)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
	})

	withDomains(t, &domainsRecorder{rows: []domainRow{
		{id: 1, domainName: "blog.example.com", systemUser: "c_blog_example_com", topLevel: true},
		{id: 2, domainName: "blog-example.com", systemUser: "c_blog_example_com", topLevel: true},
		{id: 3, domainName: "alone.example.net", systemUser: "c_alone_example_net", topLevel: true},
		// An addon domain carries its parent's system user. Counting it would
		// report every parent that has one as a collision.
		{id: 4, domainName: "shop.example.org", systemUser: "c_alone_example_net", topLevel: false},
	}})

	ReportSystemUserCollisions()
	report := written.String()
	if !strings.Contains(report, "c_blog_example_com") {
		t.Errorf("the collided pair was not reported:\n%s", report)
	}
	if strings.Contains(report, "c_alone_example_net") {
		t.Errorf("a domain with no sibling was reported:\n%s", report)
	}
}

// The sibling check has to run BEFORE the first thing keyed on the system user,
// which is the nginx vhost path. Deprovision cannot be executed in a test (it
// runs userdel and systemctl), so the ordering is pinned where it is decided.
func TestTheSiblingCheckRunsBeforeAnyHostTeardown(t *testing.T) {
	source, err := os.ReadFile("provisioner.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	start := strings.Index(body, "func Deprovision(domainName, systemUser string) error {")
	if start < 0 {
		t.Fatal("Deprovision was renamed; this test has to follow it")
	}
	body = body[start:]

	check := strings.Index(body, "OtherTopLevelDomainsUsing(systemUser, domainName)")
	firstRemoval := strings.Index(body, `cfgPath := "/etc/nginx/conf.d/dom_"`)
	switch {
	case check < 0:
		t.Fatal("Deprovision no longer asks whether the system user is shared")
	case firstRemoval < 0:
		t.Fatal("the vhost removal moved; this test has to follow it")
	case check > firstRemoval:
		t.Error("the vhost is removed before the sibling check, so a shared tenant loses its vhost")
	}

	// A failed lookup has to keep the user too. Reading the error and then acting
	// on an empty sibling list is the same as never asking.
	if failClosed := strings.Index(body, "if err != nil || len(siblings) > 0 {"); failClosed < 0 || failClosed > firstRemoval {
		t.Error("a failed sibling lookup no longer keeps the system user")
	}
}
