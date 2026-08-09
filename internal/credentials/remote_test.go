package credentials

import (
	"database/sql"
	"database/sql/driver"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"servika/internal/secret"
)

// A recording driver, as used elsewhere in the repository: there is no sqlmock
// dependency, and what matters here is only which hosts the panel believes a
// user answers on.
type remoteRecorder struct {
	mu sync.Mutex
	// hosts is what db_remote_hosts holds for every user.
	hosts []string
	// names is what db_accounts holds.
	names []string
	// storedPass is the db_pass_plain value db_accounts returns.
	storedPass string
	// failOn makes the matching query return a driver error, so a test can prove
	// that a read failure REFUSES rather than quietly skipping the remote hosts.
	failOn     string
	statements []string
}

var (
	remoteStateMu sync.Mutex
	remoteState   = map[string]*remoteRecorder{}
)

type remoteDriver struct{}

func (remoteDriver) Open(name string) (driver.Conn, error) {
	remoteStateMu.Lock()
	defer remoteStateMu.Unlock()
	recorder, ok := remoteState[name]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return &remoteConn{recorder: recorder}, nil
}

type remoteConn struct{ recorder *remoteRecorder }

func (c *remoteConn) Prepare(query string) (driver.Stmt, error) {
	c.recorder.mu.Lock()
	c.recorder.statements = append(c.recorder.statements, query)
	c.recorder.mu.Unlock()
	return &remoteStmt{recorder: c.recorder, query: query}, nil
}
func (c *remoteConn) Close() error              { return nil }
func (c *remoteConn) Begin() (driver.Tx, error) { return nil, io.ErrUnexpectedEOF }

type remoteStmt struct {
	recorder *remoteRecorder
	query    string
}

func (s *remoteStmt) Close() error  { return nil }
func (s *remoteStmt) NumInput() int { return -1 }
func (s *remoteStmt) Exec([]driver.Value) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}
func (s *remoteStmt) Query([]driver.Value) (driver.Rows, error) {
	if s.recorder.failOn != "" && strings.Contains(s.query, s.recorder.failOn) {
		return nil, io.ErrUnexpectedEOF
	}
	switch {
	case strings.Contains(s.query, "db_remote_hosts"):
		return &remoteRows{column: "mysql_host", values: s.recorder.hosts}, nil
	case strings.Contains(s.query, "db_pass_plain"):
		// Legacy plaintext, which DecryptDBPass passes through unchanged.
		return &remoteRows{column: "db_pass_plain", values: []string{s.recorder.storedPass}}, nil
	case strings.Contains(s.query, "db_accounts"):
		return &remoteRows{column: "db_name", values: s.recorder.names}, nil
	}
	return &remoteRows{column: "x"}, nil
}

type remoteRows struct {
	column string
	values []string
	at     int
}

func (r *remoteRows) Columns() []string { return []string{r.column} }
func (r *remoteRows) Close() error      { return nil }
func (r *remoteRows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	dest[0] = r.values[r.at]
	r.at++
	return nil
}

var remoteDriverOnce sync.Once

func remoteDB(t *testing.T, recorder *remoteRecorder) *sql.DB {
	t.Helper()
	remoteDriverOnce.Do(func() { sql.Register("credremote", remoteDriver{}) })
	name := t.Name()
	remoteStateMu.Lock()
	remoteState[name] = recorder
	remoteStateMu.Unlock()
	t.Cleanup(func() {
		remoteStateMu.Lock()
		delete(remoteState, name)
		remoteStateMu.Unlock()
	})
	db, err := sql.Open("credremote", name)
	if err != nil {
		t.Fatalf("open recording database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// initSecret arms the at-rest encryption the password paths use. Without it a
// password change fails before it ever builds a statement, which would make
// every assertion below vacuous.
func initSecret(t *testing.T) {
	t.Helper()
	if err := secret.Init([]byte(strings.Repeat("k", 32))); err != nil {
		t.Fatalf("secret.Init: %v", err)
	}
}

// The host component of a MariaDB account is a PATTERN, where `%` matches any
// string. A value carrying one would not be a bad row: it would be a grant to
// the whole internet on an account the panel still called restricted.
func TestAWildcardNeverReachesAHostComponent(t *testing.T) {
	for _, host := range []string{
		"%", "_", "10.0.0.%", "10.0.0._", "'", "` OR 1=1", "10.0.0.1 ", "",
		"host name", "10.0.0.1'; DROP USER 'x'@'%'; --",
	} {
		if ValidRemoteHost(host) {
			t.Errorf("ValidRemoteHost(%q) = true", host)
		}
	}
	for _, host := range []string{
		"203.0.113.7", "10.0.0.0/255.255.255.0", "2001:db8::5", "192.0.2.0/255.255.255.128",
	} {
		if !ValidRemoteHost(host) {
			t.Errorf("ValidRemoteHost(%q) = false", host)
		}
	}
}

// A refused host must not reach the client at all, rather than being caught by
// MariaDB after the statement was already built and sent.
func TestARefusedHostNeverReachesTheClient(t *testing.T) {
	initSecret(t)
	_, stdinPath := stubRootSQL(t, 0)
	if err := MySQLGrantRemote("c_site_app", "%", "ZxcvbnmAsdfgh234", []string{"c_site_db"}); err == nil {
		t.Fatal("MySQLGrantRemote accepted a wildcard host")
	}
	if data, err := readIfPresent(stdinPath); err == nil && strings.TrimSpace(data) != "" {
		t.Errorf("statements reached the client anyway: %q", data)
	}
}

func readIfPresent(path string) (string, error) {
	data, err := readFileForTest(path)
	return data, err
}

// Every database the user owns has to be granted to the new remote account.
// MariaDB keeps grants per account, so a remote client would otherwise connect
// successfully and then see nothing.
func TestARemoteAccountIsGrantedEveryDatabaseTheUserOwns(t *testing.T) {
	initSecret(t)
	_, stdinPath := stubRootSQL(t, 0)
	err := MySQLGrantRemote("c_site_app", "203.0.113.7", "ZxcvbnmAsdfgh234",
		[]string{"c_site_shop", "c_site_blog"})
	if err != nil {
		t.Fatalf("MySQLGrantRemote: %v", err)
	}
	stdin := readStub(t, stdinPath)
	for _, want := range []string{
		"CREATE USER IF NOT EXISTS 'c_site_app'@'203.0.113.7'",
		"ALTER USER 'c_site_app'@'203.0.113.7'",
		"GRANT ALL PRIVILEGES ON `c_site_shop`.* TO 'c_site_app'@'203.0.113.7'",
		"GRANT ALL PRIVILEGES ON `c_site_blog`.* TO 'c_site_app'@'203.0.113.7'",
	} {
		if !strings.Contains(stdin, want) {
			t.Errorf("missing %q in:\n%s", want, stdin)
		}
	}
}

// A password change applies to ONE account. The remote accounts are separate
// accounts with their own passwords, so missing them leaves a working credential
// the customer believes they have just rotated.
func TestAPasswordChangeReachesEveryHostTheUserAnswersOn(t *testing.T) {
	initSecret(t)
	_, stdinPath := stubRootSQL(t, 0)
	db := remoteDB(t, &remoteRecorder{hosts: []string{"203.0.113.7", "10.0.0.0/255.255.255.0"}})

	if err := MySQLChangePassword(db, "c_site_app", "ZxcvbnmAsdfgh234"); err != nil {
		t.Fatalf("MySQLChangePassword: %v", err)
	}
	stdin := readStub(t, stdinPath)
	for _, want := range []string{
		"ALTER USER 'c_site_app'@'localhost'",
		"ALTER USER 'c_site_app'@'203.0.113.7'",
		"ALTER USER 'c_site_app'@'10.0.0.0/255.255.255.0'",
	} {
		if !strings.Contains(stdin, want) {
			t.Errorf("missing %q in:\n%s", want, stdin)
		}
	}
	if got := strings.Count(stdin, "ALTER USER"); got != 3 {
		t.Errorf("ALTER USER appears %d times, want 3", got)
	}
}

// A read failure must REFUSE the change. Skipping the remote hosts silently is
// exactly the outcome the rotation was meant to prevent.
func TestAnUnreadableHostListRefusesThePasswordChange(t *testing.T) {
	initSecret(t)
	stubRootSQL(t, 0)
	db := remoteDB(t, &remoteRecorder{failOn: "db_remote_hosts"})

	if err := MySQLChangePassword(db, "c_site_app", "ZxcvbnmAsdfgh234"); err == nil {
		t.Fatal("MySQLChangePassword succeeded while the remote host list was unreadable")
	}
}

// A database attached to an existing user has to be granted to that user's
// remote accounts too, or it is invisible from outside.
func TestANewDatabaseIsGrantedToTheRemoteAccountsToo(t *testing.T) {
	initSecret(t)
	_, stdinPath := stubRootSQL(t, 0)
	db := remoteDB(t, &remoteRecorder{hosts: []string{"203.0.113.7"}, storedPass: "ZxcvbnmAsdfgh234"})

	// The stored password read is a plaintext legacy value, which DecryptDBPass
	// passes through unchanged.
	if err := MySQLCreateDBForUser(db, 1, "c_site_new", "c_site_app"); err != nil {
		t.Fatalf("MySQLCreateDBForUser: %v", err)
	}
	stdin := readStub(t, stdinPath)
	for _, want := range []string{
		"GRANT ALL PRIVILEGES ON `c_site_new`.* TO 'c_site_app'@'localhost'",
		"GRANT ALL PRIVILEGES ON `c_site_new`.* TO 'c_site_app'@'203.0.113.7'",
	} {
		if !strings.Contains(stdin, want) {
			t.Errorf("missing %q in:\n%s", want, stdin)
		}
	}
}

// Dropping the user has to drop every host it answers on. The panel row would be
// removed by the domain's cascade, but a cascade cannot drop a MariaDB account:
// the credential would outlive the record of it and still authenticate.
func TestDroppingAUserRemovesEveryRemoteAccount(t *testing.T) {
	initSecret(t)
	_, stdinPath := stubRootSQL(t, 0)
	db := remoteDB(t, &remoteRecorder{hosts: []string{"203.0.113.7", "198.51.100.0/255.255.255.0"}})

	if err := MySQLDropDB(db, "c_site_db", "c_site_app"); err != nil {
		t.Fatalf("MySQLDropDB: %v", err)
	}
	stdin := readStub(t, stdinPath)
	for _, want := range []string{
		"DROP USER IF EXISTS 'c_site_app'@'localhost'",
		"DROP USER IF EXISTS 'c_site_app'@'203.0.113.7'",
		"DROP USER IF EXISTS 'c_site_app'@'198.51.100.0/255.255.255.0'",
	} {
		if !strings.Contains(stdin, want) {
			t.Errorf("missing %q in:\n%s", want, stdin)
		}
	}
}

// A host that somehow got into the table in an unusable shape must stop the
// operation, not be interpolated into a statement.
func TestAStoredHostIsValidatedBeforeItIsInterpolated(t *testing.T) {
	initSecret(t)
	stubRootSQL(t, 0)
	db := remoteDB(t, &remoteRecorder{hosts: []string{"%"}})

	if err := MySQLChangePassword(db, "c_site_app", "ZxcvbnmAsdfgh234"); err == nil {
		t.Fatal("a stored wildcard host was interpolated into a statement")
	}
}

// readFileForTest reads a stub capture that may not exist, so a test can assert
// "nothing was written" without failing on the absence itself.
func readFileForTest(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- test-owned path under t.TempDir().
	if err != nil {
		return "", err
	}
	return string(data), nil
}
