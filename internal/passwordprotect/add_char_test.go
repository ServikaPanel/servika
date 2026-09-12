package passwordprotect

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Add writes a bcrypt hash to disk, hands the file to nginx and re-renders a
// vhost, so nothing reached it before. What matters most is the rollback: a
// half-finished add must not leave a hash readable by every tenant, and must
// not leave a vhost naming a file that is gone. These tests pin the refusals,
// the argv, the stored row and both rollback paths.

const (
	theSystemUser = "c_test"
	qDomain       = "SELECT system_user"
	qSubdomain    = "FROM subdomains"
	qCount        = "COUNT(*)"
	insRecord     = "INSERT INTO protected_directories"
	delRecord     = "DELETE FROM protected_directories"
)

// ppScript answers the handler's queries and records its statements.
type ppScript struct {
	mu       sync.Mutex
	rows     map[string][][]driver.Value
	queryErr map[string]error
	failExec map[string]error
	execs    []string
	execArgs map[string][]driver.Value
}

func (s *ppScript) answer(query string) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, err := range s.queryErr {
		if strings.Contains(query, fragment) {
			return nil, err
		}
	}
	for fragment, values := range s.rows {
		if strings.Contains(query, fragment) {
			return &ppRows{values: values}, nil
		}
	}
	return nil, errors.New("the test script has no answer for: " + query)
}

func (s *ppScript) record(query string, args []driver.NamedValue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.execs = append(s.execs, query)
	if s.execArgs == nil {
		s.execArgs = map[string][]driver.Value{}
	}
	values := make([]driver.Value, 0, len(args))
	for _, a := range args {
		values = append(values, a.Value)
	}
	s.execArgs[query] = values
}

func (s *ppScript) argsOf(fragment string) []driver.Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	for query, values := range s.execArgs {
		if strings.Contains(query, fragment) {
			return values
		}
	}
	return nil
}

func (s *ppScript) ran(fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, query := range s.execs {
		if strings.Contains(query, fragment) {
			return true
		}
	}
	return false
}

type ppRows struct {
	values [][]driver.Value
	at     int
}

func (r *ppRows) Columns() []string {
	if len(r.values) == 0 {
		return []string{""}
	}
	return make([]string, len(r.values[0]))
}
func (r *ppRows) Close() error { return nil }
func (r *ppRows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

type ppConn struct{ script *ppScript }

func (c ppConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c ppConn) Driver() driver.Driver                        { return ppDriver{} }
func (c ppConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c ppConn) Close() error                                 { return nil }
func (c ppConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c ppConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.script.answer(query)
}

func (c ppConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.script.record(query, args)
	if err, ok := c.script.execErr(query); ok {
		return nil, err
	}
	return ppResult{}, nil
}

// execErr fails a statement whose text carries the fragment.
func (s *ppScript) execErr(query string) (error, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, err := range s.failExec {
		if strings.Contains(query, fragment) {
			return err, true
		}
	}
	return nil, false
}

type ppResult struct{}

func (ppResult) LastInsertId() (int64, error) { return 1, nil }
func (ppResult) RowsAffected() (int64, error) { return 1, nil }

type ppDriver struct{}

func (ppDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// ownedDomain is the tenant domain the request addresses, with no subdomain and
// no user left on the path after a rollback.
func ownedDomain() *ppScript {
	return &ppScript{
		rows: map[string][][]driver.Value{
			qDomain:    {{theSystemUser, "8.3"}},
			qSubdomain: {{int64(3)}},
			qCount:     {{int64(0)}},
		},
	}
}

// hostCalls answers for the host and records what the endpoint asked it to do.
type hostCalls struct {
	mu         sync.Mutex
	argv       [][]string
	secured    []string
	gidErr     error
	dirErr     error
	fileErr    error
	writeFails bool
	renderErrs []error
	rendered   int
}

func (c *hostCalls) record(name string, args []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.argv = append(c.argv, append([]string{name}, args...))
}

// ranArgv reports whether the recorded calls contain this exact command.
func (c *hostCalls) ranArgv(want ...string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, got := range c.argv {
		if strings.Join(got, " ") == strings.Join(want, " ") {
			return true
		}
	}
	return false
}

func (c *hostCalls) render() error {
	c.rendered++
	if c.rendered <= len(c.renderErrs) {
		return c.renderErrs[c.rendered-1]
	}
	return nil
}

func (c *hostCalls) install(t *testing.T, dir string) {
	t.Helper()
	gidWas, secureWas, runWas := gidOfNginx, secureFile, runCommand
	socketWas, applyWas, subWas, dirWas := phpSocketFor, applyVhost, reRenderSub, htpasswdDir
	t.Cleanup(func() {
		gidOfNginx, secureFile, runCommand = gidWas, secureWas, runWas
		phpSocketFor, applyVhost, reRenderSub, htpasswdDir = socketWas, applyWas, subWas, dirWas
	})
	htpasswdDir = dir
	gidOfNginx = func() (int, error) { return 42, c.gidErr }
	secureFile = func(path string, _, _ int, _ os.FileMode) error {
		c.secured = append(c.secured, path)
		if path == htpasswdDir {
			return c.dirErr
		}
		return c.fileErr
	}
	runCommand = c.command
	phpSocketFor = func(string, string) (string, error) { return "/run/php-fpm/test.sock", nil }
	applyVhost = func(*sql.DB, int64, string, string) error { return c.render() }
	reRenderSub = func(*sql.DB, int64) error { return c.render() }
}

// command stands in for htpasswd, restorecon and nginx. The create run writes
// the file, because the rollback is defined by whether this request made it.
func (c *hostCalls) command(name string, args ...string) *exec.Cmd {
	c.record(name, args)
	if name == "htpasswd" && strings.Contains(args[0], "c") {
		// #nosec G306 -- test-owned temp file.
		_ = os.WriteFile(args[1], []byte("alice:$2y$05$hash\n"), 0o600)
	}
	if c.writeFails && name == "htpasswd" && args[0] != "-D" {
		return exec.Command("/usr/bin/false")
	}
	return exec.Command("/usr/bin/true")
}

func addRequest(body, sid string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/domains/7/password-protection", strings.NewReader(body))
	routes := chi.NewRouteContext()
	routes.URLParams.Add("id", "7")
	if sid != "" {
		routes.URLParams.Add("sid", sid)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routes))
}

func addUser(t *testing.T, script *ppScript, calls *hostCalls, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	calls.install(t, t.TempDir())
	db := sql.OpenDB(ppConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	h := &Handlers{DB: db}
	w := httptest.NewRecorder()
	h.Add(w, addRequest(body, ""))
	var decoded map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &decoded)
	return w, decoded
}

const goodBody = `{"path":"/private","username":"alice","password":"SecretPass1"}`

func TestAddRefusesADomainItCannotRead(t *testing.T) {
	script := ownedDomain()
	script.queryErr = map[string]error{qDomain: errors.New("no rows")}
	w, decoded := addUser(t, script, &hostCalls{}, goodBody)
	if w.Code != http.StatusNotFound || decoded["error"] != "domain not found" {
		t.Fatalf("status = %d error = %v, want 404 domain not found", w.Code, decoded["error"])
	}
}

// The file name and the vhost are built from the system user, so a row that is
// not a tenant is refused before anything is written.
func TestAddRefusesADomainWithoutATenantUser(t *testing.T) {
	script := ownedDomain()
	script.rows[qDomain] = [][]driver.Value{{"root", "8.3"}}
	calls := &hostCalls{}
	w, decoded := addUser(t, script, calls, goodBody)
	if w.Code != http.StatusBadRequest || decoded["error"] != "invalid user" {
		t.Fatalf("status = %d error = %v, want 400 invalid user", w.Code, decoded["error"])
	}
	if len(calls.argv) != 0 {
		t.Fatalf("the host was touched for a refused domain: %v", calls.argv)
	}
}

func TestAddRefusesASubdomainOfAnotherDomain(t *testing.T) {
	script := ownedDomain()
	script.queryErr = map[string]error{qSubdomain: errors.New("no rows")}
	calls := &hostCalls{}
	calls.install(t, t.TempDir())
	db := sql.OpenDB(ppConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	h := &Handlers{DB: db}
	w := httptest.NewRecorder()
	h.Add(w, addRequest(goodBody, "9"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if len(calls.argv) != 0 {
		t.Fatalf("the host was touched for a refused subdomain: %v", calls.argv)
	}
}

func TestAddRefusesABodyItCannotRead(t *testing.T) {
	w, decoded := addUser(t, ownedDomain(), &hostCalls{}, "{")
	if w.Code != http.StatusBadRequest || decoded["error"] != "invalid request body" {
		t.Fatalf("status = %d error = %v, want 400 invalid request body", w.Code, decoded["error"])
	}
}

// The path becomes part of a file name and of a location block, so a traversal
// or a character outside the pattern is refused.
func TestAddRefusesAPathItCannotUse(t *testing.T) {
	for _, path := range []string{"/../etc", "/with space", "/a?b=1"} {
		body := `{"path":"` + path + `","username":"alice","password":"SecretPass1"}`
		w, decoded := addUser(t, ownedDomain(), &hostCalls{}, body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%q: status = %d, want 400", path, w.Code)
		}
		if decoded["error"] != "invalid path (example: /private)" {
			t.Errorf("%q: error = %v", path, decoded["error"])
		}
	}
}

func TestAddRefusesAUsernameOutsideThePattern(t *testing.T) {
	body := `{"path":"/private","username":"bad user","password":"SecretPass1"}`
	w, decoded := addUser(t, ownedDomain(), &hostCalls{}, body)
	if w.Code != http.StatusBadRequest || decoded["error"] != "invalid username" {
		t.Fatalf("status = %d error = %v, want 400 invalid username", w.Code, decoded["error"])
	}
}

func TestAddRefusesAPasswordOutsideTheLengthBounds(t *testing.T) {
	for _, password := range []string{"abc", strings.Repeat("a", 129)} {
		body := `{"path":"/private","username":"alice","password":"` + password + `"}`
		w, decoded := addUser(t, ownedDomain(), &hostCalls{}, body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%d characters: status = %d, want 400", len(password), w.Code)
		}
		if decoded["error"] != "password must contain 4 to 128 characters" {
			t.Errorf("%d characters: error = %v", len(password), decoded["error"])
		}
	}
}

// htpasswd reads one line from stdin, so a line break would store a truncated
// password and lock the customer out of the directory they just protected.
func TestAddRefusesAPasswordCarryingALineBreak(t *testing.T) {
	for _, password := range []string{"Secret\nPass1", "Secret\rPass1", "Secret\x00Pass1"} {
		body, _ := json.Marshal(map[string]string{"path": "/private", "username": "alice", "password": password})
		w, decoded := addUser(t, ownedDomain(), &hostCalls{}, string(body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%q: status = %d, want 400", password, w.Code)
		}
		if decoded["error"] != "password cannot contain line breaks" {
			t.Errorf("%q: error = %v", password, decoded["error"])
		}
	}
}

// A host with no nginx account is refused before the hash is written, or the
// file would be left behind with nothing able to close it.
func TestAddRefusesAHostWithNoNginxAccount(t *testing.T) {
	calls := &hostCalls{gidErr: errors.New("unknown user nginx")}
	w, decoded := addUser(t, ownedDomain(), calls, goodBody)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if decoded["error"] != "could not resolve the nginx account" {
		t.Fatalf("error = %v", decoded["error"])
	}
	if len(calls.argv) != 0 {
		t.Fatalf("the hash was written without an nginx account: %v", calls.argv)
	}
}

func TestAddWritesTheHashAndStoresTheRecord(t *testing.T) {
	script, calls := ownedDomain(), &hostCalls{}
	w, decoded := addUser(t, script, calls, goodBody)
	if w.Code != http.StatusOK || decoded["ok"] != true {
		t.Fatalf("status = %d body = %v, want 200 ok", w.Code, decoded)
	}
	file := filepath.Join(htpasswdDir, "d7_private")
	if !calls.ranArgv("htpasswd", "-ciB", file, "alice") {
		t.Fatalf("the create run is missing from %v", calls.argv)
	}
	if !calls.ranArgv("restorecon", file) {
		t.Fatalf("the SELinux context was not applied: %v", calls.argv)
	}
	args := script.argsOf(insRecord)
	want := []driver.Value{int64(7), int64(0), "/private", "alice", file}
	if len(args) != len(want) {
		t.Fatalf("stored %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("stored argument %d = %v, want %v", i, args[i], want[i])
		}
	}
	if calls.rendered != 1 {
		t.Fatalf("rendered %d times, want 1", calls.rendered)
	}
}

// An existing file gains a user instead of being recreated, or the users
// already protecting the directory would be truncated away.
func TestAddAppendsToAnExistingFile(t *testing.T) {
	calls := &hostCalls{}
	dir := t.TempDir()
	calls.install(t, dir)
	file := filepath.Join(dir, "d7_private")
	if err := os.WriteFile(file, []byte("bob:$2y$05$hash\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	db := sql.OpenDB(ppConn{script: ownedDomain()})
	t.Cleanup(func() { _ = db.Close() })
	h := &Handlers{DB: db}
	w := httptest.NewRecorder()
	h.Add(w, addRequest(goodBody, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !calls.ranArgv("htpasswd", "-iB", file, "alice") {
		t.Fatalf("the append run is missing from %v", calls.argv)
	}
}

func TestAddFailsWhenTheHashCannotBeWritten(t *testing.T) {
	script := ownedDomain()
	calls := &hostCalls{writeFails: true}
	w, decoded := addUser(t, script, calls, goodBody)
	if w.Code != http.StatusInternalServerError || decoded["error"] != "operation failed" {
		t.Fatalf("status = %d error = %v, want 500 operation failed", w.Code, decoded["error"])
	}
	if script.ran(insRecord) {
		t.Fatal("a record was stored for a hash that was not written")
	}
}

// The file already holds the hash, so a securing failure must not leave it
// behind: every account on the host could read it while the screen reported
// success.
func TestAddRemovesTheFileItCreatedWhenItCannotBeSecured(t *testing.T) {
	script := ownedDomain()
	calls := &hostCalls{fileErr: errors.New("operation not permitted")}
	w, decoded := addUser(t, script, calls, goodBody)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if decoded["error"] != "could not secure the password file" {
		t.Fatalf("error = %v", decoded["error"])
	}
	file := filepath.Join(htpasswdDir, "d7_private")
	if !calls.ranArgv("htpasswd", "-D", file, "alice") {
		t.Fatalf("the user was not deleted: %v", calls.argv)
	}
	if _, err := os.Stat(file); err == nil {
		t.Fatal("the hash was left on disk after the file could not be secured")
	}
	if script.ran(insRecord) {
		t.Fatal("a record was stored for a file that was removed")
	}
}

func TestAddFailsWhenTheDirectoryCannotBeSecured(t *testing.T) {
	calls := &hostCalls{dirErr: errors.New("operation not permitted")}
	w, decoded := addUser(t, ownedDomain(), calls, goodBody)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if decoded["error"] != "could not secure the htpasswd directory" {
		t.Fatalf("error = %v", decoded["error"])
	}
	if len(calls.argv) != 0 {
		t.Fatalf("the hash was written into an open directory: %v", calls.argv)
	}
}

func TestAddFailsWhenTheDirectoryCannotBeCreated(t *testing.T) {
	calls := &hostCalls{}
	dir := t.TempDir()
	calls.install(t, dir)
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	htpasswdDir = filepath.Join(blocker, "htpasswd")

	db := sql.OpenDB(ppConn{script: ownedDomain()})
	t.Cleanup(func() { _ = db.Close() })
	h := &Handlers{DB: db}
	w := httptest.NewRecorder()
	h.Add(w, addRequest(goodBody, ""))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	var decoded map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &decoded)
	if decoded["error"] != "could not create htpasswd directory" {
		t.Fatalf("error = %v", decoded["error"])
	}
}

func TestAddFailsWhenTheRecordCannotBeStored(t *testing.T) {
	script := ownedDomain()
	script.failExec = map[string]error{insRecord: errors.New("connection refused")}
	calls := &hostCalls{}
	w, decoded := addUser(t, script, calls, goodBody)
	if w.Code != http.StatusInternalServerError || decoded["error"] != "could not add record" {
		t.Fatalf("status = %d error = %v, want 500 could not add record", w.Code, decoded["error"])
	}
	if calls.rendered != 0 {
		t.Fatal("the vhost was rendered for a record that was not stored")
	}
}

// A vhost that fails validation would leave the site down, so the record and
// the hash are rolled back and the previous vhost is rendered again.
func TestAddRollsBackWhenTheVhostFailsToRender(t *testing.T) {
	script := ownedDomain()
	calls := &hostCalls{renderErrs: []error{errors.New("nginx -t failed")}}
	w, decoded := addUser(t, script, calls, goodBody)
	if w.Code != http.StatusInternalServerError || decoded["error"] != "operation failed" {
		t.Fatalf("status = %d error = %v, want 500 operation failed", w.Code, decoded["error"])
	}
	if !script.ran(delRecord) {
		t.Fatalf("the record was left behind: %v", script.execs)
	}
	file := filepath.Join(htpasswdDir, "d7_private")
	if !calls.ranArgv("htpasswd", "-D", file, "alice") {
		t.Fatalf("the user was not deleted: %v", calls.argv)
	}
	if _, err := os.Stat(file); err == nil {
		t.Fatal("the hash was left on disk after the rollback")
	}
	if calls.rendered != 2 {
		t.Fatalf("rendered %d times, want the failed render and the restore", calls.rendered)
	}
}

// The file stays when another user still protects the path, or the rollback of
// one add would unprotect the directory for everyone else.
func TestAddKeepsTheFileWhenAnotherUserRemains(t *testing.T) {
	script := ownedDomain()
	script.rows[qCount] = [][]driver.Value{{int64(1)}}
	calls := &hostCalls{renderErrs: []error{errors.New("nginx -t failed")}}
	w, _ := addUser(t, script, calls, goodBody)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if _, err := os.Stat(filepath.Join(htpasswdDir, "d7_private")); err != nil {
		t.Fatalf("the file was removed while another user still protects the path: %v", err)
	}
}
