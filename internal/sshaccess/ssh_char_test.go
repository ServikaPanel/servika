package sshaccess

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Switching SSH on is a chain of host commands, and the whole point of the
// chain is that it is fail-closed: an account must never be left with a login
// shell and no jail. These pin every step, every rollback and the row that is
// only written when the chain finished.

// domainRow answers the one lookup both handlers make.
type domainRow struct {
	systemUser, domainName string
	done                   bool
}

func (r *domainRow) Columns() []string { return []string{"system_user", "domain_name"} }
func (r *domainRow) Close() error      { return nil }

func (r *domainRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0], dest[1] = r.systemUser, r.domainName
	return nil
}

// domainConn is a database holding one domain, or none.
type domainConn struct {
	systemUser string
	missing    bool
	execErr    error
	execs      [][]driver.Value
}

func (c *domainConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c *domainConn) Driver() driver.Driver                        { return domainDriver{} }
func (c *domainConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c *domainConn) Close() error                                 { return nil }
func (c *domainConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c *domainConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	if c.missing {
		return &domainRow{done: true}, nil
	}
	return &domainRow{systemUser: c.systemUser, domainName: "example.test"}, nil
}

func (c *domainConn) ExecContext(_ context.Context, _ string, args []driver.NamedValue) (driver.Result, error) {
	values := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		values = append(values, arg.Value)
	}
	c.execs = append(c.execs, values)
	if c.execErr != nil {
		return nil, c.execErr
	}
	return domainResult{}, nil
}

type domainResult struct{}

func (domainResult) LastInsertId() (int64, error) { return 1, nil }
func (domainResult) RowsAffected() (int64, error) { return 1, nil }

type domainDriver struct{}

func (domainDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

func domainDB(t *testing.T, conn *domainConn) *sql.DB {
	t.Helper()
	db := sql.OpenDB(conn)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// sshHost records every command the handlers run and answers each from a table.
type sshHost struct {
	calls []string
	// fail marks a command line fragment whose command fails.
	fail map[string]bool
	// prepared counts how often the SSH directory was made ready.
	prepared int
	// prepareErr is what making it ready reports.
	prepareErr error
	writeErr   error
	chmodErr   error
	written    string
	chmodded   bool
	synced     int
	locked     int
}

// fakeSSHHost points every seam at the recorder for one test.
func fakeSSHHost(t *testing.T) *sshHost {
	t.Helper()
	host := &sshHost{fail: map[string]bool{}}

	previousRun, previousDir := runCommand, sshDirReady
	previousWrite, previousChmod := writeAuthorizedKeys, chmodAuthorizedKeys
	previousSync, previousLock := syncSSHPassword, lockSSHPassword
	previousHome := tenantHomeRoot

	runCommand = func(name string, arguments ...string) *exec.Cmd {
		line := strings.TrimSpace(name + " " + strings.Join(arguments, " "))
		host.calls = append(host.calls, line)
		for fragment := range host.fail {
			if strings.Contains(line, fragment) {
				return exec.Command("/bin/sh", "-c", "echo refused >&2; exit 1")
			}
		}
		return exec.Command("/bin/sh", "-c", "exit 0")
	}
	sshDirReady = func(string) error {
		host.prepared++
		return host.prepareErr
	}
	writeAuthorizedKeys = func(_, _ string, body []byte, _ uint32, _ string) error {
		host.written = string(body)
		return host.writeErr
	}
	chmodAuthorizedKeys = func(_, _ string, _ uint32) error {
		host.chmodded = true
		return host.chmodErr
	}
	syncSSHPassword = func(*sql.DB, string) error { host.synced++; return nil }
	lockSSHPassword = func(string) error { host.locked++; return nil }
	tenantHomeRoot = t.TempDir()

	t.Cleanup(func() {
		runCommand, sshDirReady = previousRun, previousDir
		writeAuthorizedKeys, chmodAuthorizedKeys = previousWrite, previousChmod
		syncSSHPassword, lockSSHPassword = previousSync, previousLock
		tenantHomeRoot = previousHome
	})
	return host
}

// ran reports whether a command carrying fragment was run.
func (h *sshHost) ran(fragment string) bool {
	for _, call := range h.calls {
		if strings.Contains(call, fragment) {
			return true
		}
	}
	return false
}

// assertRan fails the test for any command that was not run.
func (h *sshHost) assertRan(t *testing.T, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if !h.ran(fragment) {
			t.Errorf("%q was not run: %v", fragment, h.calls)
		}
	}
}

// sshRequest sends one request for domain 7 to a handler.
func sshRequest(t *testing.T, handler http.HandlerFunc, body string) (int, map[string]any) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/domains/7/ssh", strings.NewReader(body))
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", "7")
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))

	recorder := httptest.NewRecorder()
	handler(recorder, request)

	var decoded map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("the response is not JSON: %s", recorder.Body.String())
	}
	return recorder.Code, decoded
}

func errorOf(body map[string]any) string {
	message, _ := body["error"].(string)
	return message
}

// Switching SSH on is confinement first: the jail and the restricted group are
// what stop a shell from being a shell on the whole server.
func TestEnablingSSHConfinesTheAccountBeforeItIsRecorded(t *testing.T) {
	host := fakeSSHHost(t)
	conn := &domainConn{systemUser: "c_acme"}
	h := &Handlers{DB: domainDB(t, conn)}

	status, body := sshRequest(t, h.Configure, `{"active":true}`)

	if status != http.StatusOK {
		t.Fatalf("status %d, want 200 (%v)", status, body)
	}
	if body["active"] != true || body["shell"] != enabledShell || body["username"] != "c_acme" {
		t.Errorf("body = %v", body)
	}
	host.assertRan(t,
		"usermod -s "+enabledShell+" c_acme",
		"groupadd -f servika-ssh",
		"setup c_acme",
		"gpasswd -a c_acme servika-ssh")
	if host.prepared != 1 || host.synced != 1 {
		t.Errorf("prepared %d times, synced %d times", host.prepared, host.synced)
	}
	if len(conn.execs) != 1 || conn.execs[0][0] != int64(1) || conn.execs[0][1] != int64(7) {
		t.Errorf("the recorded row = %v, want ssh_access=1 on domain 7", conn.execs)
	}
}

// Switching it off is the reverse, and the password is locked so the account
// cannot be reached with the one the FTP login shares.
func TestDisablingSSHRemovesTheJailAndLocksThePassword(t *testing.T) {
	host := fakeSSHHost(t)
	conn := &domainConn{systemUser: "c_acme"}
	h := &Handlers{DB: domainDB(t, conn)}

	status, body := sshRequest(t, h.Configure, `{"active":false}`)

	if status != http.StatusOK {
		t.Fatalf("status %d, want 200 (%v)", status, body)
	}
	if body["active"] != false || body["shell"] != disabledShell {
		t.Errorf("body = %v", body)
	}
	host.assertRan(t,
		"usermod -s "+disabledShell+" c_acme",
		"gpasswd -d c_acme servika-ssh",
		"teardown c_acme")
	if host.locked != 1 || host.synced != 0 || host.prepared != 0 {
		t.Errorf("locked %d, synced %d, prepared %d", host.locked, host.synced, host.prepared)
	}
	if len(conn.execs) != 1 || conn.execs[0][0] != int64(0) {
		t.Errorf("the recorded row = %v, want ssh_access=0", conn.execs)
	}
}

// FAIL-CLOSED: confinement that cannot be established takes the shell back and
// records nothing, so SSH is never left on and unconfined.
func TestConfinementThatFailsTakesTheShellBack(t *testing.T) {
	for _, tc := range []struct {
		name, failing, message string
		tornDown               bool
	}{
		{
			name: "the jail cannot be set up", failing: "setup c_acme",
			message: "SSH jail could not be configured",
		},
		{
			name: "the account cannot join the group", failing: "gpasswd -a",
			message: "SSH access group could not be configured", tornDown: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := fakeSSHHost(t)
			host.fail[tc.failing] = true
			conn := &domainConn{systemUser: "c_acme"}
			h := &Handlers{DB: domainDB(t, conn)}

			status, body := sshRequest(t, h.Configure, `{"active":true}`)

			if status != http.StatusInternalServerError {
				t.Fatalf("status %d, want 500 (%v)", status, body)
			}
			if errorOf(body) != tc.message {
				t.Errorf("message %q, want %q", errorOf(body), tc.message)
			}
			if !host.ran("usermod -s " + disabledShell + " c_acme") {
				t.Errorf("the shell was left enabled: %v", host.calls)
			}
			if host.ran("teardown c_acme") != tc.tornDown {
				t.Errorf("teardown ran = %v, want %v: %v", !tc.tornDown, tc.tornDown, host.calls)
			}
			if len(conn.execs) != 0 {
				t.Errorf("ssh_access was recorded anyway: %v", conn.execs)
			}
		})
	}
}

// A directory or a password that could not be prepared is logged and the change
// goes on: the key endpoint refuses the same directory on its own, and a shell
// without a synchronised password is still a shell the operator asked for.
func TestAPrepareFailureDoesNotStopTheChange(t *testing.T) {
	host := fakeSSHHost(t)
	host.prepareErr = errors.New("no such directory")
	conn := &domainConn{systemUser: "c_acme"}
	h := &Handlers{DB: domainDB(t, conn)}

	status, _ := sshRequest(t, h.Configure, `{"active":true}`)

	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	if len(conn.execs) != 1 {
		t.Errorf("the change was not recorded: %v", conn.execs)
	}
}

// configureCase is one request the shell endpoint turns down.
type configureCase struct {
	name, body, systemUser string
	missing                bool
	failing                string
	execErr                error
	status                 int
	message                string
}

func configureRefusals() []configureCase {
	return []configureCase{
		{
			name: "the domain does not exist", body: `{"active":true}`, missing: true,
			status: http.StatusNotFound, message: "domain not found",
		},
		{
			name: "the account is not one this panel made", body: `{"active":true}`,
			systemUser: "root",
			status:     http.StatusBadRequest, message: "invalid system user",
		},
		{
			name: "the body is not JSON", body: "{", systemUser: "c_acme",
			status: http.StatusBadRequest, message: "invalid request body",
		},
		{
			name: "the shell cannot be changed", body: `{"active":true}`, systemUser: "c_acme",
			failing: "usermod",
			status:  http.StatusInternalServerError, message: "operation failed",
		},
		{
			name: "the change cannot be recorded", body: `{"active":true}`, systemUser: "c_acme",
			execErr: errors.New("the table is gone"),
			status:  http.StatusInternalServerError, message: "operation failed",
		},
	}
}

func TestTheShellEndpointRefusesWhatItCannotDo(t *testing.T) {
	for _, tc := range configureRefusals() {
		t.Run(tc.name, func(t *testing.T) {
			host := fakeSSHHost(t)
			if tc.failing != "" {
				host.fail[tc.failing] = true
			}
			conn := &domainConn{systemUser: tc.systemUser, missing: tc.missing, execErr: tc.execErr}
			h := &Handlers{DB: domainDB(t, conn)}

			status, body := sshRequest(t, h.Configure, tc.body)

			if status != tc.status {
				t.Errorf("status %d, want %d (%v)", status, tc.status, body)
			}
			if errorOf(body) != tc.message {
				t.Errorf("message %q, want %q", errorOf(body), tc.message)
			}
		})
	}
}

// A key file is written whole, with a trailing newline, and an empty body
// clears the file rather than refusing it.
func TestSavingAKeyWritesTheWholeFile(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		hasKey           bool
	}{
		{
			name: "one key", body: `{"key":"ssh-ed25519 AAAA user@host"}`,
			want: "ssh-ed25519 AAAA user@host\n", hasKey: true,
		},
		{
			name: "a comment and two keys",
			body: `{"key":"# work\nssh-rsa AAAA a@b\necdsa-sha2-nistp256 BBBB c@d"}`,
			want: "# work\nssh-rsa AAAA a@b\necdsa-sha2-nistp256 BBBB c@d\n", hasKey: true,
		},
		{name: "an empty body clears every key", body: `{"key":"   "}`, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := fakeSSHHost(t)
			h := &Handlers{DB: domainDB(t, &domainConn{systemUser: "c_acme"})}

			status, body := sshRequest(t, h.SaveKey, tc.body)

			if status != http.StatusOK {
				t.Fatalf("status %d, want 200 (%v)", status, body)
			}
			if body["has_key"] != tc.hasKey {
				t.Errorf("has_key = %v, want %v", body["has_key"], tc.hasKey)
			}
			if host.written != tc.want {
				t.Errorf("wrote %q, want %q", host.written, tc.want)
			}
			if !host.chmodded {
				t.Error("the mode was not pinned after the write")
			}
		})
	}
}

// keyCase is one request the key endpoint turns down.
type keyCase struct {
	name, body, systemUser string
	missing                bool
	prepareErr, writeErr   error
	chmodErr               error
	status                 int
	message                string
}

func keyRefusals() []keyCase {
	return []keyCase{
		{
			name: "the domain does not exist", body: `{"key":"ssh-ed25519 AAAA"}`, missing: true,
			status: http.StatusNotFound, message: "domain not found",
		},
		{
			name: "the account is not one this panel made", body: `{"key":"ssh-ed25519 AAAA"}`,
			systemUser: "root",
			status:     http.StatusBadRequest, message: "invalid system user",
		},
		{
			name: "the body is not JSON", body: "{", systemUser: "c_acme",
			status: http.StatusBadRequest, message: "invalid request body",
		},
		{
			name: "a line is not a key", body: `{"key":"ssh-rsa AAAA\nrm -rf /"}`, systemUser: "c_acme",
			status:  http.StatusBadRequest,
			message: "invalid SSH key: every line must start with ssh-, ecdsa-, or sk-",
		},
		{
			name: "the directory cannot be prepared", body: `{"key":"ssh-ed25519 AAAA"}`,
			systemUser: "c_acme", prepareErr: errors.New("refused"),
			status: http.StatusInternalServerError, message: "operation failed",
		},
		{
			name: "the file cannot be written", body: `{"key":"ssh-ed25519 AAAA"}`,
			systemUser: "c_acme", writeErr: errors.New("refused"),
			status: http.StatusInternalServerError, message: "operation failed",
		},
		{
			name: "the mode cannot be pinned", body: `{"key":"ssh-ed25519 AAAA"}`,
			systemUser: "c_acme", chmodErr: errors.New("refused"),
			status: http.StatusInternalServerError, message: "operation failed",
		},
	}
}

func TestTheKeyEndpointRefusesWhatItCannotDo(t *testing.T) {
	for _, tc := range keyRefusals() {
		t.Run(tc.name, func(t *testing.T) {
			host := fakeSSHHost(t)
			host.prepareErr, host.writeErr, host.chmodErr = tc.prepareErr, tc.writeErr, tc.chmodErr
			h := &Handlers{DB: domainDB(t, &domainConn{systemUser: tc.systemUser, missing: tc.missing})}

			status, body := sshRequest(t, h.SaveKey, tc.body)

			if status != tc.status {
				t.Errorf("status %d, want %d (%v)", status, tc.status, body)
			}
			if errorOf(body) != tc.message {
				t.Errorf("message %q, want %q", errorOf(body), tc.message)
			}
		})
	}
}

// The screen reads the shell off the host rather than off the row, so an
// account changed outside the panel is reported as it actually is.
func TestTheScreenReadsTheShellFromTheHost(t *testing.T) {
	host := fakeSSHHost(t)
	previous := runCommand
	runCommand = func(name string, arguments ...string) *exec.Cmd {
		host.calls = append(host.calls, name+" "+strings.Join(arguments, " "))
		return exec.Command("/bin/echo", "c_acme:x:1001:1001::/home/c_acme:"+enabledShell)
	}
	t.Cleanup(func() { runCommand = previous })
	h := &Handlers{DB: domainDB(t, &domainConn{systemUser: "c_acme"}), IPv4: "203.0.113.5"}

	status, body := sshRequest(t, h.Show, "")

	if status != http.StatusOK {
		t.Fatalf("status %d, want 200 (%v)", status, body)
	}
	if body["active"] != true || body["shell"] != enabledShell ||
		body["username"] != "c_acme" || body["ssh_host"] != "203.0.113.5" {
		t.Errorf("body = %v", body)
	}
	if !host.ran("getent passwd c_acme") {
		t.Errorf("the shell was not read from the host: %v", host.calls)
	}
}

// A domain that is not there is a 404 rather than an empty screen.
func TestTheScreenRefusesADomainThatIsNotThere(t *testing.T) {
	fakeSSHHost(t)
	h := &Handlers{DB: domainDB(t, &domainConn{missing: true})}

	status, body := sshRequest(t, h.Show, "")

	if status != http.StatusNotFound || errorOf(body) != "domain not found" {
		t.Errorf("status %d, body %v", status, body)
	}
}
