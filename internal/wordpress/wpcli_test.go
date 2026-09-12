package wordpress

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The query fragments the scripted database answers.
const (
	domainLookup   = "SELECT system_user, domain_name, COALESCE(cert_path,'')"
	customerLookup = "SELECT customer_id FROM domains WHERE id=?"
	planLookup     = "SELECT plan_id FROM customers WHERE id=?"
	maxDBLookup    = "SELECT max_db FROM service_plans WHERE id=?"
	dbCountLookup  = "FROM db_accounts a JOIN domains d"
	dbOwnerLookup  = "SELECT COUNT(*) FROM db_accounts WHERE domain_id=? AND db_name=?"
)

// wpCall is one wp-cli invocation, with what went in on its standard input.
type wpCall struct {
	args  []string
	stdin string
}

// wpAnswer is what the recorder hands back for one wp-cli call.
type wpAnswer struct {
	out string
	err error
}

// wpRecorder answers wp-cli calls from a script and keeps what it was asked.
//
// It also remembers the secrets the handler generated, because they arrive on
// standard input and nothing else in the test can know them: the database
// password wp-config.php is asked for afterwards, and the administrator
// password the install verifies afterwards.
type wpRecorder struct {
	mu      sync.Mutex
	calls   []wpCall
	answers map[string]wpAnswer

	dbPass    string
	adminPass string
	userPass  string
}

// wpCallKey names a call by its subcommand. `eval` carries its PHP source as
// the second argument, so the password check gets a name of its own.
func wpCallKey(args []string) string {
	switch {
	case len(args) == 0:
		return ""
	case len(args) == 1:
		return args[0]
	case args[0] == "eval" && strings.Contains(args[1], "wp_check_password"):
		return "eval check-password"
	case args[0] == "eval":
		return "eval " + strings.TrimSpace(args[1])
	default:
		return args[0] + " " + args[1]
	}
}

func (rec *wpRecorder) run(stdin string, args []string) ([]byte, error) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.calls = append(rec.calls, wpCall{args: args, stdin: stdin})
	key := wpCallKey(args)
	switch key {
	case "config create":
		rec.dbPass = strings.TrimSpace(stdin)
	case "core install":
		rec.adminPass = strings.TrimSpace(stdin)
	case "user update":
		rec.userPass = strings.TrimSpace(stdin)
	}
	answer, scripted := rec.answers[key]
	if !scripted {
		return rec.defaultAnswer(key, stdin), nil
	}
	return []byte(answer.out), answer.err
}

// defaultAnswer is what an unscripted call returns: the reads that verify a
// secret answer with the value the handler just supplied, so the default path
// is the one where wp-cli did its job.
func (rec *wpRecorder) defaultAnswer(key, stdin string) []byte {
	switch key {
	case "config get":
		return []byte(rec.dbPass)
	case "eval check-password":
		lines := strings.Split(stdin, "\n")
		if len(lines) > 1 && (lines[1] == rec.adminPass || lines[1] == rec.userPass) {
			return []byte("OK")
		}
		return []byte("MISMATCH")
	default:
		return nil
	}
}

// argvFor returns the arguments of the first call to a subcommand.
func (rec *wpRecorder) argvFor(key string) []string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, call := range rec.calls {
		if wpCallKey(call.args) == key {
			return call.args
		}
	}
	return nil
}

// keys names every call in order.
func (rec *wpRecorder) keys() []string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	seen := make([]string, 0, len(rec.calls))
	for _, call := range rec.calls {
		seen = append(seen, wpCallKey(call.args))
	}
	return seen
}

// recordWP routes both wp-cli seams into one recorder for the length of a test.
func recordWP(t *testing.T, answers map[string]wpAnswer) *wpRecorder {
	t.Helper()
	if answers == nil {
		answers = map[string]wpAnswer{}
	}
	rec := &wpRecorder{answers: answers}
	setForTest(t, &wpInput, func(_ time.Duration, _, stdin string, args ...string) ([]byte, error) {
		return rec.run(stdin, args)
	})
	setForTest(t, &wpOutput, func(_ context.Context, _ string, args ...string) ([]byte, error) {
		return rec.run("", args)
	})
	return rec
}

// hostRecorder keeps the host commands and MySQL calls an install makes.
type hostRecorder struct {
	mu        sync.Mutex
	commands  [][]string
	created   []string
	dropped   []string
	removed   []string
	createErr error
	removeErr error
}

func (h *hostRecorder) argvOf(name string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, argv := range h.commands {
		if argv[0] == name {
			return argv
		}
	}
	return nil
}

// recordHost replaces the host seams so no test runs chown, mysql or a
// deletion.
func recordHost(t *testing.T) *hostRecorder {
	t.Helper()
	host := &hostRecorder{}
	setForTest(t, &wpCommand, func(name string, args ...string) *exec.Cmd {
		host.mu.Lock()
		host.commands = append(host.commands, append([]string{name}, args...))
		host.mu.Unlock()
		return exec.Command("true")
	})
	setForTest(t, &createMySQLDB, func(_ *sql.DB, _ int64, dbName, _, _ string) error {
		host.mu.Lock()
		host.created = append(host.created, dbName)
		host.mu.Unlock()
		return host.createErr
	})
	setForTest(t, &dropMySQLDB, func(_ *sql.DB, dbName, dbUser string) error {
		host.mu.Lock()
		host.dropped = append(host.dropped, dbName+"/"+dbUser)
		host.mu.Unlock()
		return nil
	})
	setForTest(t, &removeInstall, func(_, absolutePath, _ string) error {
		host.mu.Lock()
		host.removed = append(host.removed, absolutePath)
		host.mu.Unlock()
		return host.removeErr
	})
	return host
}

// tenantRoot points the package at a temporary home and returns the document
// root of the c_test tenant.
func tenantRoot(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	setForTest(t, &tenantHomeRoot, home)
	root := filepath.Join(home, "c_test", "public_html")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("create the document root: %v", err)
	}
	return root
}

// wpRequest builds a request whose chi route carries the domain id 1.
func wpRequest(method, target, body string) *http.Request {
	return requestWithID(method, target, body, "1")
}

// domainScript answers h.domain with one tenant.
func domainScript(systemUser string) *sqlScript {
	s := newScript()
	s.rows[domainLookup] = [][]driver.Value{{systemUser, "example.com", ""}}
	return s
}

// adminDomain adds the rows that make the domain plan-free, so the database
// quota gate passes without a plan lookup.
func adminDomain(s *sqlScript) *sqlScript {
	s.rows[customerLookup] = [][]driver.Value{{nil}}
	return s
}

func assertStatus(t *testing.T, recorder *httptest.ResponseRecorder, status int, fragment string) {
	t.Helper()
	if recorder.Code != status {
		t.Errorf("status = %d, want %d (body %s)", recorder.Code, status, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), fragment) {
		t.Errorf("body = %s, want it to hold %q", recorder.Body.String(), fragment)
	}
}

// wpConfig writes the file resolveDirectory looks for.
func wpConfig(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wp-config.php"), []byte(body), 0o600); err != nil {
		t.Fatalf("write wp-config.php: %v", err)
	}
}

// equalStrings reports whether two argument lists are the same.
func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// assertArgvHolds checks that every named argument is present, in the order
// given.
func assertArgvHolds(t *testing.T, argv []string, want ...string) {
	t.Helper()
	at := 0
	for _, arg := range argv {
		if at < len(want) && arg == want[at] {
			at++
		}
	}
	if at != len(want) {
		t.Errorf("argv = %v, want it to hold %v in order", argv, want)
	}
}
