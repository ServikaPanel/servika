package apps

import (
	"database/sql"
	"database/sql/driver"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"servika/internal/appruntime"
	"servika/internal/secret"
)

// A fake host for the three functions that publish an application: the tenant
// home, the unit directory, the environment and log directories, the installed
// interpreter, systemd and the vhost render are all replaced by seams so the
// whole publish path can be measured on a laptop.

const testUser = "c_example"

// setForTest replaces a package-level seam for one test.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

// appHost is the recorded host a test acts on.
type appHost struct {
	home    string
	units   string
	envDir  string
	logDir  string
	calls   []string
	failing map[string]bool // systemctl verb -> the command fails
	show    string          // what `systemctl show` prints
	render  error           // what the vhost render answers
}

// fakeHost points every host seam at a directory of its own.
func fakeHost(t *testing.T) *appHost {
	t.Helper()
	host := &appHost{
		home:    t.TempDir(),
		units:   t.TempDir(),
		envDir:  t.TempDir(),
		logDir:  t.TempDir(),
		failing: map[string]bool{},
	}
	initSecret(t)
	setForTest(t, &tenantHomeRoot, host.home)
	setForTest(t, &unitDir, host.units)
	t.Setenv("SERVIKA_APP_ENV_DIR", host.envDir)
	t.Setenv("SERVIKA_APP_LOG_DIR", host.logDir)

	interpreter := filepath.Join(t.TempDir(), "node")
	if err := os.WriteFile(interpreter, []byte("#!/bin/sh\n"), 0o755); err != nil { // #nosec G306 -- a stand-in interpreter in a temp dir.
		t.Fatalf("write the stand-in interpreter: %v", err)
	}
	setForTest(t, &resolveRuntimePath, func(appruntime.Kind, string) (string, bool) {
		return interpreter, true
	})
	setForTest(t, &runSystemCommand, host.command)
	setForTest(t, &phpSocketFor, func(string, string) (string, error) {
		return "/run/php-fpm/example.sock", nil
	})
	setForTest(t, &applyVhostForDomain, func(*sql.DB, int64, string, string) error { return host.render })

	if err := os.MkdirAll(filepath.Join(host.home, testUser, "api"), 0o755); err != nil {
		t.Fatalf("create the application directory: %v", err)
	}
	return host
}

// command records a systemctl invocation and answers as the test scripted it.
func (h *appHost) command(name string, arguments ...string) *exec.Cmd {
	h.calls = append(h.calls, name+" "+strings.Join(arguments, " "))
	verb := ""
	if len(arguments) > 0 {
		verb = arguments[0]
	}
	switch {
	case h.failing[verb]:
		return exec.Command("/bin/sh", "-c", "echo refused >&2; exit 1")
	case verb == "show":
		return exec.Command("/bin/echo", h.show)
	}
	return exec.Command("/bin/sh", "-c", "exit 0")
}

// ran reports whether a systemctl call carrying fragment was made.
func (h *appHost) ran(fragment string) bool {
	for _, call := range h.calls {
		if strings.Contains(call, fragment) {
			return true
		}
	}
	return false
}

// unitBody returns the installed unit, or "" when none was written.
func (h *appHost) unitBody(t *testing.T, id int64) string {
	t.Helper()
	body, err := os.ReadFile(UnitPath(id)) // #nosec G304 -- a temp directory this test owns.
	if err != nil {
		return ""
	}
	return string(body)
}

// envBody returns the installed environment file, or "" when none was written.
func (h *appHost) envBody(t *testing.T, id int64) string {
	t.Helper()
	body, err := os.ReadFile(EnvPath(id)) // #nosec G304 -- a temp directory this test owns.
	if err != nil {
		return ""
	}
	return string(body)
}

func initSecret(t *testing.T) {
	t.Helper()
	if err := secret.Init([]byte("a-test-key-that-is-long-enough-32")); err != nil {
		t.Fatalf("secret.Init: %v", err)
	}
}

// domainRow scripts the domain lookup and the quota gate, which reads the same
// table. A NULL customer_id is an administrator's domain, which carries no plan
// limit.
func domainRow(script *sqlScript) {
	script.rows["SELECT system_user, COALESCE(php_version,'8.3') FROM domains"] =
		[][]driver.Value{{testUser, "8.3"}}
	script.rows["SELECT customer_id FROM domains"] = [][]driver.Value{{nil}}
}

// scriptAppRow scripts the application read-back in the column order of
// appColumns.
func scriptAppRow(script *sqlScript, enabled int64) {
	script.rows["FROM apps WHERE id=? AND domain_id=?"] = [][]driver.Value{
		{int64(4), int64(7), int64(0), "api", "node", "22", "api", "node server.js", "/api/", int64(30001), enabled},
	}
}

// noEnvironment scripts an application with no stored environment.
func noEnvironment(script *sqlScript) {
	script.rows["SELECT name, value FROM app_env"] = nil
}
