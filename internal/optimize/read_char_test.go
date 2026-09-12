package optimize

import (
	"context"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Current reads four different places, and a read that fails must be REPORTED
// rather than read as "not set": Compute offers an unset parameter, so a
// swallowed failure turns an unreadable host into a full page of proposals.

const variablesQuery = "information_schema.SYSTEM_VARIABLES"

// hostFiles points the three file seams at a temporary tree. A missing file is
// how a case says the host does not have it.
func hostFiles(t *testing.T, nginx, pool string, sysctls map[string]string) {
	t.Helper()
	dir := t.TempDir()

	if nginx != "" {
		setForTest(t, &nginxPath, writeAt(t, dir, "nginx.conf", nginx))
	} else {
		setForTest(t, &nginxPath, filepath.Join(dir, "absent-nginx.conf"))
	}
	if pool != "" {
		setForTest(t, &fpmPoolPath, writeAt(t, dir, "www.conf", pool))
	} else {
		setForTest(t, &fpmPoolPath, filepath.Join(dir, "absent-www.conf"))
	}

	root := filepath.Join(dir, "proc-sys")
	for param, value := range sysctls {
		target := filepath.Join(root, strings.ReplaceAll(param, ".", "/"))
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			t.Fatalf("create %s: %v", target, err)
		}
		if err := os.WriteFile(target, []byte(value+"\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}
	setForTest(t, &procSysRoot, root)
}

func writeAt(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// sysctlParams are the sysctl parameters the specs table asks about, which is
// what Current tries to read.
func sysctlParams() []string {
	var out []string
	for _, item := range specs {
		if item.service == ServiceSysctl {
			out = append(out, item.param)
		}
	}
	return out
}

func TestCurrentReadsEveryPlaceAParameterCanLive(t *testing.T) {
	values := map[string]string{}
	for _, param := range sysctlParams() {
		values[param] = "1"
	}
	hostFiles(t, "events {\n  worker_connections 1024;\n}\n", "[www]\npm.max_children = 50\n", values)

	script := newScript()
	script.rows[variablesQuery] = [][]driver.Value{
		{"innodb_buffer_pool_size", "134217728"},
	}

	current, problems := Current(context.Background(), scriptDB(t, script))
	if len(problems) != 0 {
		t.Fatalf("problems = %v, want none", problems)
	}
	if current[ServiceNginx+":worker_connections"] != "1024" {
		t.Errorf("nginx value = %q, want 1024", current[ServiceNginx+":worker_connections"])
	}
	if current[ServicePHPFPM+":pm.max_children"] != "50" {
		t.Errorf("php-fpm value = %q, want 50", current[ServicePHPFPM+":pm.max_children"])
	}
	if current[ServiceMariaDB+":innodb_buffer_pool_size"] != "134217728" {
		t.Errorf("mariadb value = %q, want the byte figure the server reported",
			current[ServiceMariaDB+":innodb_buffer_pool_size"])
	}
	for _, param := range sysctlParams() {
		if current[ServiceSysctl+":"+param] != "1" {
			t.Errorf("sysctl %s = %q, want 1", param, current[ServiceSysctl+":"+param])
		}
	}
}

// A file that cannot be read is a PROBLEM, never a parameter that is absent.
func TestAnUnreadableFileIsReportedRatherThanReadAsUnset(t *testing.T) {
	hostFiles(t, "", "", nil)
	script := newScript()
	script.rows[variablesQuery] = nil

	current, problems := Current(context.Background(), scriptDB(t, script))
	// nginx, the pool and every sysctl the specs table asks about.
	want := 2 + len(sysctlParams())
	if len(problems) != want {
		t.Fatalf("problems = %d (%v), want %d", len(problems), problems, want)
	}
	if len(current) != 0 {
		t.Errorf("values = %v, want none", current)
	}
}

// A MariaDB that cannot be asked is one problem, and the files beside it are
// still read.
func TestAFailedVariableQueryIsOneProblem(t *testing.T) {
	values := map[string]string{}
	for _, param := range sysctlParams() {
		values[param] = "1"
	}
	hostFiles(t, "events {\n  worker_connections 2048;\n}\n", "[www]\npm.max_children = 50\n", values)

	script := newScript()
	script.fail[variablesQuery] = errors.New("connection refused")

	current, problems := Current(context.Background(), scriptDB(t, script))
	if len(problems) != 1 {
		t.Fatalf("problems = %v, want the one query failure", problems)
	}
	if !strings.Contains(problems[0].Error(), "mariadb variables") {
		t.Errorf("problem is %q, want it to name the variables read", problems[0])
	}
	if current[ServiceNginx+":worker_connections"] != "2048" {
		t.Errorf("the files beside it were not read: %v", current)
	}
}

// No database connection is not a problem: the screen still shows the files.
func TestCurrentWithNoDatabaseReadsTheFiles(t *testing.T) {
	values := map[string]string{}
	for _, param := range sysctlParams() {
		values[param] = "1"
	}
	hostFiles(t, "events {\n  worker_connections 512;\n}\n", "[www]\npm.max_children = 5\n", values)

	current, problems := Current(context.Background(), nil)
	if len(problems) != 0 {
		t.Fatalf("problems = %v, want none", problems)
	}
	if current[ServiceNginx+":worker_connections"] != "512" {
		t.Errorf("nginx value = %q, want 512", current[ServiceNginx+":worker_connections"])
	}
	for key := range current {
		if strings.HasPrefix(key, ServiceMariaDB+":") {
			t.Errorf("a MariaDB value appeared with no connection: %q", key)
		}
	}
}

// A sysctl name that is not a name is refused before it is opened, and the
// refusal is a problem like any other read failure. Nothing in specs can fail
// that test today, so the case is built by putting one there.
func TestASysctlNameThatIsNotANameIsRefused(t *testing.T) {
	hostFiles(t, "events {\n}\n", "[www]\n", nil)
	setForTest(t, &specs, []spec{{
		service: ServiceSysctl, param: "net/ipv4/../../etc/shadow",
	}})

	current, problems := Current(context.Background(), nil)
	if len(problems) != 1 {
		t.Fatalf("problems = %v, want the one refusal", problems)
	}
	if !strings.Contains(problems[0].Error(), "carries") {
		t.Errorf("problem is %q, want it to name the character it refused", problems[0])
	}
	if len(current) != 0 {
		t.Errorf("values = %v, want none", current)
	}
}

// A directive nginx.conf does not carry leaves the key ABSENT rather than
// present and empty, because Compute reads an absent key as "not set" and an
// empty one as a value.
func TestADirectiveThatIsNotThereLeavesTheKeyAbsent(t *testing.T) {
	values := map[string]string{}
	for _, param := range sysctlParams() {
		values[param] = "1"
	}
	hostFiles(t, "events {\n}\n", "[www]\n", values)

	current, problems := Current(context.Background(), nil)
	if len(problems) != 0 {
		t.Fatalf("problems = %v, want none", problems)
	}
	if _, ok := current[ServiceNginx+":worker_connections"]; ok {
		t.Errorf("the key is present with %q, want it absent",
			current[ServiceNginx+":worker_connections"])
	}
}
