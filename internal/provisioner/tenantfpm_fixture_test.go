package provisioner

import (
	"database/sql"
	"database/sql/driver"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tenantFPMFixture runs the tenant PHP-FPM paths against a temporary
// configuration root, a php-fpm binary that exists but never runs, a fake account
// table and recorded commands. A command whose argv starts with one of fail exits
// 1 printing "refused"; every other command prints outputs[argv joined by spaces]
// and succeeds. socketUp decides whether a master's socket appears.
type tenantFPMFixture struct {
	homes    string
	units    string
	cfgRoot  string
	pools    string
	fpmBin   string
	accounts map[string]*user.User
	socketUp bool
	fail     [][]string
	outputs  map[string]string
	script   *sqlScript
	db       *sql.DB
	capture  *renderCapture
	commands *commandRecorder
}

const (
	planChildrenQuery = "p.pm_max_children"
	parentPHPQuery    = "COALESCE(php_version,'') FROM domains"
	exampleUnit       = "php-fpm-c_example_com.service"
)

func withTenantFPM(t *testing.T) *tenantFPMFixture {
	t.Helper()
	root := t.TempDir()
	f := &tenantFPMFixture{
		homes:    withTenantHome(t),
		units:    withTenantUnits(t),
		cfgRoot:  filepath.Join(root, "php-fpm-tenant"),
		pools:    filepath.Join(root, "php-fpm.d"),
		fpmBin:   filepath.Join(root, "php-fpm"),
		accounts: map[string]*user.User{"c_example_com": {Username: "c_example_com", Uid: "1500", Gid: "1500"}},
		socketUp: true,
		outputs:  map[string]string{"getenforce": "Disabled"},
	}
	plantFile(t, f.fpmBin)
	if err := os.MkdirAll(filepath.Join(f.homes, "c_example_com"), 0o710); err != nil {
		t.Fatal(err)
	}
	setForTest(t, &tenantCfgRoot, f.cfgRoot)
	setForTest(t, &phpMap, map[string]phpConfig{
		"8.3": {PoolDir: f.pools, SockDir: filepath.Join(root, "run"), Service: "php-fpm", FPMBin: f.fpmBin},
	})
	setForTest(t, &socketAppears, func(string, time.Duration) bool { return f.socketUp })
	setForTest(t, &fcontextDone, true)
	t.Setenv("SERVIKA_FPM_LOG_DIR", filepath.Join(root, "fpm-logs"))
	withAccounts(t, f.accounts)
	f.capture = withRenderCapture(t)
	f.script = vhostScript(domainDetails("example.com", "c_example_com", "", "", "", "php-fpm", "", 0, 0, "", nil))
	f.script.rows[planChildrenQuery] = [][]driver.Value{}
	f.script.rows[parentPHPQuery] = [][]driver.Value{{"8.3"}}
	f.db = withScript(t, f.script)
	f.commands = withCommandScript(t, f.respond)
	return f
}

func (f *tenantFPMFixture) respond(argv []string) (string, int) {
	for _, prefix := range f.fail {
		if hasArgvPrefix(argv, prefix) {
			return "refused", 1
		}
	}
	return f.outputs[strings.Join(argv, " ")], 0
}

// installUnit makes c_example_com a tenant that already runs its own master.
func (f *tenantFPMFixture) installUnit(t *testing.T) {
	t.Helper()
	writeFixture(t, tenantUnitPath("c_example_com"), "[Service]\n")
}

func (f *tenantFPMFixture) globalConfig() string {
	return filepath.Join(tenantCfgDir("c_example_com"), "php-fpm.conf")
}

// plantDirectory puts a non-empty directory at path, which a write or a rename
// onto that path refuses.
func plantDirectory(t *testing.T, path string) {
	t.Helper()
	plantFile(t, filepath.Join(path, "occupied"))
}

func assertFileHolds(t *testing.T, path, want string) {
	t.Helper()
	if data, err := os.ReadFile(path); err != nil || string(data) != want {
		t.Errorf("%s holds %q, %v; want %q", filepath.Base(path), data, err, want)
	}
}
