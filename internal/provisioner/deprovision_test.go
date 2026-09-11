package provisioner

import (
	"database/sql/driver"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"servika/internal/config"
)

// Deprovision takes a tenant off the host, but only when no other top-level
// domain still answers to its system user: a shared user keeps its home, account,
// vhost and pool, and a lookup that failed counts as shared. These tests plant
// every file a tenant owns in temporary directories and pin which of them each
// situation removes, which commands run and what is returned.

const siblingDomainsQuery = "AND domain_name<>?"

// tenantHost is every file and directory a provisioned tenant owns outside the
// database, plus a neighbour's subdomain vhost that must survive.
type tenantHost struct {
	vhost, subdomainVhost, neighbourVhost string
	certificates, wafConf, wafCustom      string
	crontab, suspendedCrontab             string
	backups, fpmLog, rotatedFPMLog        string
	pool, poolBackup, unit, tenantConfig  string
}

type deprovisionFixture struct {
	host     tenantHost
	accounts map[string]*user.User
	script   *sqlScript
	commands *commandRecorder
}

func withDeprovisioning(t *testing.T) *deprovisionFixture {
	t.Helper()
	root := t.TempDir()
	dir := func(name string) string { return filepath.Join(root, name) }
	withTenantHome(t)
	withTenantUnits(t)
	certRoot(t)
	setForTest(t, &nginxConfDir, dir("conf.d"))
	setForTest(t, &wafDomainsDir, dir("modsec"))
	setForTest(t, &cronSpoolDir, dir("cron"))
	setForTest(t, &suspendedCronDir, dir("cron-suspended"))
	setForTest(t, &tenantCfgRoot, dir("php-fpm-tenant"))
	setForTest(t, &legacyTenantLogDir, dir("legacy-fpm-logs"))
	setForTest(t, &phpMap, map[string]phpConfig{"8.3": {PoolDir: dir("php-fpm.d"), SockDir: dir("run"), Service: "php-fpm"}})
	t.Setenv("SERVIKA_NGINX_CACHE_DIR", dir("cache"))
	t.Setenv("SERVIKA_BACKUP_ROOT", dir("backups"))
	t.Setenv("SERVIKA_FPM_LOG_DIR", dir("fpm-logs"))

	f := &deprovisionFixture{
		accounts: map[string]*user.User{"c_example_com": {Username: "c_example_com", Uid: "1500", Gid: "1500"}},
		script:   &sqlScript{rows: map[string][][]driver.Value{siblingDomainsQuery: {}}},
	}
	withAccounts(t, f.accounts)
	withScript(t, f.script)
	f.commands = withCommands(t)
	f.host = plantTenantHost(t)
	return f
}

// plantTenantHost writes every file a tenant owns and returns their paths.
func plantTenantHost(t *testing.T) tenantHost {
	t.Helper()
	host := tenantHost{
		vhost:            filepath.Join(nginxConfDir, "dom_c_example_com.conf"),
		subdomainVhost:   filepath.Join(nginxConfDir, "sub_c_example_com_3.conf"),
		neighbourVhost:   filepath.Join(nginxConfDir, "sub_c_example_net_3.conf"),
		certificates:     certSystemDir("example.com"),
		wafConf:          filepath.Join(wafDomainsDir, "c_example_com.conf"),
		wafCustom:        filepath.Join(wafDomainsDir, "c_example_com.custom.conf"),
		crontab:          filepath.Join(cronSpoolDir, "c_example_com"),
		suspendedCrontab: filepath.Join(suspendedCronDir, "c_example_com"),
		backups:          filepath.Join(config.BackupRoot(), "c_example_com"),
		fpmLog:           tenantLogPath("c_example_com"),
		rotatedFPMLog:    tenantLogPath("c_example_com") + ".1",
		pool:             filepath.Join(phpMap["8.3"].PoolDir, "c_example_com.conf"),
		poolBackup:       filepath.Join(phpMap["8.3"].PoolDir, "c_example_com.conf.bak"),
		unit:             tenantUnitPath("c_example_com"),
		tenantConfig:     tenantCfgDir("c_example_com"),
	}
	for _, file := range []string{
		host.vhost, host.subdomainVhost, host.neighbourVhost, host.wafConf, host.wafCustom,
		host.crontab, host.suspendedCrontab, host.fpmLog, host.rotatedFPMLog, host.pool, host.poolBackup, host.unit,
		filepath.Join(host.certificates, "example.com.crt"),
		filepath.Join(host.backups, "manual.tar.gz"),
		filepath.Join(host.tenantConfig, "php-fpm.conf"),
	} {
		plantFile(t, file)
	}
	return host
}

// plantFile puts a placeholder file at path, creating the directories above it.
func plantFile(t *testing.T, path string) {
	t.Helper()
	writeFixture(t, path, "planted\n")
}

func assertPathsGone(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s is still there (%v)", path, err)
		}
	}
}

func assertPathsKept(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s was removed: %v", path, err)
		}
	}
}

func TestDeprovisioningTearsDownEverythingTheTenantOwns(t *testing.T) {
	f := withDeprovisioning(t)
	h := f.host

	if err := Deprovision("example.com", "c_example_com"); err != nil {
		t.Fatalf("Deprovision() error = %v", err)
	}

	assertPathsGone(t, h.vhost, h.subdomainVhost, h.certificates, h.wafConf, h.wafCustom, h.crontab, h.suspendedCrontab,
		h.backups, h.fpmLog, h.rotatedFPMLog, h.pool, h.poolBackup, h.unit, h.tenantConfig)
	assertPathsKept(t, h.neighbourVhost)
	want := [][]string{
		{"systemctl", "disable", "--now", "php-fpm-c_example_com.service"},
		{"systemctl", "daemon-reload"},
		{"systemctl", "reload", "nginx"},
		{"userdel", "-r", "c_example_com"},
		{"systemctl", "reload-or-restart", "php-fpm"},
	}
	if got := f.commands.argvs(); !reflect.DeepEqual(got, want) {
		t.Errorf("ran %q\nwant %q", got, want)
	}
}

// A system user another domain still answers to keeps everything keyed on it;
// only this domain's certificate directory goes. A lookup that failed is treated
// the same way, because an orphaned user is recoverable and a deleted home is not.
func TestASystemUserStillInUseKeepsItsHost(t *testing.T) {
	cases := []struct {
		name   string
		script func(s *sqlScript)
	}{
		{"another domain answers to it", func(s *sqlScript) { s.rows[siblingDomainsQuery] = [][]driver.Value{{int64(4)}} }},
		{"the lookup failed", func(s *sqlScript) { s.fail = map[string]error{siblingDomainsQuery: errors.New(lostConnectionTo)} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withDeprovisioning(t)
			tc.script(f.script)
			h := f.host

			if err := Deprovision("example.com", "c_example_com"); err != nil {
				t.Fatalf("Deprovision() error = %v", err)
			}

			assertPathsGone(t, h.certificates)
			assertPathsKept(t, h.vhost, h.subdomainVhost, h.wafConf, h.crontab, h.backups, h.fpmLog, h.pool, h.unit, h.tenantConfig)
			if want := [][]string{{"systemctl", "reload", "nginx"}}; !reflect.DeepEqual(f.commands.argvs(), want) {
				t.Errorf("ran %q, want only %q", f.commands.argvs(), want)
			}
		})
	}
}

// The account and everything that only userdel's success unlocks stay when the
// name does not carry the tenant prefix; the vhost and pool keyed on it are gone
// by then.
func TestAUserWithoutTheTenantPrefixIsNeverDeleted(t *testing.T) {
	f := withDeprovisioning(t)

	err := Deprovision("example.com", "www_data")

	if err == nil || !strings.Contains(err.Error(), "refusing to delete a user without the c_ prefix") {
		t.Fatalf("Deprovision() error = %v, want the prefix refusal", err)
	}
	if f.commands.ran("userdel") {
		t.Errorf("userdel ran for a user without the tenant prefix: %q", f.commands.argvs())
	}
	assertPathsGone(t, f.host.certificates)
	assertPathsKept(t, f.host.crontab, f.host.backups)
}

// Backups and PHP-FPM logs are removed only after userdel ran, so a tenant whose
// account is already gone keeps them; its crontab and pool still go.
func TestAnAccountAlreadyGoneKeepsItsBackupsAndLogs(t *testing.T) {
	f := withDeprovisioning(t)
	delete(f.accounts, "c_example_com")
	h := f.host

	if err := Deprovision("example.com", "c_example_com"); err != nil {
		t.Fatalf("Deprovision() error = %v", err)
	}

	assertPathsGone(t, h.vhost, h.crontab, h.suspendedCrontab, h.pool)
	assertPathsKept(t, h.backups, h.fpmLog)
	if f.commands.ran("userdel") {
		t.Errorf("userdel ran for an account that does not exist: %q", f.commands.argvs())
	}
}

func TestDeprovisioningWithoutAUsableDomainNameKeepsTheCertificates(t *testing.T) {
	for _, name := range []string{"", "bad name"} {
		t.Run("domain "+name, func(t *testing.T) {
			f := withDeprovisioning(t)

			if err := Deprovision(name, "c_example_com"); err != nil {
				t.Fatalf("Deprovision() error = %v", err)
			}

			assertPathsKept(t, f.host.certificates)
			assertPathsGone(t, f.host.vhost, f.host.pool)
		})
	}
}
