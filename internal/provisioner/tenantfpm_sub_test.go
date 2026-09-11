package provisioner

import (
	"database/sql/driver"
	"slices"
	"strings"
	"testing"
)

// ApplySubdomainFPM puts a subdomain's pool inside its tenant's own master when
// that master exists and runs the subdomain's PHP version, and otherwise clears
// any pool left from an earlier state and answers the socket the subdomain falls
// back to. A pool the master refuses or does not serve is taken back out. These
// tests pin each of those outcomes.

const blogDocRoot = "/home/c_example_com/public_html/blog"

func applyBlogSubdomain(f *tenantFPMFixture, user string, subdomainID int64) (string, error) {
	return ApplySubdomainFPM(f.db, 7, subdomainID, user, blogDocRoot, "8.3")
}

func TestASubdomainPoolJoinsItsTenantsMaster(t *testing.T) {
	f := withTenantFPM(t)
	f.installUnit(t)

	socket, err := applyBlogSubdomain(f, "c_example_com", 5)

	if err != nil || socket != tenantSubSocket("c_example_com", 5) {
		t.Fatalf("ApplySubdomainFPM() = %q, %v; want the subdomain socket", socket, err)
	}
	assertArgvs(t, f.commands.argvs(), [][]string{
		{f.fpmBin, "-t", "-y", f.globalConfig()},
		{"systemctl", "reload-or-restart", exampleUnit},
		{"restorecon", socket},
	})
	assertFileHolds(t, tenantSubPoolPath("c_example_com", 5), renderTenantPoolScoped(f.db, "c_example_com", 7, 5, blogDocRoot))
}

// A subdomain its tenant's master cannot serve falls back, and a pool left from
// an earlier eligible state is removed so it cannot keep the old socket bound.
func TestASubdomainTheTenantMasterCannotServeFallsBack(t *testing.T) {
	cases := []struct {
		name       string
		ownMaster  bool
		parentPHP  string
		wantSocket string
		reloads    bool
	}{
		{"the tenant runs on the shared master", false, "8.3", "/run/php-fpm/c_example_com.sock", false},
		{"the subdomain asks for another PHP version", true, "7.4", tenantSocket("c_example_com"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withTenantFPM(t)
			phpMap["7.4"] = phpConfig{PoolDir: f.pools, Service: "php74-php-fpm", FPMBin: f.fpmBin}
			if tc.ownMaster {
				f.installUnit(t)
			}
			f.script.rows[parentPHPQuery] = [][]driver.Value{{tc.parentPHP}}
			stale := tenantSubPoolPath("c_example_com", 5)
			plantFile(t, stale)

			socket, err := applyBlogSubdomain(f, "c_example_com", 5)

			if err != nil || socket != tc.wantSocket {
				t.Fatalf("ApplySubdomainFPM() = %q, %v; want %q", socket, err, tc.wantSocket)
			}
			assertPathsGone(t, stale)
			if reloaded := f.commands.ran("systemctl", "reload-or-restart", exampleUnit); reloaded != tc.reloads {
				t.Errorf("the tenant master was reloaded = %v, want %v", reloaded, tc.reloads)
			}
		})
	}
}

func TestASubdomainPoolThatCannotBeInstalledIsRefused(t *testing.T) {
	cases := []struct {
		name        string
		user        string
		subdomainID int64
		prepare     func(t *testing.T, f *tenantFPMFixture)
		reason      string
	}{
		{"the system user is not a tenant", "root", 5, func(*testing.T, *tenantFPMFixture) {}, "invalid system user"},
		{"the subdomain id is not valid", "c_example_com", 0, func(*testing.T, *tenantFPMFixture) {}, "invalid subdomain id: 0"},
		{"the version has no binary", "c_example_com", 5, func(_ *testing.T, f *tenantFPMFixture) {
			phpMap["8.3"] = phpConfig{PoolDir: f.pools, Service: "php-fpm"}
		}, "PHP-FPM binary is undefined for 8.3"},
		{"the pool layout cannot be migrated", "c_example_com", 5, func(t *testing.T, _ *tenantFPMFixture) {
			plantFile(t, tenantPoolDir("c_example_com"))
		}, "migrate tenant pool layout"},
		{"the pool cannot be written", "c_example_com", 5, func(t *testing.T, _ *tenantFPMFixture) {
			plantDirectory(t, tenantSubPoolPath("c_example_com", 5))
		}, "write subdomain pool"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withTenantFPM(t)
			f.installUnit(t)
			tc.prepare(t, f)

			_, err := applyBlogSubdomain(f, tc.user, tc.subdomainID)

			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("ApplySubdomainFPM() error = %v, want one naming %q", err, tc.reason)
			}
			if f.commands.ran("systemctl") {
				t.Errorf("the master was touched for a pool that was never written: %q", f.commands.argvs())
			}
		})
	}
}

// A pool the master refuses, or one it does not come up serving, is taken back
// out: the previous pool is restored when there was one.
func TestASubdomainPoolTheMasterDoesNotServeIsTakenBackOut(t *testing.T) {
	cases := []struct {
		name     string
		previous string
		prepare  func(f *tenantFPMFixture)
		reason   string
		reloads  int
	}{
		{"php-fpm rejects a new pool", "", func(f *tenantFPMFixture) { f.fail = [][]string{{f.fpmBin, "-t"}} },
			"validate subdomain pool: refused", 0},
		{"php-fpm rejects a changed pool", "[sub-5]\n; previous\n", func(f *tenantFPMFixture) { f.fail = [][]string{{f.fpmBin, "-t"}} },
			"validate subdomain pool: refused", 0},
		{"the master cannot reload a new pool", "", func(f *tenantFPMFixture) { f.fail = [][]string{{"systemctl", "reload-or-restart"}} },
			"reload tenant PHP-FPM: refused", 2},
		{"the master cannot reload a changed pool", "[sub-5]\n; previous\n", func(f *tenantFPMFixture) { f.fail = [][]string{{"systemctl", "reload-or-restart"}} },
			"reload tenant PHP-FPM: refused", 2},
		{"the socket never appears", "", func(f *tenantFPMFixture) { f.socketUp = false },
			"subdomain PHP-FPM socket was not created", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withTenantFPM(t)
			f.installUnit(t)
			pool := tenantSubPoolPath("c_example_com", 5)
			if tc.previous != "" {
				writeFixture(t, pool, tc.previous)
			}
			tc.prepare(f)

			_, err := applyBlogSubdomain(f, "c_example_com", 5)

			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("ApplySubdomainFPM() error = %v, want one naming %q", err, tc.reason)
			}
			assertSubdomainPoolRestored(t, pool, tc.previous)
			if got := countArgvs(f.commands, []string{"systemctl", "reload-or-restart", exampleUnit}); got != tc.reloads {
				t.Errorf("reloaded the tenant master %d times, want %d", got, tc.reloads)
			}
		})
	}
}

func assertSubdomainPoolRestored(t *testing.T, pool, previous string) {
	t.Helper()
	if previous == "" {
		assertPathsGone(t, pool)
		return
	}
	assertFileHolds(t, pool, previous)
}

func countArgvs(r *commandRecorder, argv []string) int {
	count := 0
	for _, recorded := range r.argvs() {
		if slices.Equal(recorded, argv) {
			count++
		}
	}
	return count
}
