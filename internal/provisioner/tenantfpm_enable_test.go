package provisioner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// EnableTenantFPM moves a domain onto its own PHP-FPM master: it writes the pool,
// the global configuration and the unit, validates them, sets the shared pool
// aside on a first install, starts the unit, waits for its socket and renders the
// vhost onto it. Anything that fails once the unit exists sends the domain back
// to the shared master. These tests pin the sequence, every refusal before a file
// is written, and what each later failure leaves behind.

func TestATenantMovesToItsOwnMaster(t *testing.T) {
	f := withTenantFPM(t)
	sharedPool := filepath.Join(f.pools, "c_example_com.conf")
	plantFile(t, sharedPool)

	socket, err := EnableTenantFPM(f.db, 7, "c_example_com", "8.3")

	if err != nil || socket != tenantSocket("c_example_com") {
		t.Fatalf("EnableTenantFPM() = %q, %v; want the tenant socket", socket, err)
	}
	assertArgvs(t, f.commands.argvs(), [][]string{
		{"getenforce"},
		{f.fpmBin, "-t", "-y", f.globalConfig()},
		{"systemctl", "daemon-reload"},
		{"systemctl", "reload-or-restart", "php-fpm"},
		{"systemctl", "enable", exampleUnit},
		{"systemctl", "restart", exampleUnit},
		{"restorecon", "-R", tenantRunDir("c_example_com")},
		{"restorecon", "-R", tenantCfgDir("c_example_com")},
		{"restorecon", socket},
	})
	assertFileHolds(t, tenantMainPoolPath("c_example_com"), renderTenantPool(f.db, "c_example_com", 7))
	assertFileHolds(t, f.globalConfig(), renderTenantGlobalConfig("c_example_com"))
	assertFileHolds(t, tenantUnitPath("c_example_com"), renderTenantUnit("c_example_com", f.fpmBin))
	assertPathsGone(t, sharedPool)
	assertPathsKept(t, sharedPool+".bak")
	if len(f.capture.opts) != 1 || f.capture.opts[0].PHPSocket != socket {
		t.Errorf("rendered %+v, want one render onto the tenant socket", f.capture.opts)
	}
}

// Only a first install sets the shared pool aside; a tenant already on its own
// master keeps whatever the shared directory holds.
func TestAMasterAlreadyInstalledLeavesTheSharedPoolAlone(t *testing.T) {
	f := withTenantFPM(t)
	f.installUnit(t)
	sharedPool := filepath.Join(f.pools, "c_example_com.conf")
	plantFile(t, sharedPool)

	if _, err := EnableTenantFPM(f.db, 7, "c_example_com", "8.3"); err != nil {
		t.Fatalf("EnableTenantFPM() error = %v", err)
	}

	assertPathsKept(t, sharedPool)
	if f.commands.ran("systemctl", "reload-or-restart", "php-fpm") {
		t.Error("the shared master was reloaded for a tenant that already had its own")
	}
}

func TestATenantMasterWithoutADatabaseIsNotRendered(t *testing.T) {
	f := withTenantFPM(t)

	if _, err := EnableTenantFPM(nil, 7, "c_example_com", "8.3"); err != nil {
		t.Fatalf("EnableTenantFPM() error = %v", err)
	}
	if len(f.capture.opts) != 0 {
		t.Errorf("rendered %+v without a database", f.capture.opts)
	}
}

func TestATenantMasterIsRefusedBeforeItsUnitIsWritten(t *testing.T) {
	cases := []struct {
		name    string
		user    string
		prepare func(t *testing.T, f *tenantFPMFixture)
		reason  string
	}{
		{"the system user is not a tenant", "root", func(*testing.T, *tenantFPMFixture) {}, "invalid system user"},
		{"the version has no binary", "c_example_com", func(t *testing.T, f *tenantFPMFixture) {
			phpMap["8.3"] = phpConfig{PoolDir: f.pools, Service: "php-fpm"}
		}, "PHP-FPM binary is undefined for 8.3"},
		{"the binary is not installed", "c_example_com", func(t *testing.T, f *tenantFPMFixture) {
			removePath(t, f.fpmBin)
		}, "PHP-FPM binary is unavailable for 8.3"},
		{"the tenant home is missing", "c_example_com", func(t *testing.T, f *tenantFPMFixture) {
			removePath(t, filepath.Join(f.homes, "c_example_com"))
		}, "tenant home is unavailable"},
		{"the configuration directory cannot be created", "c_example_com", func(t *testing.T, f *tenantFPMFixture) {
			plantFile(t, f.cfgRoot)
		}, "create tenant configuration directory"},
		{"the log directory cannot be created", "c_example_com", func(t *testing.T, _ *tenantFPMFixture) {
			blocker := filepath.Join(t.TempDir(), "a-file")
			plantFile(t, blocker)
			t.Setenv("SERVIKA_FPM_LOG_DIR", filepath.Join(blocker, "logs"))
		}, "create the tenant PHP-FPM log directory"},
		{"the log directory carries the wrong label", "c_example_com", func(t *testing.T, f *tenantFPMFixture) {
			f.outputs["getenforce"] = "Enforcing"
			f.outputs["stat -c %C "+tenantLogDir()] = "system_u:object_r:var_log_t:s0"
		}, `is labelled "var_log_t", not "httpd_log_t"`},
		{"the pool layout cannot be migrated", "c_example_com", func(t *testing.T, _ *tenantFPMFixture) {
			plantFile(t, tenantPoolDir("c_example_com"))
		}, "migrate tenant pool layout"},
		{"the pool cannot be written", "c_example_com", func(t *testing.T, _ *tenantFPMFixture) {
			plantDirectory(t, tenantMainPoolPath("c_example_com"))
		}, "write tenant pool"},
		{"the global configuration cannot be written", "c_example_com", func(t *testing.T, f *tenantFPMFixture) {
			plantDirectory(t, f.globalConfig())
		}, "write tenant global configuration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withTenantFPM(t)
			tc.prepare(t, f)

			_, err := EnableTenantFPM(f.db, 7, tc.user, "8.3")

			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("EnableTenantFPM() error = %v, want one naming %q", err, tc.reason)
			}
			assertPathsGone(t, tenantUnitPath("c_example_com"))
			if f.commands.ran("systemctl") {
				t.Errorf("systemctl ran before the unit existed: %q", f.commands.argvs())
			}
		})
	}
}

// A configuration php-fpm refuses never reaches a unit, and the pool it replaced
// is put back.
func TestARejectedTenantPoolIsPutBack(t *testing.T) {
	cases := []struct {
		name     string
		previous string
	}{
		{"a previous pool is restored", "[c_example_com]\n; the previous pool\n"},
		{"a pool that did not exist is removed", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withTenantFPM(t)
			f.fail = [][]string{{f.fpmBin, "-t"}}
			if tc.previous != "" {
				writeFixture(t, tenantMainPoolPath("c_example_com"), tc.previous)
			}

			_, err := EnableTenantFPM(f.db, 7, "c_example_com", "8.3")

			if err == nil || !strings.Contains(err.Error(), "validate tenant PHP-FPM configuration: refused") {
				t.Fatalf("EnableTenantFPM() error = %v, want the validation failure", err)
			}
			if tc.previous != "" {
				assertFileHolds(t, tenantMainPoolPath("c_example_com"), tc.previous)
			} else {
				assertPathsGone(t, tenantMainPoolPath("c_example_com"))
			}
			assertPathsGone(t, tenantUnitPath("c_example_com"))
		})
	}
}

func TestATenantMasterThatDoesNotComeUpGoesBackToTheSharedMaster(t *testing.T) {
	cases := []struct {
		name     string
		prepare  func(t *testing.T, f *tenantFPMFixture)
		reason   string
		rollback bool
	}{
		{"the unit cannot be written", func(t *testing.T, _ *tenantFPMFixture) {
			plantDirectory(t, tenantUnitPath("c_example_com"))
		}, "write tenant service", false},
		{"systemd cannot reload its units", func(_ *testing.T, f *tenantFPMFixture) {
			f.fail = [][]string{{"systemctl", "daemon-reload"}}
		}, "reload systemd units: refused", true},
		{"the shared pool cannot be set aside", func(t *testing.T, f *tenantFPMFixture) {
			sharedPool := filepath.Join(f.pools, "c_example_com.conf")
			plantFile(t, sharedPool)
			plantDirectory(t, sharedPool+".bak")
		}, "preserve shared PHP-FPM pool", true},
		{"the unit cannot be enabled", func(_ *testing.T, f *tenantFPMFixture) {
			f.fail = [][]string{{"systemctl", "enable"}}
		}, "enable tenant PHP-FPM: refused", true},
		{"the unit cannot be restarted", func(_ *testing.T, f *tenantFPMFixture) {
			f.fail = [][]string{{"systemctl", "restart"}}
		}, "restart tenant PHP-FPM: refused", true},
		{"the socket never appears", func(_ *testing.T, f *tenantFPMFixture) {
			f.socketUp = false
		}, "tenant PHP-FPM socket was not created", true},
		{"the vhost cannot be rendered", func(_ *testing.T, f *tenantFPMFixture) {
			f.capture.err = errors.New("nginx -t failed")
		}, "render tenant nginx virtual host: nginx -t failed", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withTenantFPM(t)
			tc.prepare(t, f)

			_, err := EnableTenantFPM(f.db, 7, "c_example_com", "8.3")

			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("EnableTenantFPM() error = %v, want one naming %q", err, tc.reason)
			}
			if rolledBack := f.commands.ran("systemctl", "disable", "--now", exampleUnit); rolledBack != tc.rollback {
				t.Errorf("rolled back to the shared master = %v, want %v; ran %q", rolledBack, tc.rollback, f.commands.argvs())
			}
		})
	}
}

func removePath(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
}
