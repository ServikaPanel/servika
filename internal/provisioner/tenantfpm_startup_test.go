package provisioner

import (
	"database/sql/driver"
	"errors"
	"os"
	"testing"
)

// EnsureTenantFPMOnStartup repairs the pool of every tenant that runs its own
// master, starts a master that is not running, and sends a tenant whose master
// will not start back to the shared one. repairTenantPoolDrift rewrites a pool
// that no longer matches the template, validates it and reloads gracefully, and
// puts the old pool back when php-fpm refuses the new one. These tests pin both.

func TestStartupStartsOnlyTenantMastersThatAreNotRunning(t *testing.T) {
	cases := []struct {
		name      string
		ownMaster bool
		state     string
		fail      [][]string
		want      [][]string
	}{
		{"a tenant on the shared master is left alone", false, "", nil, [][]string{}},
		{"a running master is left running", true, "active", nil,
			[][]string{{"systemctl", "is-active", exampleUnit}}},
		{"a stopped master is started", true, "inactive", nil,
			[][]string{{"systemctl", "is-active", exampleUnit}, {"systemctl", "start", exampleUnit}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withTenantFPM(t)
			f.script.rows[domainSweepQuery] = [][]driver.Value{{int64(7), "c_example_com", "8.3"}}
			if tc.ownMaster {
				f.installUnit(t)
				plantCurrentPool(t, f)
			}
			f.outputs["systemctl is-active "+exampleUnit] = tc.state

			EnsureTenantFPMOnStartup()

			assertArgvs(t, f.commands.argvs(), tc.want)
		})
	}
}

// A master that will not start is not left failing: the tenant goes back to the
// shared master, and a rollback that fails too is only logged.
func TestATenantMasterThatWillNotStartGoesBackToTheSharedMaster(t *testing.T) {
	for _, accountKnown := range []bool{true, false} {
		t.Run(map[bool]string{true: "the rollback succeeds", false: "the rollback fails"}[accountKnown], func(t *testing.T) {
			f := withTenantFPM(t)
			f.script.rows[domainSweepQuery] = [][]driver.Value{{int64(7), "c_example_com", "8.3"}}
			f.installUnit(t)
			plantCurrentPool(t, f)
			f.fail = [][]string{{"systemctl", "start"}}
			if !accountKnown {
				delete(f.accounts, "c_example_com")
			}

			EnsureTenantFPMOnStartup()

			if !f.commands.ran("systemctl", "disable", "--now", exampleUnit) {
				t.Errorf("the tenant was not sent back to the shared master: %q", f.commands.argvs())
			}
			assertPathsGone(t, tenantUnitPath("c_example_com"))
		})
	}
}

func TestStartupWithoutAReadableDomainListStartsNothing(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *tenantFPMFixture)
		want    [][]string
	}{
		{"there is no database", func(t *testing.T, _ *tenantFPMFixture) { withoutDatabase(t) }, [][]string{}},
		{"the domain list cannot be read", func(_ *testing.T, f *tenantFPMFixture) {
			f.script.fail[domainSweepQuery] = errors.New(lostConnectionTo)
		}, [][]string{}},
		{"an unreadable row is skipped and a list cut short keeps what arrived", func(_ *testing.T, f *tenantFPMFixture) {
			f.script.rows[domainSweepQuery] = [][]driver.Value{{nil, "c_example_net", "8.3"}, {int64(7), "c_example_com", "8.3"}}
			f.script.endWith = map[string]error{domainSweepQuery: errors.New(lostConnectionTo)}
		}, [][]string{{"systemctl", "is-active", exampleUnit}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withTenantFPM(t)
			f.installUnit(t)
			plantCurrentPool(t, f)
			f.outputs["systemctl is-active "+exampleUnit] = "active"
			tc.prepare(t, f)

			EnsureTenantFPMOnStartup()

			assertArgvs(t, f.commands.argvs(), tc.want)
		})
	}
}

// plantCurrentPool writes the pool the template renders today, so the drift
// repair has nothing to do.
func plantCurrentPool(t *testing.T, f *tenantFPMFixture) {
	t.Helper()
	writeFixture(t, tenantMainPoolPath("c_example_com"), renderTenantPool(f.db, "c_example_com", 7))
}

const driftedPool = "[c_example_com]\nphp_admin_value[error_log] = /unwritable\n"

func TestADriftedTenantPoolIsRewrittenValidatedAndReloaded(t *testing.T) {
	f := withTenantFPM(t)
	writeFixture(t, tenantMainPoolPath("c_example_com"), driftedPool)

	repairTenantPoolDrift(7, "c_example_com", "8.3")

	assertFileHolds(t, tenantMainPoolPath("c_example_com"), renderTenantPool(f.db, "c_example_com", 7))
	assertFileHolds(t, f.globalConfig(), renderTenantGlobalConfig("c_example_com"))
	assertArgvs(t, f.commands.argvs(), [][]string{
		{f.fpmBin, "-t", "-y", f.globalConfig()},
		{"systemctl", "reload", exampleUnit},
	})
}

// A pool still in the old single-file layout is moved into pool.d and rewritten
// even when its content is current, because the global configuration still
// includes the file that is gone.
func TestALegacyTenantPoolIsMovedAndRewritten(t *testing.T) {
	f := withTenantFPM(t)
	writeFixture(t, tenantLegacyPoolPath("c_example_com"), renderTenantPool(f.db, "c_example_com", 7))

	repairTenantPoolDrift(7, "c_example_com", "8.3")

	assertPathsGone(t, tenantLegacyPoolPath("c_example_com"))
	assertFileHolds(t, f.globalConfig(), renderTenantGlobalConfig("c_example_com"))
	if !f.commands.ran("systemctl", "reload", exampleUnit) {
		t.Errorf("the master was not reloaded onto the moved pool: %q", f.commands.argvs())
	}
}

func TestATenantPoolDriftRepairThatCannotFinishLeavesThePool(t *testing.T) {
	cases := []struct {
		name     string
		prepare  func(t *testing.T, f *tenantFPMFixture)
		wantPool func(f *tenantFPMFixture) string
		commands int
	}{
		{"php-fpm rejects the rewritten pool", func(_ *testing.T, f *tenantFPMFixture) {
			f.fail = [][]string{{f.fpmBin, "-t"}}
		}, func(*tenantFPMFixture) string { return driftedPool }, 1},
		{"the master cannot reload", func(_ *testing.T, f *tenantFPMFixture) {
			f.fail = [][]string{{"systemctl", "reload"}}
		}, currentPool, 2},
		{"the version has no binary", func(_ *testing.T, f *tenantFPMFixture) {
			phpMap["8.3"] = phpConfig{PoolDir: f.pools, Service: "php-fpm"}
		}, func(*tenantFPMFixture) string { return driftedPool }, 0},
		{"the global configuration cannot be written", func(t *testing.T, f *tenantFPMFixture) {
			plantDirectory(t, f.globalConfig())
		}, currentPool, 0},
		{"the pool cannot be written", func(t *testing.T, _ *tenantFPMFixture) {
			if os.Geteuid() == 0 {
				t.Skip("root writes a read-only file")
			}
			if err := os.Chmod(tenantMainPoolPath("c_example_com"), 0o444); err != nil {
				t.Fatal(err)
			}
		}, func(*tenantFPMFixture) string { return driftedPool }, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withTenantFPM(t)
			writeFixture(t, tenantMainPoolPath("c_example_com"), driftedPool)
			tc.prepare(t, f)

			repairTenantPoolDrift(7, "c_example_com", "8.3")

			assertFileHolds(t, tenantMainPoolPath("c_example_com"), tc.wantPool(f))
			if got := len(f.commands.argvs()); got != tc.commands {
				t.Errorf("ran %q, want %d commands", f.commands.argvs(), tc.commands)
			}
		})
	}
}

func currentPool(f *tenantFPMFixture) string { return renderTenantPool(f.db, "c_example_com", 7) }

func TestATenantPoolDriftRepairWithNothingToRepairDoesNothing(t *testing.T) {
	cases := []struct {
		name    string
		user    string
		prepare func(t *testing.T, f *tenantFPMFixture)
	}{
		{"there is no database", "c_example_com", func(t *testing.T, _ *tenantFPMFixture) { withoutDatabase(t) }},
		{"the name is not a tenant", "www_data", func(*testing.T, *tenantFPMFixture) {}},
		{"the tenant has no pool", "c_example_com", func(t *testing.T, _ *tenantFPMFixture) {
			removePath(t, tenantMainPoolPath("c_example_com"))
		}},
		{"the pool is current", "c_example_com", func(t *testing.T, f *tenantFPMFixture) { plantCurrentPool(t, f) }},
		{"a legacy pool cannot be moved", "c_example_com", func(t *testing.T, _ *tenantFPMFixture) {
			removePath(t, tenantPoolDir("c_example_com"))
			plantFile(t, tenantLegacyPoolPath("c_example_com"))
			plantFile(t, tenantPoolDir("c_example_com"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withTenantFPM(t)
			writeFixture(t, tenantMainPoolPath("c_example_com"), driftedPool)
			tc.prepare(t, f)

			repairTenantPoolDrift(7, tc.user, "8.3")

			assertArgvs(t, f.commands.argvs(), [][]string{})
		})
	}
}
