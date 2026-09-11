package provisioner

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// migrateOneTenantFPMLogPath moves one installed tenant master to the new log
// directory. The global config and the unit move together or not at all, so
// every failure after the first write restores both files, and nothing is
// written or run when there is nothing to move.

const (
	fpmTestUser   = "c_example_com"
	fpmTestBinary = "/usr/sbin/php-fpm"
)

type fpmMigrationFixture struct {
	unitPath, globalPath string
	oldUnit, oldGlobal   string
}

// withFPMMigration lays out an installed tenant whose files still carry the old
// arrangement, under temporary directories.
func withFPMMigration(t *testing.T) fpmMigrationFixture {
	t.Helper()
	previousUnits, previousCfg, previousLegacy := tenantUnitDir, tenantCfgRoot, legacyTenantLogDir
	tenantUnitDir, tenantCfgRoot, legacyTenantLogDir = t.TempDir(), t.TempDir(), t.TempDir()
	t.Cleanup(func() {
		tenantUnitDir, tenantCfgRoot, legacyTenantLogDir = previousUnits, previousCfg, previousLegacy
	})
	t.Setenv("SERVIKA_FPM_LOG_DIR", t.TempDir())

	f := fpmMigrationFixture{
		unitPath:   tenantUnitPath(fpmTestUser),
		globalPath: filepath.Join(tenantCfgDir(fpmTestUser), "php-fpm.conf"),
		oldUnit:    "[Service]\nExecStart=" + fpmTestBinary + " --nodaemonize --fpm-config old\n",
		oldGlobal:  "[global]\nerror_log = /var/log/php-fpm/tenant-" + fpmTestUser + ".log\n",
	}
	if err := os.MkdirAll(filepath.Dir(f.globalPath), 0o755); err != nil {
		t.Fatalf("create the tenant config directory: %v", err)
	}
	writeFixture(t, f.unitPath, f.oldUnit)
	writeFixture(t, f.globalPath, f.oldGlobal)
	return f
}

// writeFixture writes body to path, creating the directories above it.
func writeFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create the directory of %s: %v", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", filepath.Base(path), err)
	}
}

// assertFiles checks both files; a file that does not exist reads as "".
func (f fpmMigrationFixture) assertFiles(t *testing.T, unit, global string) {
	t.Helper()
	if got, _ := os.ReadFile(f.unitPath); string(got) != unit {
		t.Errorf("unit =\n%s\nwant\n%s", got, unit)
	}
	if got, _ := os.ReadFile(f.globalPath); string(got) != global {
		t.Errorf("global config =\n%s\nwant\n%s", got, global)
	}
}

func assertArgvs(t *testing.T, got, want [][]string) {
	t.Helper()
	if !slices.EqualFunc(got, want, func(a, b []string) bool { return slices.Equal(a, b) }) {
		t.Errorf("commands = %q, want %q", got, want)
	}
}

func TestAMigrationMovesTheUnitAndTheGlobalConfigTogether(t *testing.T) {
	f := withFPMMigration(t)
	legacy := legacyTenantLogPath(fpmTestUser)
	writeFixture(t, legacy, "old log line")
	commands := withCommands(t)

	migrateOneTenantFPMLogPath(fpmTestUser, f.unitPath)

	f.assertFiles(t, renderTenantUnit(fpmTestUser, fpmTestBinary), renderTenantGlobalConfig(fpmTestUser))
	assertArgvs(t, commands.argvs(), [][]string{
		{fpmTestBinary, "-t", "-y", f.globalPath},
		{"systemctl", "daemon-reload"},
		{"systemctl", "restart", tenantUnitName(fpmTestUser)},
	})
	if moved, err := os.ReadFile(tenantLogPath(fpmTestUser)); err != nil || string(moved) != "old log line" {
		t.Errorf("the existing log was not moved into the new directory: %q, %v", moved, err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Errorf("the old log was left behind: %v", err)
	}
}

// A log already in the new directory is not overwritten by the old one.
func TestAMigrationKeepsALogAlreadyInTheNewDirectory(t *testing.T) {
	f := withFPMMigration(t)
	legacy := legacyTenantLogPath(fpmTestUser)
	writeFixture(t, legacy, "old")
	writeFixture(t, tenantLogPath(fpmTestUser), "new")
	withCommands(t)

	migrateOneTenantFPMLogPath(fpmTestUser, f.unitPath)

	if got, _ := os.ReadFile(tenantLogPath(fpmTestUser)); string(got) != "new" {
		t.Errorf("the log in the new directory was replaced: %q", got)
	}
	if got, _ := os.ReadFile(legacy); string(got) != "old" {
		t.Errorf("the old log was moved over an existing one: %q", got)
	}
}

func TestAMigrationWithNothingToDoTouchesNothing(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f fpmMigrationFixture) (unit, global string)
	}{
		{"the unit cannot be read", func(t *testing.T, f fpmMigrationFixture) (string, string) {
			if err := os.Remove(f.unitPath); err != nil {
				t.Fatal(err)
			}
			return "", f.oldGlobal
		}},
		{"the unit names no interpreter", func(t *testing.T, f fpmMigrationFixture) (string, string) {
			unit := "[Service]\nType=notify\n"
			writeFixture(t, f.unitPath, unit)
			return unit, f.oldGlobal
		}},
		{"there is no global config", func(t *testing.T, f fpmMigrationFixture) (string, string) {
			if err := os.Remove(f.globalPath); err != nil {
				t.Fatal(err)
			}
			return f.oldUnit, ""
		}},
		{"both files are already current", func(t *testing.T, f fpmMigrationFixture) (string, string) {
			unit, global := renderTenantUnit(fpmTestUser, fpmTestBinary), renderTenantGlobalConfig(fpmTestUser)
			writeFixture(t, f.unitPath, unit)
			writeFixture(t, f.globalPath, global)
			return unit, global
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withFPMMigration(t)
			unit, global := tc.prepare(t, f)
			commands := withCommands(t)

			migrateOneTenantFPMLogPath(fpmTestUser, f.unitPath)

			f.assertFiles(t, unit, global)
			assertArgvs(t, commands.argvs(), [][]string{})
		})
	}
}

// Every failure after the global config was written puts both files back and
// reloads systemd, and a failed restart restarts the master on the old files.
func TestAFailedStepRestoresBothFiles(t *testing.T) {
	restart := []string{"systemctl", "restart", tenantUnitName(fpmTestUser)}
	reload := []string{"systemctl", "daemon-reload"}
	cases := []struct {
		name string
		fail []string
		want func(f fpmMigrationFixture) [][]string
	}{
		{"php-fpm refuses the config", []string{fpmTestBinary, "-t"}, func(f fpmMigrationFixture) [][]string {
			return [][]string{{fpmTestBinary, "-t", "-y", f.globalPath}, reload}
		}},
		{"systemd cannot reload", reload, func(f fpmMigrationFixture) [][]string {
			return [][]string{{fpmTestBinary, "-t", "-y", f.globalPath}, reload, reload}
		}},
		{"the master cannot restart", []string{"systemctl", "restart"}, func(f fpmMigrationFixture) [][]string {
			return [][]string{{fpmTestBinary, "-t", "-y", f.globalPath}, reload, restart, reload, restart}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withFPMMigration(t)
			commands := withCommands(t, tc.fail)

			migrateOneTenantFPMLogPath(fpmTestUser, f.unitPath)

			f.assertFiles(t, f.oldUnit, f.oldGlobal)
			assertArgvs(t, commands.argvs(), tc.want(f))
		})
	}
}

// A global config that cannot be written stops before anything is run.
func TestAGlobalConfigThatCannotBeWrittenRunsNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only file, so the refusal cannot be produced")
	}
	f := withFPMMigration(t)
	if err := os.Chmod(f.globalPath, 0o444); err != nil {
		t.Fatal(err)
	}
	commands := withCommands(t)

	migrateOneTenantFPMLogPath(fpmTestUser, f.unitPath)

	f.assertFiles(t, f.oldUnit, f.oldGlobal)
	assertArgvs(t, commands.argvs(), [][]string{})
}

// A unit that cannot be written puts the already rewritten global config back.
func TestAUnitThatCannotBeWrittenRestoresTheGlobalConfig(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only file, so the refusal cannot be produced")
	}
	f := withFPMMigration(t)
	if err := os.Chmod(f.unitPath, 0o444); err != nil {
		t.Fatal(err)
	}
	commands := withCommands(t)

	migrateOneTenantFPMLogPath(fpmTestUser, f.unitPath)

	f.assertFiles(t, f.oldUnit, f.oldGlobal)
	assertArgvs(t, commands.argvs(), [][]string{
		{fpmTestBinary, "-t", "-y", f.globalPath},
		{"systemctl", "daemon-reload"},
	})
}
