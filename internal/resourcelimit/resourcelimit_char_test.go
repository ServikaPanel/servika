package resourcelimit

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// commandRecord holds every command the package built, in order.
type commandRecord struct{ calls [][]string }

// contains reports whether any command carried the fragment in its argv.
func (c *commandRecord) contains(fragment string) bool {
	for _, argv := range c.calls {
		if strings.Contains(strings.Join(argv, " "), fragment) {
			return true
		}
	}
	return false
}

// recordCommands answers every command with a shell script chosen from its
// argv, and records what the package asked for.
func recordCommands(t *testing.T, script func(argv []string) string) *commandRecord {
	t.Helper()
	record := &commandRecord{}
	setForTest(t, &resourceCommandContext, func(ctx context.Context, name string, args ...string) *exec.Cmd {
		argv := append([]string{name}, args...)
		record.calls = append(record.calls, argv)
		return exec.CommandContext(ctx, "sh", "-c", script(argv))
	})
	return record
}

// captureLog collects what the package logged during one test. Several
// decisions here have no other observable outcome.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buffer bytes.Buffer
	previousOutput := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&buffer)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
	})
	return &buffer
}

// systemd keeps an io.max entry alive after an empty property assignment, so
// every metric the plan no longer sets is cleared against the live cgroup by
// hand. Leaving it would keep throttling a tenant whose plan no longer limits
// its disk I/O at all.
func TestClearKernelIOLimitsClearsEveryMetricThePlanDoesNotSet(t *testing.T) {
	root := t.TempDir()
	setForTest(t, &cgroupRoot, root)
	group := "servika.slice/servika-c_site.slice"
	if err := os.MkdirAll(filepath.Join(root, group), 0755); err != nil {
		t.Fatalf("create cgroup directory: %v", err)
	}
	ioMax := filepath.Join(root, group, "io.max")
	// The blank line is what the kernel leaves behind when a device has no
	// limits at all; it names no device and must not be written back.
	if err := os.WriteFile(ioMax, []byte("259:0 rbps=1000\n\n8:0 wbps=2000\n"), 0644); err != nil {
		t.Fatalf("write io.max: %v", err)
	}
	record := recordCommands(t, func([]string) string { return "printf '%s\\n' '" + group + "'" })

	clearKernelIOLimits("c_site", Limits{IOReadMBps: 25})

	if !record.contains("systemctl show servika-c_site.slice -p ControlGroup --value") {
		t.Errorf("the live cgroup was not read: %v", record.calls)
	}
	// The file is rewritten once per device line, so the last device is what
	// remains on disk. The read bandwidth is set by the plan and is not cleared.
	data, err := os.ReadFile(ioMax)
	if err != nil {
		t.Fatalf("read io.max: %v", err)
	}
	if string(data) != "8:0 wbps=max riops=max wiops=max" {
		t.Errorf("io.max = %q, want the unset metrics cleared for the last device", data)
	}
}

// A plan that sets every metric has nothing to clear, and then the kernel is
// not touched at all.
func TestClearKernelIOLimitsAsksNothingWhenEveryMetricIsSet(t *testing.T) {
	record := recordCommands(t, func([]string) string { return "exit 0" })

	clearKernelIOLimits("c_site", Limits{IOReadMBps: 1, IOWriteMBps: 2, IOReadIOPS: 3, IOWriteIOPS: 4})

	if len(record.calls) != 0 {
		t.Errorf("commands = %v, want none", record.calls)
	}
}

// Without a live cgroup there is nothing to write to, and a missing io.max is
// the normal case for a slice that is not running.
func TestClearKernelIOLimitsStopsWhenTheCgroupIsNotThere(t *testing.T) {
	root := t.TempDir()
	setForTest(t, &cgroupRoot, root)

	t.Run("no control group reported", func(t *testing.T) {
		recordCommands(t, func([]string) string { return "printf ''" })
		clearKernelIOLimits("c_site", Limits{})
	})
	t.Run("no io.max file", func(t *testing.T) {
		recordCommands(t, func([]string) string { return "printf 'servika.slice/absent.slice'" })
		clearKernelIOLimits("c_site", Limits{})
	})
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read cgroup root: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("the cgroup root was written to: %v", entries)
	}
}

// The governor exists to stop one tenant's runaway query, so it must kill that
// query and nothing else: a query under its plan limit and an account the panel
// does not govern both stay running.
func TestGovernorScanKillsOnlyAGovernedQueryOverItsLimit(t *testing.T) {
	script := newScript()
	script.rows["FROM db_accounts a JOIN domains d"] = [][]driver.Value{{int64(5)}}
	listing := "17\tc_site_db\t9\n18\tc_site_db\t3\n19\troot\t120\nmalformed\n"
	record := recordCommands(t, func(argv []string) string {
		if strings.Contains(strings.Join(argv, " "), "PROCESSLIST") {
			return "printf '%s' '" + listing + "'"
		}
		return "exit 0"
	})

	governorScanOnce(context.Background(), scriptDB(t, script))

	if !record.contains("KILL QUERY 17") {
		t.Errorf("the query over its limit was not terminated: %v", record.calls)
	}
	for _, spared := range []string{"KILL QUERY 18", "KILL QUERY 19"} {
		if record.contains(spared) {
			t.Errorf("%q ran; only the query over its own plan limit may be terminated", spared)
		}
	}
}

// A kill the database refuses is reported with what MariaDB said, because the
// query then keeps running and the operator has to know it survived.
func TestGovernorScanReportsAKillItCouldNotRun(t *testing.T) {
	script := newScript()
	script.rows["FROM db_accounts a JOIN domains d"] = [][]driver.Value{{int64(5)}}
	messages := captureLog(t)
	recordCommands(t, func(argv []string) string {
		if strings.Contains(strings.Join(argv, " "), "PROCESSLIST") {
			return "printf '17\\tc_site_db\\t9\\n'"
		}
		return "echo 'access denied'; exit 1"
	})

	governorScanOnce(context.Background(), scriptDB(t, script))

	if !strings.Contains(messages.String(), "failed to terminate query for c_site_db") {
		t.Errorf("log = %q, want the refused kill reported", messages)
	}
}

// A domain without a plan keeps no enforcement: the tenant returns to the
// shared PHP-FPM service and its slice goes, but the default quota is still
// applied so nobody is left unlimited.
func TestApplyAllWithoutAPlanReturnsTheTenantToTheSharedService(t *testing.T) {
	script := newScript()
	script.rows["SELECT system_user, COALESCE(php_version,'8.3'), plan_id"] = [][]driver.Value{{"c_site", "8.4", nil}}

	var steps []string
	setForTest(t, &tenantFPMActive, func(string) bool { return true })
	setForTest(t, &rollbackToSharedFPM, func(_ *sql.DB, _ int64, user, php string) error {
		steps = append(steps, "rollback "+user+" "+php)
		return nil
	})
	setForTest(t, &deleteSlice, func(user string) error {
		steps = append(steps, "delete slice "+user)
		return nil
	})
	setForTest(t, &applyDomainQuota, func(context.Context, *sql.DB, int64) error {
		steps = append(steps, "quota")
		return nil
	})
	setForTest(t, &writeSlice, func(string, Limits) error {
		steps = append(steps, "write slice")
		return nil
	})

	if err := ApplyAll(context.Background(), scriptDB(t, script), 7); err != nil {
		t.Fatalf("ApplyAll() error = %v", err)
	}
	if strings.Join(steps, ", ") != "rollback c_site 8.4, delete slice c_site, quota" {
		t.Errorf("steps = %v, want the rollback, the slice removal and the default quota", steps)
	}
}

// A planned domain gets every limit, and the worker count the plan implies is
// stored for the pool renderer to read.
func TestApplyAllWithAPlanAppliesEveryLimit(t *testing.T) {
	script := newScript()
	script.rows["SELECT system_user, COALESCE(php_version,'8.3'), plan_id"] = [][]driver.Value{{"c_site", "8.3", int64(3)}}

	var steps []string
	setForTest(t, &planLimits, func(context.Context, *sql.DB, int64) (Limits, error) {
		return Limits{RAMMB: 1024}, nil
	})
	setForTest(t, &writeSlice, func(user string, l Limits) error {
		steps = append(steps, "slice "+user)
		return nil
	})
	setForTest(t, &enableTenantFPM, func(*sql.DB, int64, string, string) (string, error) {
		steps = append(steps, "tenant fpm")
		return "", nil
	})
	setForTest(t, &applyDomainQuota, func(context.Context, *sql.DB, int64) error {
		steps = append(steps, "quota")
		return nil
	})
	setForTest(t, &applyMySQLLimits, func(_ context.Context, _ *sql.DB, _ int64, l Limits) error {
		steps = append(steps, "mysql")
		return nil
	})

	if err := ApplyAll(context.Background(), scriptDB(t, script), 7); err != nil {
		t.Fatalf("ApplyAll() error = %v", err)
	}
	if strings.Join(steps, ", ") != "slice c_site, tenant fpm, quota, mysql" {
		t.Errorf("steps = %v, want the slice, the tenant service, the quota and the MariaDB limits", steps)
	}
	if len(script.execs) != 1 {
		t.Fatalf("statements = %v, want the stored worker limit", script.execs)
	}
	stored := script.execs[0]
	if !strings.Contains(stored.query, "INSERT INTO php_settings") {
		t.Errorf("statement = %q, want the PHP worker limit", stored.query)
	}
	// 1024 MB of RAM buys 16 workers at 64 MB each.
	if len(stored.args) != 2 || stored.args[1] != int64(16) {
		t.Errorf("arguments = %v, want the domain and 16 workers", stored.args)
	}
}

// A domain row without a system user names no tenant, and applying limits to
// nothing would report success it did not have.
func TestApplyAllRefusesADomainWithoutASystemUser(t *testing.T) {
	script := newScript()
	script.rows["SELECT system_user, COALESCE(php_version,'8.3'), plan_id"] = [][]driver.Value{{"", "8.3", int64(3)}}

	err := ApplyAll(context.Background(), scriptDB(t, script), 7)
	if err == nil || !strings.Contains(err.Error(), "system_user is empty") {
		t.Fatalf("error = %v, want one naming the empty system user", err)
	}
}

// The worker limit is what the pool renderer reads later, so a failure to store
// it is reported rather than logged and passed over.
func TestApplyAllFailsWhenTheWorkerLimitCannotBeStored(t *testing.T) {
	script := newScript()
	script.rows["SELECT system_user, COALESCE(php_version,'8.3'), plan_id"] = [][]driver.Value{{"c_site", "8.3", int64(3)}}
	script.fail["INSERT INTO php_settings"] = errScripted
	setForTest(t, &planLimits, func(context.Context, *sql.DB, int64) (Limits, error) { return Limits{}, nil })
	setForTest(t, &writeSlice, func(string, Limits) error { return nil })

	err := ApplyAll(context.Background(), scriptDB(t, script), 7)
	if err == nil || !strings.Contains(err.Error(), "store PHP-FPM worker limit") {
		t.Fatalf("error = %v, want one naming the worker limit", err)
	}
}

// healingDomains scripts the domain list tenant healing reads.
func healingDomains(t *testing.T, rows [][]driver.Value) *sql.DB {
	t.Helper()
	script := newScript()
	script.rows["SELECT id, system_user, COALESCE(php_version,'8.3'), domain_name"] = rows
	return scriptDB(t, script)
}

// A tenant that already runs its own service must not be restarted at boot: its
// limits are reasserted in place, because a restart would drop every request in
// flight for a site that is working.
func TestHealTenantFPMReassertsWithoutRestartingAnActiveTenant(t *testing.T) {
	db := healingDomains(t, [][]driver.Value{{int64(4), "c_site", "8.3", "site.test"}})
	captureLog(t)

	var steps []string
	setForTest(t, &tenantFPMActive, func(string) bool { return true })
	setForTest(t, &reassertLimits, func(context.Context, *sql.DB, int64) error {
		steps = append(steps, "reassert")
		return nil
	})
	setForTest(t, &applyAllLimits, func(context.Context, *sql.DB, int64) error {
		steps = append(steps, "apply all")
		return nil
	})
	setForTest(t, &probeHTTPS, func(string) int {
		steps = append(steps, "probe")
		return 200
	})

	HealTenantFPM(context.Background(), db)

	if strings.Join(steps, ", ") != "reassert" {
		t.Errorf("steps = %v, want the limits reasserted and nothing else", steps)
	}
}

// A cutover that turns a working site into a server error is undone: the tenant
// goes back to the shared service and its slice is removed.
func TestHealTenantFPMRollsBackACutoverThatBreaksTheSite(t *testing.T) {
	db := healingDomains(t, [][]driver.Value{{int64(4), "c_site", "8.3", "site.test"}})
	captureLog(t)
	setForTest(t, &cutoverSettle, time.Millisecond)

	probes := []int{200, 502}
	var steps []string
	setForTest(t, &tenantFPMActive, func(string) bool { return len(steps) > 0 })
	setForTest(t, &applyAllLimits, func(context.Context, *sql.DB, int64) error {
		steps = append(steps, "apply all")
		return nil
	})
	setForTest(t, &probeHTTPS, func(string) int {
		status := probes[0]
		if len(probes) > 1 {
			probes = probes[1:]
		}
		return status
	})
	setForTest(t, &serviceActive, func(string) bool { return true })
	setForTest(t, &rollbackToSharedFPM, func(*sql.DB, int64, string, string) error {
		steps = append(steps, "rollback")
		return nil
	})
	setForTest(t, &deleteSlice, func(string) error {
		steps = append(steps, "delete slice")
		return nil
	})

	HealTenantFPM(context.Background(), db)

	if strings.Join(steps, ", ") != "apply all, rollback, delete slice" {
		t.Errorf("steps = %v, want the cutover undone", steps)
	}
}

// Healing only manages tenants it created, and a row it cannot read is skipped
// rather than stopping the run for everybody behind it.
func TestHealTenantFPMSkipsWhatItCannotUse(t *testing.T) {
	db := healingDomains(t, [][]driver.Value{
		{"unreadable", "c_site", "8.3", "site.test"},
		{int64(5), "root", "8.3", "panel.test"},
		{int64(6), "", "8.3", "empty.test"},
	})
	messages := captureLog(t)

	touched := 0
	setForTest(t, &tenantFPMActive, func(string) bool {
		touched++
		return true
	})
	setForTest(t, &reassertLimits, func(context.Context, *sql.DB, int64) error { return nil })

	HealTenantFPM(context.Background(), db)

	if touched != 0 {
		t.Errorf("healing touched %d domains, want none of these three", touched)
	}
	if !strings.Contains(messages.String(), "skipped an unreadable domain row") {
		t.Errorf("log = %q, want the unreadable row reported", messages)
	}
}

// Quota that cannot be enforced is never half-applied: the run stops, and the
// sentinel tells the operator which of the two reasons it was.
func TestHealQuotaOnStartupStopsWhenQuotaCannotBeEnforced(t *testing.T) {
	cases := []struct {
		name       string
		compatible bool
		accounting bool
		wantWrite  bool
		wantLog    string
	}{
		{name: "the root filesystem is not XFS", wantLog: "not XFS"},
		{name: "enforcement is off", compatible: true, wantWrite: true, wantLog: "fs noquota"},
		{name: "accounting on without enforcement", compatible: true, accounting: true, wantWrite: true, wantLog: "uqnoenforce"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := newScript()
			script.rows["SELECT COUNT(*) FROM domains"] = [][]driver.Value{{int64(4)}}
			messages := captureLog(t)

			written, deleted, applied := false, false, false
			setForTest(t, &quotaFSCompatible, func() bool { return tc.compatible })
			setForTest(t, &quotaActive, func() (bool, bool) { return tc.accounting, false })
			setForTest(t, &sentinelWrite, func() { written = true })
			setForTest(t, &sentinelDelete, func() { deleted = true })
			setForTest(t, &applyDomainQuota, func(context.Context, *sql.DB, int64) error {
				applied = true
				return nil
			})

			HealQuotaOnStartup(context.Background(), scriptDB(t, script))

			if applied {
				t.Error("a quota was applied while enforcement was off")
			}
			if written != tc.wantWrite || deleted == tc.wantWrite {
				t.Errorf("sentinel written=%v deleted=%v, want written=%v", written, deleted, tc.wantWrite)
			}
			if !strings.Contains(messages.String(), tc.wantLog) || !strings.Contains(messages.String(), "4 skipped") {
				t.Errorf("log = %q, want %q and the tenant count", messages, tc.wantLog)
			}
		})
	}
}

// With enforcement active every tenant is re-asserted, the stale reboot warning
// goes, and one failing tenant is counted as skipped instead of ending the run.
func TestHealQuotaOnStartupAppliesEveryTenantAndCountsTheFailures(t *testing.T) {
	script := newScript()
	script.rows["SELECT id FROM domains"] = [][]driver.Value{{int64(1)}, {int64(2)}, {int64(3)}}
	messages := captureLog(t)

	deleted := false
	var seen []int64
	setForTest(t, &quotaFSCompatible, func() bool { return true })
	setForTest(t, &quotaActive, func() (bool, bool) { return true, true })
	setForTest(t, &sentinelDelete, func() { deleted = true })
	setForTest(t, &applyDomainQuota, func(_ context.Context, _ *sql.DB, id int64) error {
		seen = append(seen, id)
		if id == 2 {
			return errScripted
		}
		return nil
	})

	HealQuotaOnStartup(context.Background(), scriptDB(t, script))

	if len(seen) != 3 {
		t.Errorf("applied to %v, want all three tenants", seen)
	}
	if !deleted {
		t.Error("the stale reboot sentinel was left behind")
	}
	if !strings.Contains(messages.String(), "quota heal: 2 tenants / 1 skipped") {
		t.Errorf("log = %q, want two applied and one skipped", messages)
	}
}

// Each limit is applied independently, so one host failure is reported and the
// rest are still applied. Returning early would leave a domain with some of its
// plan enforced and no record of which part.
func TestApplyAllReportsEveryStepThatFailedAndStillFinishes(t *testing.T) {
	script := newScript()
	script.rows["SELECT system_user, COALESCE(php_version,'8.3'), plan_id"] = [][]driver.Value{{"c_site", "8.3", int64(3)}}
	messages := captureLog(t)

	setForTest(t, &planLimits, func(context.Context, *sql.DB, int64) (Limits, error) { return Limits{}, nil })
	setForTest(t, &writeSlice, func(string, Limits) error { return errScripted })
	setForTest(t, &enableTenantFPM, func(*sql.DB, int64, string, string) (string, error) { return "", errScripted })
	setForTest(t, &applyDomainQuota, func(context.Context, *sql.DB, int64) error { return errScripted })
	setForTest(t, &applyMySQLLimits, func(context.Context, *sql.DB, int64, Limits) error { return errScripted })

	if err := ApplyAll(context.Background(), scriptDB(t, script), 7); err != nil {
		t.Fatalf("ApplyAll() error = %v, want the failures reported rather than returned", err)
	}
	for _, want := range []string{
		"write slice c_site", "tenant PHP-FPM c_site", "xfs user-quota c_site", "mysql governor c_site",
	} {
		if !strings.Contains(messages.String(), want) {
			t.Errorf("log = %q, want it to name %q", messages, want)
		}
	}
}

// Nothing is applied from a plan that could not be read, and a rollback that
// fails is returned rather than logged: it leaves the tenant on a service that
// is going away.
func TestApplyAllStopsWhenItCannotReadOrRollBack(t *testing.T) {
	const domainQuery = "SELECT system_user, COALESCE(php_version,'8.3'), plan_id"

	t.Run("the domain row cannot be read", func(t *testing.T) {
		script := newScript()
		script.fail[domainQuery] = errScripted
		if err := ApplyAll(context.Background(), scriptDB(t, script), 7); err == nil {
			t.Fatal("ApplyAll() reported success for a domain it could not read")
		}
	})

	t.Run("the plan cannot be read", func(t *testing.T) {
		script := newScript()
		script.rows[domainQuery] = [][]driver.Value{{"c_site", "8.3", int64(3)}}
		setForTest(t, &planLimits, func(context.Context, *sql.DB, int64) (Limits, error) {
			return Limits{}, errScripted
		})
		applied := false
		setForTest(t, &writeSlice, func(string, Limits) error {
			applied = true
			return nil
		})
		if err := ApplyAll(context.Background(), scriptDB(t, script), 7); err == nil {
			t.Fatal("ApplyAll() reported success without a plan to apply")
		}
		if applied {
			t.Error("a slice was written from limits that could not be read")
		}
	})

	t.Run("the tenant cannot be returned to the shared service", func(t *testing.T) {
		script := newScript()
		script.rows[domainQuery] = [][]driver.Value{{"c_site", "8.3", nil}}
		setForTest(t, &tenantFPMActive, func(string) bool { return true })
		setForTest(t, &rollbackToSharedFPM, func(*sql.DB, int64, string, string) error { return errScripted })
		removed := false
		setForTest(t, &deleteSlice, func(string) error {
			removed = true
			return nil
		})
		err := ApplyAll(context.Background(), scriptDB(t, script), 7)
		if err == nil || !strings.Contains(err.Error(), "rollback tenant PHP-FPM") {
			t.Fatalf("error = %v, want one naming the rollback", err)
		}
		if removed {
			t.Error("the slice was removed while the tenant still runs its own service")
		}
	})
}

// A cutover that keeps the site up is kept, and nothing is rolled back.
func TestHealTenantFPMCompletesACutoverThatKeepsTheSiteUp(t *testing.T) {
	db := healingDomains(t, [][]driver.Value{{int64(4), "c_site", "8.3", "site.test"}})
	messages := captureLog(t)
	setForTest(t, &cutoverSettle, time.Millisecond)

	applied := false
	setForTest(t, &tenantFPMActive, func(string) bool { return applied })
	setForTest(t, &applyAllLimits, func(context.Context, *sql.DB, int64) error {
		applied = true
		return nil
	})
	setForTest(t, &probeHTTPS, func(string) int { return 200 })
	setForTest(t, &serviceActive, func(string) bool { return true })
	setForTest(t, &rollbackToSharedFPM, func(*sql.DB, int64, string, string) error {
		t.Error("a healthy cutover was rolled back")
		return nil
	})

	HealTenantFPM(context.Background(), db)

	if !strings.Contains(messages.String(), "completed cutover for c_site") {
		t.Errorf("log = %q, want the cutover recorded", messages)
	}
}

// When the tenant service does not come up at all there is nothing to roll
// back: the domain stays on the shared service, and that is said out loud.
func TestHealTenantFPMLeavesATenantOnTheSharedServiceWhenTheCutoverDoesNotTake(t *testing.T) {
	db := healingDomains(t, [][]driver.Value{{int64(4), "c_site", "8.3", "site.test"}})
	messages := captureLog(t)

	setForTest(t, &tenantFPMActive, func(string) bool { return false })
	setForTest(t, &applyAllLimits, func(context.Context, *sql.DB, int64) error { return errScripted })
	setForTest(t, &probeHTTPS, func(string) int { return 200 })
	setForTest(t, &serviceActive, func(string) bool {
		t.Error("a service that never started was probed")
		return false
	})

	HealTenantFPM(context.Background(), db)

	if !strings.Contains(messages.String(), "failed to apply limits for c_site") {
		t.Errorf("log = %q, want the failed apply reported", messages)
	}
	if !strings.Contains(messages.String(), "left c_site on the shared service") {
		t.Errorf("log = %q, want the tenant reported as left behind", messages)
	}
}

// Healing runs at boot in the background, so a database it cannot read stops it
// quietly rather than taking the panel down with it.
func TestHealTenantFPMStopsWhenItCannotListDomains(t *testing.T) {
	messages := captureLog(t)
	setForTest(t, &tenantFPMActive, func(string) bool {
		t.Error("healing continued without a domain list")
		return false
	})

	HealTenantFPM(context.Background(), nil)

	script := newScript()
	script.fail["SELECT id, system_user, COALESCE(php_version,'8.3'), domain_name"] = errScripted
	HealTenantFPM(context.Background(), scriptDB(t, script))

	if !strings.Contains(messages.String(), "could not list domains") {
		t.Errorf("log = %q, want the unreadable domain list reported", messages)
	}
}

// Every failure inside the run is named, and a cancelled boot stops between
// domains rather than in the middle of one tenant's cutover.
func TestHealTenantFPMReportsWhatItCouldNotFinish(t *testing.T) {
	t.Run("the domain list ends in an error", func(t *testing.T) {
		messages := captureLog(t)
		script := newScript()
		const listQuery = "SELECT id, system_user, COALESCE(php_version,'8.3'), domain_name"
		script.rows[listQuery] = [][]driver.Value{{int64(4), "c_site", "8.3", "site.test"}}
		script.endWith[listQuery] = errScripted
		setForTest(t, &tenantFPMActive, func(string) bool {
			t.Error("healing continued on a list it could not finish reading")
			return false
		})

		HealTenantFPM(context.Background(), scriptDB(t, script))

		if !strings.Contains(messages.String(), "stopped while reading domains") {
			t.Errorf("log = %q, want the truncated list reported", messages)
		}
	})

	t.Run("an active tenant cannot be reasserted", func(t *testing.T) {
		messages := captureLog(t)
		db := healingDomains(t, [][]driver.Value{{int64(4), "c_site", "8.3", "site.test"}})
		setForTest(t, &tenantFPMActive, func(string) bool { return true })
		setForTest(t, &reassertLimits, func(context.Context, *sql.DB, int64) error { return errScripted })

		HealTenantFPM(context.Background(), db)

		if !strings.Contains(messages.String(), "failed to reassert limits for c_site") {
			t.Errorf("log = %q, want the failed reassert reported", messages)
		}
	})

	t.Run("a rollback fails", func(t *testing.T) {
		messages := captureLog(t)
		db := healingDomains(t, [][]driver.Value{{int64(4), "c_site", "8.3", "site.test"}})
		setForTest(t, &cutoverSettle, time.Millisecond)
		applied := false
		setForTest(t, &tenantFPMActive, func(string) bool { return applied })
		setForTest(t, &applyAllLimits, func(context.Context, *sql.DB, int64) error {
			applied = true
			return nil
		})
		setForTest(t, &probeHTTPS, func(string) int { return 200 })
		setForTest(t, &serviceActive, func(string) bool { return false })
		setForTest(t, &rollbackToSharedFPM, func(*sql.DB, int64, string, string) error { return errScripted })
		removed := false
		setForTest(t, &deleteSlice, func(string) error {
			removed = true
			return nil
		})

		HealTenantFPM(context.Background(), db)

		if !strings.Contains(messages.String(), "rollback failed for c_site") {
			t.Errorf("log = %q, want the failed rollback reported", messages)
		}
		if !removed {
			t.Error("the slice was left behind after a failed rollback")
		}
	})

	t.Run("the boot is cancelled part way through", func(t *testing.T) {
		messages := captureLog(t)
		db := healingDomains(t, [][]driver.Value{
			{int64(4), "c_site", "8.3", "site.test"},
			{int64(5), "c_other", "8.3", "other.test"},
		})
		ctx, cancel := context.WithCancel(context.Background())
		var seen []string
		setForTest(t, &tenantFPMActive, func(user string) bool {
			seen = append(seen, user)
			cancel()
			return true
		})
		setForTest(t, &reassertLimits, func(context.Context, *sql.DB, int64) error { return nil })

		HealTenantFPM(ctx, db)

		if strings.Join(seen, ",") != "c_site" {
			t.Errorf("healed %v, want the run to stop at the cancellation", seen)
		}
		if !strings.Contains(messages.String(), "canceled: migrated=0 active=1") {
			t.Errorf("log = %q, want the cancelled run reported with its counts", messages)
		}
	})
}

// The quota run is a boot task too: an unreadable list stops it, a single
// unreadable id is skipped, and a cancelled boot stops between tenants.
func TestHealQuotaOnStartupSurvivesWhatItCannotRead(t *testing.T) {
	setForTest(t, &quotaFSCompatible, func() bool { return true })
	setForTest(t, &quotaActive, func() (bool, bool) { return true, true })
	setForTest(t, &sentinelDelete, func() {})

	t.Run("no database", func(t *testing.T) {
		setForTest(t, &quotaFSCompatible, func() bool {
			t.Error("healing looked at the filesystem without a database")
			return true
		})
		HealQuotaOnStartup(context.Background(), nil)
	})

	t.Run("the tenant list cannot be read", func(t *testing.T) {
		messages := captureLog(t)
		script := newScript()
		script.fail["SELECT id FROM domains"] = errScripted
		HealQuotaOnStartup(context.Background(), scriptDB(t, script))
		if !strings.Contains(messages.String(), "could not read domain list") {
			t.Errorf("log = %q, want the unreadable list reported", messages)
		}
	})

	t.Run("one tenant id cannot be read", func(t *testing.T) {
		messages := captureLog(t)
		script := newScript()
		script.rows["SELECT id FROM domains"] = [][]driver.Value{{"unreadable"}, {int64(2)}}
		var seen []int64
		setForTest(t, &applyDomainQuota, func(_ context.Context, _ *sql.DB, id int64) error {
			seen = append(seen, id)
			return nil
		})
		HealQuotaOnStartup(context.Background(), scriptDB(t, script))
		if len(seen) != 1 || seen[0] != 2 {
			t.Errorf("applied to %v, want only the tenant that could be read", seen)
		}
		if !strings.Contains(messages.String(), "skipping an unreadable tenant id") {
			t.Errorf("log = %q, want the skipped id reported", messages)
		}
	})

	t.Run("the boot is cancelled part way through", func(t *testing.T) {
		messages := captureLog(t)
		script := newScript()
		script.rows["SELECT id FROM domains"] = [][]driver.Value{{int64(1)}, {int64(2)}}
		ctx, cancel := context.WithCancel(context.Background())
		var seen []int64
		setForTest(t, &applyDomainQuota, func(_ context.Context, _ *sql.DB, id int64) error {
			seen = append(seen, id)
			cancel()
			return nil
		})

		HealQuotaOnStartup(ctx, scriptDB(t, script))

		if len(seen) != 1 {
			t.Errorf("applied to %v, want the run to stop at the cancellation", seen)
		}
		if !strings.Contains(messages.String(), "cancelled (ctx) — 1 tenants / 0 skipped") {
			t.Errorf("log = %q, want the cancelled run reported with its counts", messages)
		}
	})
}
