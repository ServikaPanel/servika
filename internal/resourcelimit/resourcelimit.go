// Package resourcelimit applies per-domain cgroup, XFS quota, and MariaDB limits.
// Limits are loaded from the domain's assigned plan and enforced at the system level.
package resourcelimit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"servika/internal/provisioner"

	"golang.org/x/sys/unix"
)

// Limits contains active resource values loaded from a service plan.
type Limits struct {
	CPUPercent          int
	RAMMB               int
	MaxProcess          int
	InodeQuota          int
	IOWeight            int
	MySQLMaxConnections int
	DiskQuotaMB         int
	PMMaxChildren       int
	IOReadMBps          int
	IOWriteMBps         int
	IOReadIOPS          int
	IOWriteIOPS         int
	DBMaxQueriesPerHour int
	DBMaxUpdatesPerHour int
	DBMaxQuerySeconds   int
}

// GetPlanLimits returns limits from the domain's assigned plan.
// An unassigned plan returns zero values, which remove enforcement.
func GetPlanLimits(ctx context.Context, db *sql.DB, domainID int64) (Limits, error) {
	var l Limits
	err := db.QueryRowContext(ctx, `
		SELECT COALESCE(p.cpu_percent,0), COALESCE(p.ram_mb,0),
		       COALESCE(p.max_process,0), COALESCE(p.inode_quota,0),
		       COALESCE(p.io_weight,100), COALESCE(p.mysql_max_connections,0),
		       COALESCE(p.disk_quota_mb,0), COALESCE(p.pm_max_children,0),
		       COALESCE(p.io_read_mbps,0), COALESCE(p.io_write_mbps,0),
		       COALESCE(p.io_read_iops,0), COALESCE(p.io_write_iops,0),
		       COALESCE(p.db_max_queries_per_hour,0), COALESCE(p.db_max_updates_per_hour,0),
		       COALESCE(p.db_max_query_seconds,0)
		FROM domains d LEFT JOIN service_plans p ON p.id=d.plan_id
		WHERE d.id=?`, domainID).
		Scan(&l.CPUPercent, &l.RAMMB, &l.MaxProcess, &l.InodeQuota,
			&l.IOWeight, &l.MySQLMaxConnections, &l.DiskQuotaMB, &l.PMMaxChildren,
			&l.IOReadMBps, &l.IOWriteMBps, &l.IOReadIOPS, &l.IOWriteIOPS,
			&l.DBMaxQueriesPerHour, &l.DBMaxUpdatesPerHour, &l.DBMaxQuerySeconds)
	return l, err
}

const (
	sliceDir     = "/etc/systemd/system"
	ioDevicePath = "/home"
)

func calculatePMMaxChildren(l Limits) int {
	if l.PMMaxChildren > 0 {
		return l.PMMaxChildren
	}
	if l.RAMMB > 0 {
		return max(4, l.RAMMB/64)
	}
	return 8
}

func resourceCommand(name string, args ...string) *exec.Cmd {
	return resourceCommandContext(context.Background(), name, args...)
}

// resourceCommandContext is a variable so a test can substitute a command that
// actually hangs, which is the only way to prove a deadline takes effect.
var resourceCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
	}
	return command
}

func sliceName(systemUser string) string {
	// systemd slice, for example servika-c_registry_persistent_test_local.slice.
	return "servika-" + systemUser + ".slice"
}

func slicePath(systemUser string) string {
	return filepath.Join(sliceDir, sliceName(systemUser))
}

// WriteSystemdSlice writes /etc/systemd/system/servika-<system-user>.slice with cgroup v2
// CPUQuota, MemoryMax, TasksMax, IOWeight, and optional absolute disk I/O limits.
func WriteSystemdSlice(systemUser string, l Limits) error {
	content := fmt.Sprintf(`# Servika per-domain resource slice: %s
[Unit]
Description=Servika panel slice for %s
Before=slices.target

[Slice]
CPUAccounting=yes
MemoryAccounting=yes
TasksAccounting=yes
IOAccounting=yes

CPUQuota=%d%%
MemoryMax=%dM
MemoryHigh=%dM
TasksMax=%d
IOWeight=%d
%s`, systemUser, systemUser,
		nonzero(l.CPUPercent, 100),
		nonzero(l.RAMMB, 512),
		nonzero(l.RAMMB, 512)*90/100, // MemoryHigh = 90% of Max (soft throttle)
		nonzero(l.MaxProcess, 50),
		nonzero(l.IOWeight, 100),
		ioSliceLines(l))

	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(slicePath(systemUser), []byte(content), 0644); err != nil {
		return fmt.Errorf("write slice: %w", err)
	}
	if out, err := resourceCommand("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("daemon-reload: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if err := resourceCommand("systemctl", "is-active", "--quiet", sliceName(systemUser)).Run(); err == nil {
		properties := []string{
			"set-property", "--runtime", sliceName(systemUser),
			fmt.Sprintf("CPUQuota=%d%%", nonzero(l.CPUPercent, 100)),
			fmt.Sprintf("MemoryMax=%dM", nonzero(l.RAMMB, 512)),
			fmt.Sprintf("MemoryHigh=%dM", nonzero(l.RAMMB, 512)*90/100),
			fmt.Sprintf("TasksMax=%d", nonzero(l.MaxProcess, 50)),
			fmt.Sprintf("IOWeight=%d", nonzero(l.IOWeight, 100)),
		}
		properties = append(properties, ioSetPropertyArgs(l)...)
		if out, err := resourceCommand("systemctl", properties...).CombinedOutput(); err != nil {
			return fmt.Errorf("update active slice: %s: %w", strings.TrimSpace(string(out)), err)
		}
		clearKernelIOLimits(systemUser, l)
	}
	return nil
}

func ioSliceLines(l Limits) string {
	var lines strings.Builder
	if l.IOReadMBps > 0 {
		fmt.Fprintf(&lines, "IOReadBandwidthMax=%s %dM\n", ioDevicePath, l.IOReadMBps)
	}
	if l.IOWriteMBps > 0 {
		fmt.Fprintf(&lines, "IOWriteBandwidthMax=%s %dM\n", ioDevicePath, l.IOWriteMBps)
	}
	if l.IOReadIOPS > 0 {
		fmt.Fprintf(&lines, "IOReadIOPSMax=%s %d\n", ioDevicePath, l.IOReadIOPS)
	}
	if l.IOWriteIOPS > 0 {
		fmt.Fprintf(&lines, "IOWriteIOPSMax=%s %d\n", ioDevicePath, l.IOWriteIOPS)
	}
	return lines.String()
}

func ioSetPropertyArgs(l Limits) []string {
	argument := func(property string, value int, bandwidth bool) string {
		if value <= 0 {
			return property + "="
		}
		if bandwidth {
			return fmt.Sprintf("%s=%s %dM", property, ioDevicePath, value)
		}
		return fmt.Sprintf("%s=%s %d", property, ioDevicePath, value)
	}
	return []string{
		argument("IOReadBandwidthMax", l.IOReadMBps, true),
		argument("IOWriteBandwidthMax", l.IOWriteMBps, true),
		argument("IOReadIOPSMax", l.IOReadIOPS, false),
		argument("IOWriteIOPSMax", l.IOWriteIOPS, false),
	}
}

// clearKernelIOLimits removes stale live limits that systemd empty assignments may retain.
func clearKernelIOLimits(systemUser string, l Limits) {
	clears := make([]string, 0, 4)
	if l.IOReadMBps <= 0 {
		clears = append(clears, "rbps=max")
	}
	if l.IOWriteMBps <= 0 {
		clears = append(clears, "wbps=max")
	}
	if l.IOReadIOPS <= 0 {
		clears = append(clears, "riops=max")
	}
	if l.IOWriteIOPS <= 0 {
		clears = append(clears, "wiops=max")
	}
	if len(clears) == 0 {
		return
	}

	output, err := resourceCommand(
		"systemctl", "show", sliceName(systemUser), "-p", "ControlGroup", "--value",
	).Output()
	controlGroup := strings.TrimSpace(string(output))
	if err != nil || controlGroup == "" {
		return
	}
	ioMaxPath := filepath.Join(cgroupRoot, controlGroup, "io.max")
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	data, err := os.ReadFile(ioMaxPath)
	if err != nil {
		return
	}
	suffix := " " + strings.Join(clears, " ")
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
		_ = os.WriteFile(ioMaxPath, []byte(fields[0]+suffix), 0644)
	}
}

// DeleteSystemdSlice removes the systemd slice and tears down its live state.
//
// Removing only the unit file is not enough: a running slice stays "loaded
// active", keeping its cgroup and any `systemctl set-property --runtime`
// drop-ins alive, so the old CPU/Memory/IO limits keep enforcing after the plan
// was removed. Stop the slice, delete the runtime drop-in directory, then remove
// the unit file, daemon-reload, and reset-failed so no stale state lingers.
func DeleteSystemdSlice(systemUser string) error {
	if systemUser == "" || !strings.HasPrefix(systemUser, "c_") {
		return nil // safety: only tenant (c_) slices are managed here
	}
	unit := sliceName(systemUser)
	// Stop first so the cgroup is released before the unit file disappears.
	_, _ = resourceCommand("systemctl", "stop", unit).CombinedOutput()
	// Transient drop-ins written by set-property --runtime live under /run.
	_ = os.RemoveAll("/run/systemd/system.control/" + unit + ".d")
	// A swallowed removal leaves the old slice enforcing stale CPU/Memory/IO limits
	// after the plan was removed; return the error so the caller can react.
	if p := slicePath(systemUser); p != "" {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove slice %s: %w", p, err)
		}
	}
	if out, err := resourceCommand("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("daemon-reload after slice removal: %v: %s", err, strings.TrimSpace(string(out)))
	}
	_, _ = resourceCommand("systemctl", "reset-failed", unit).CombinedOutput()
	return nil
}

// ── XFS USER quota (CloudLinux disk + inode parity) ──────────────────────────
// Tenant homes (/home/c_<sk>) may NOT be on a separate mount (both production servers
// have /home on the root XFS /dev/vdaN / /dev/sdaN). XFS *user* quota is applied to
// the tenant user (c_<sk>) on the root mount. Files are owned c_<sk>:c_<sk> so user
// quota maps exactly; tenants cannot chown, providing escape protection. The previous
// PROJECT-quota approach (/home separate mount + pquota) does not work on this
// infrastructure and is replaced by user-quota.
//
// The root XFS quota can only be enabled at MOUNT time; live remount cannot activate it.
// GRUB `rootflags=uquota` + a single reboot IS required (installer/update script writes it).
// When quota is INACTIVE on the filesystem (noquota, reboot pending) ALL quota operations
// are SILENTLY skipped — never a hard failure (otherwise tenant create would break).

// quotaMount is the mount point where XFS user quota is enforced.
// /home is not a separate mount, so the root is used.
const quotaMount = "/"

const xfsSuperMagic = 0x58465342

// QuotaFSCompatible reports whether the quota mount uses XFS.
// If Statfs fails, it returns true so transient host read errors do not raise a false warning.
func QuotaFSCompatible() bool {
	var st unix.Statfs_t
	if err := unix.Statfs(quotaMount, &st); err != nil {
		return true
	}
	return int64(st.Type) == xfsSuperMagic
}

// Plan-less tenant defaults (CloudLinux parity — don't leave unlimited).
const (
	defaultDiskMB = 5120   // 5 GB
	defaultInode  = 500000 // 500k files+dirs
)

// reQuotaSK validates the system user allowlist.
// provisioner.SlugFromDomain produces "c_" + [a-z0-9_].
// Only values passing this regex reach xfs_quota arg slices — shell/arg injection is closed.
var reQuotaSK = regexp.MustCompile(`^c_[a-z0-9_]{1,60}$`)

// mountQuotaActive checks whether XFS user quota accounting/enforcement is on for the root
// filesystem. It parses `xfs_quota -x -c 'state -u' /`; when noquota the output is empty
// and both return false.
func mountQuotaActive() (accounting, enforcement bool) {
	out, err := resourceCommand("xfs_quota", "-x", "-c", "state -u", quotaMount).CombinedOutput()
	if err != nil {
		return false, false
	}
	for ln := range strings.SplitSeq(string(out), "\n") {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "Accounting:"):
			accounting = strings.Contains(t, "ON")
		case strings.HasPrefix(t, "Enforcement:"):
			enforcement = strings.Contains(t, "ON")
		}
	}
	return accounting, enforcement
}

// ── Quota visibility sentinel ───────────────────────────────────────────────
// When XFS user-quota enforcement is INACTIVE (noquota → single reboot pending;
// or uqnoenforce → accounting on / enforcement off), ALL quota operations silently
// no-op. So the operator doesn't assume "quota is active", HealQuotaOnStartup WRITES
// this sentinel at boot; it DELETES it when enforcement is active. The status
// endpoint reads it and drops a quota-reboot-required flag into the UI.
const quotaSentinelDir = "/etc/servika"
const quotaRebootSentinel = quotaSentinelDir + "/reboot-required-quota"

// quotaSentinelWrite writes the reboot-required sentinel idempotently. Fixed path;
// os.WriteFile = O_WRONLY|O_CREATE|O_TRUNC, 0644, root. Content = description +
// RFC3339 timestamp.
func quotaSentinelWrite() {
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(quotaSentinelDir, 0755); err != nil {
		log.Printf("quota sentinel: could not create directory (%s): %v", quotaSentinelDir, err)
		return
	}
	body := "disk quota inactive — rootflags=uquota + reboot required\n" +
		time.Now().Format(time.RFC3339) + "\n"
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(quotaRebootSentinel, []byte(body), 0644); err != nil {
		log.Printf("quota sentinel write failed (%s): %v", quotaRebootSentinel, err)
	}
}

// quotaSentinelDelete removes the stale reboot warning after enforcement becomes
// active (post-reboot). If the file doesn't exist it is a no-op (idempotent).
func quotaSentinelDelete() {
	if err := os.Remove(quotaRebootSentinel); err != nil && !os.IsNotExist(err) {
		log.Printf("quota sentinel delete failed (%s): %v", quotaRebootSentinel, err)
	}
}

// QuotaRebootRequired reports whether disk quota enforcement is INACTIVE on a compatible
// XFS quota mount. Checks the sentinel file first (HealQuotaOnStartup writes it at
// boot) to avoid exec; falls back to live XFS enforcement check. The status endpoint
// uses this to feed the quota_reboot_required UI flag.
func QuotaRebootRequired() bool {
	if !QuotaFSCompatible() {
		return false
	}
	if _, err := os.Stat(quotaRebootSentinel); err == nil {
		return true
	}
	_, enf := mountQuotaActive()
	return !enf
}

// quotaLimitArgs builds the arg slice for xfs_quota (safe — testable without shell).
// soft is set to hard * 0.95. diskMB or inode of 0 means "0" = UNLIMITED for that metric
// (xfs_quota bhard/ihard=0 → no limit). sk must already pass reQuotaSK before calling.
func quotaLimitArgs(sk string, diskMB, inode int) []string {
	if diskMB < 0 {
		diskMB = 0
	}
	if inode < 0 {
		inode = 0
	}
	diskSoft := diskMB * 95 / 100
	inodeSoft := inode * 95 / 100
	limit := fmt.Sprintf("limit -u bsoft=%dm bhard=%dm isoft=%d ihard=%d %s",
		diskSoft, diskMB, inodeSoft, inode, sk)
	return []string{"-x", "-c", limit, quotaMount}
}

// ApplyQuota enforces XFS user disk+inode quota for a tenant (c_<sk>).
// When the filesystem quota is INACTIVE (noquota — reboot pending) it logs and returns nil
// (NEVER an error). diskMB/inode of 0 leaves that metric unlimited. The command is called
// with an arg slice (no shell); sk passes the allowlist (reQuotaSK) — no injection possible.
func ApplyQuota(ctx context.Context, sk string, diskMB, inode int) error {
	if !reQuotaSK.MatchString(sk) {
		return fmt.Errorf("quota: invalid system user format: %q", sk)
	}
	if acc, enf := mountQuotaActive(); !enf {
		// enforcement off → don't write limits (they won't be enforced).
		// When acc is on this is the uqnoenforce case.
		if acc {
			log.Printf("quota: XFS quota accounting is on but enforcement is OFF (uqnoenforce?) — limits NOT enforced, skipping %s", sk)
		} else {
			log.Printf("quota: inactive on filesystem (noquota) — single reboot required, skipping %s", sk)
		}
		return nil
	}
	home := "/home/" + sk
	if _, err := os.Stat(home); os.IsNotExist(err) {
		return nil // not yet provisioned — skip silently
	}
	// Ensure the user actually exists and has a non-zero UID.
	uidOut, err := resourceCommand("id", "-u", sk).Output()
	if err != nil {
		return nil
	}
	if uid := strings.TrimSpace(string(uidOut)); uid == "" || uid == "0" {
		return fmt.Errorf("quota: %s has invalid uid (%q)", sk, uid)
	}
	if out, e := resourceCommandContext(ctx, "xfs_quota", quotaLimitArgs(sk, diskMB, inode)...).CombinedOutput(); e != nil {
		return fmt.Errorf("xfs_quota limit %s: %s: %w", sk, strings.TrimSpace(string(out)), e)
	}
	log.Printf("quota applied: %s disk=%dMB inode=%d", sk, diskMB, inode)
	return nil
}

// effectiveQuota resolves the effective quota: domain override (>0) > plan value >
// (no plan) default. When a plan IS assigned the plan value is used (0 = explicitly
// unlimited per plan); when no plan exists a reasonable default is applied (CloudLinux
// parity). Domain override beats both.
func effectiveQuota(diskOverride, inodeOverride int, planAssigned bool, planDisk, planInode int) (int, int) {
	disk, inode := defaultDiskMB, defaultInode
	if planAssigned {
		disk, inode = planDisk, planInode
	}
	if diskOverride > 0 {
		disk = diskOverride
	}
	if inodeOverride > 0 {
		inode = inodeOverride
	}
	return disk, inode
}

// DomainQuotaApply resolves the effective quota (override > plan > default) for a domain
// and calls ApplyQuota. Used by create + plan-change hooks (ApplyAll / ReassertLimits) and
// HealQuotaOnStartup — this is the single resolution source.
func DomainQuotaApply(ctx context.Context, db *sql.DB, domainID int64) error {
	var sk string
	var dDisk, dInode int
	var planID sql.NullInt64
	var pDisk, pInode int
	err := db.QueryRowContext(ctx, `
		SELECT d.system_user,
		       COALESCE(d.disk_quota_mb,0), COALESCE(d.inode_quota,0),
		       d.plan_id,
		       COALESCE(p.disk_quota_mb,0), COALESCE(p.inode_quota,0)
		FROM domains d LEFT JOIN service_plans p ON p.id=d.plan_id
		WHERE d.id=?`, domainID).
		Scan(&sk, &dDisk, &dInode, &planID, &pDisk, &pInode)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(sk, "c_") {
		return nil // admin / invalid system user — don't touch
	}
	disk, inode := effectiveQuota(dDisk, dInode, planID.Valid, pDisk, pInode)
	return ApplyQuota(ctx, sk, disk, inode)
}

// quotaReportRow returns the Used and Hard fields from a `xfs_quota report -u -N <metric> /`
// output line matching sk. The block metric returns KB; the inode metric returns count.
// Output format: User Used Soft Hard [grace...].
func quotaReportRow(metric, sk string) (used, hard int) {
	out, err := resourceCommand("xfs_quota", "-x", "-c", "report -u -N "+metric, quotaMount).CombinedOutput()
	if err != nil {
		return 0, 0
	}
	for ln := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 || f[0] != sk {
			continue
		}
		used, _ = strconv.Atoi(f[1])
		hard, _ = strconv.Atoi(f[3])
		return used, hard
	}
	return 0, 0
}

// QuotaStatus returns the live disk (MB) / inode usage and limits from xfs_quota for a
// tenant (UI consumption). When quota is inactive or sk invalid all values return 0.
func QuotaStatus(sk string) (usedMB, limitMB, usedInode, limitInode int) {
	if !reQuotaSK.MatchString(sk) {
		return 0, 0, 0, 0
	}
	if acc, enf := mountQuotaActive(); !enf {
		// enforcement off → limits aren't enforced; don't report usage/limit (return 0).
		if acc {
			log.Printf("quota status: XFS quota accounting is on but enforcement is OFF (uqnoenforce?) — limits NOT enforced")
		}
		return 0, 0, 0, 0
	}
	bUsedKB, bHardKB := quotaReportRow("-b", sk) // KB
	iUsed, iHard := quotaReportRow("-i", sk)     // count
	return bUsedKB / 1024, bHardKB / 1024, iUsed, iHard
}

var (
	mysqlAccountPattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	mysqlHostPattern    = regexp.MustCompile(`^[A-Za-z0-9_.%\-]{1,64}$`)
	protectedMySQLUsers = map[string]bool{
		"root": true, "mysql": true, "mariadb.sys": true, "panel": true,
		"event_scheduler": true, "debian-sys-maint": true, "replication": true,
		"repl": true, "healthcheck": true, "": true,
	}
)

func governedMySQLAccount(user string) bool {
	return mysqlAccountPattern.MatchString(user) && !protectedMySQLUsers[strings.ToLower(user)]
}

func nonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func mysqlLimitSQL(user, host string, l Limits) (string, error) {
	if !governedMySQLAccount(user) {
		return "", fmt.Errorf("invalid or protected MySQL username")
	}
	if !mysqlHostPattern.MatchString(host) {
		return "", fmt.Errorf("invalid MySQL host")
	}
	return fmt.Sprintf(
		"ALTER USER '%s'@'%s' WITH MAX_USER_CONNECTIONS %d MAX_QUERIES_PER_HOUR %d MAX_UPDATES_PER_HOUR %d;",
		user, host, nonNegative(l.MySQLMaxConnections), nonNegative(l.DBMaxQueriesPerHour),
		nonNegative(l.DBMaxUpdatesPerHour)), nil
}

func parseMySQLAccountHosts(output string) map[string][]string {
	hosts := make(map[string][]string)
	for line := range strings.SplitSeq(strings.TrimSpace(output), "\n") {
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) != 2 {
			continue
		}
		user := strings.TrimSpace(fields[0])
		host := strings.TrimSpace(fields[1])
		if user != "" && host != "" {
			hosts[user] = append(hosts[user], host)
		}
	}
	return hosts
}

func mysqlAccountHosts(ctx context.Context) (map[string][]string, error) {
	command := resourceCommandContext(ctx, "mysql", "-uroot", "-N", "-B", "-e",
		"SELECT User,Host FROM mysql.user")
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list MariaDB account hosts: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return parseMySQLAccountHosts(string(output)), nil
}

func mysqlLimitStatements(users []string, accountHosts map[string][]string, l Limits) []string {
	var statements []string
	for _, user := range users {
		if !governedMySQLAccount(user) {
			log.Printf("mysql governor skipped account %q: invalid or protected username", user)
			continue
		}
		hosts := accountHosts[user]
		if len(hosts) == 0 {
			log.Printf("mysql governor skipped account %q: no MariaDB host found", user)
			continue
		}
		for _, host := range hosts {
			statement, err := mysqlLimitSQL(user, host, l)
			if err != nil {
				log.Printf("mysql governor skipped account %q at host %q: %v", user, host, err)
				continue
			}
			statements = append(statements, statement)
		}
	}
	return statements
}

// ApplyMySQLLimits applies native MariaDB limits to every host of each database account owned by a domain.
func ApplyMySQLLimits(ctx context.Context, db *sql.DB, domainID int64, l Limits) error {
	rows, err := db.QueryContext(ctx, `SELECT db_user FROM db_accounts WHERE domain_id=?`, domainID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	var users []string
	for rows.Next() {
		var user string
		if err := rows.Scan(&user); err != nil {
			return err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(users) == 0 {
		return nil
	}

	accountHosts, err := mysqlAccountHosts(ctx)
	if err != nil {
		return err
	}
	statements := mysqlLimitStatements(users, accountHosts, l)
	if len(statements) == 0 {
		return nil
	}
	statements = append(statements, "FLUSH USER_RESOURCES;")
	command := resourceCommandContext(ctx, "mysql", "-uroot", "-e", strings.Join(statements, ""))
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("mysql governor: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

const governorPollInterval = 5 * time.Second

// SlowQueryWatchdog terminates tenant queries that exceed their plan duration limit.
func SlowQueryWatchdog(ctx context.Context, db *sql.DB) {
	if db == nil {
		return
	}
	ticker := time.NewTicker(governorPollInterval)
	defer ticker.Stop()
	log.Printf("MySQL governor slow-query watchdog started with interval %s", governorPollInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			governorScanOnce(ctx, db)
		}
	}
}

func queryExceedsLimit(seconds, limit int) bool {
	return limit > 0 && seconds > limit
}

// governorScanKillTimeout bounds each mysql call the scan makes. The context main
// passes in is never cancelled, so without a deadline of its own a single hung
// mysql client blocks the scan, and the scan runs inline on the watchdog's ticker,
// which means the guard against runaway queries stops running exactly when the
// database is in the trouble it exists to catch. It is well under the 5-second
// poll interval so a stuck call cannot pile up behind the next tick.
const governorScanTimeout = 3 * time.Second

func governorScanOnce(ctx context.Context, db *sql.DB) {
	ctx, cancel := context.WithTimeout(ctx, governorScanTimeout)
	defer cancel()
	output, err := resourceCommandContext(ctx, "mysql", "-uroot", "-N", "-B", "-e",
		"SELECT ID,USER,TIME FROM information_schema.PROCESSLIST WHERE COMMAND<>'Sleep' AND TIME>0").Output()
	if err != nil {
		return
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		queryID, idErr := strconv.Atoi(strings.TrimSpace(fields[0]))
		user := strings.TrimSpace(fields[1])
		seconds, secondsErr := strconv.Atoi(strings.TrimSpace(fields[2]))
		if idErr != nil || secondsErr != nil || seconds <= 0 || !governedMySQLAccount(user) {
			continue
		}

		var limit int
		err := db.QueryRowContext(ctx,
			`SELECT COALESCE(p.db_max_query_seconds,0)
			 FROM db_accounts a JOIN domains d ON d.id=a.domain_id
			 LEFT JOIN service_plans p ON p.id=d.plan_id
			 WHERE a.db_user=? LIMIT 1`, user).Scan(&limit)
		if err != nil || !queryExceedsLimit(seconds, limit) {
			continue
		}
		killOutput, killErr := resourceCommandContext(ctx, "mysql", "-uroot", "-e",
			fmt.Sprintf("KILL QUERY %d", queryID)).CombinedOutput()
		if killErr != nil {
			log.Printf("MySQL governor failed to terminate query for %s (id=%d): %s: %v",
				user, queryID, strings.TrimSpace(string(killOutput)), killErr)
			continue
		}
		log.Printf("MySQL governor terminated query for %s after %ds, limit %ds (id=%d)",
			user, seconds, limit, queryID)
	}
}

// ApplyAll applies systemd slice, tenant PHP-FPM, XFS, and MySQL limits from a domain's plan.
func ApplyAll(ctx context.Context, db *sql.DB, domainID int64) error {
	var systemUser, phpVersion string
	var planID sql.NullInt64
	if err := db.QueryRowContext(ctx,
		`SELECT system_user, COALESCE(php_version,'8.3'), plan_id
		 FROM domains WHERE id=?`, domainID).
		Scan(&systemUser, &phpVersion, &planID); err != nil {
		return err
	}
	if systemUser == "" {
		return fmt.Errorf("system_user is empty")
	}
	if !planID.Valid {
		if tenantFPMActive(systemUser) {
			if err := rollbackToSharedFPM(db, domainID, systemUser, phpVersion); err != nil {
				return fmt.Errorf("rollback tenant PHP-FPM: %w", err)
			}
		}
		_ = deleteSlice(systemUser)
		// Even without a plan, apply DEFAULT disk/inode quota (CloudLinux parity:
		// never leave tenants unlimited). When the filesystem is noquota,
		// DomainQuotaApply skips silently (never an error).
		if err := applyDomainQuota(ctx, db, domainID); err != nil {
			log.Printf("quota (no plan) %s: %v", systemUser, err)
		}
		return nil
	}

	l, err := planLimits(ctx, db, domainID)
	if err != nil {
		return err
	}
	if err := writeSlice(systemUser, l); err != nil {
		log.Printf("write slice %s: %v", systemUser, err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO php_settings(domain_id, subdomain_id, pm_max_children, extra_directives, debug_mode)
		VALUES(?,0,?, "", 0) ON DUPLICATE KEY UPDATE pm_max_children=VALUES(pm_max_children)`,
		domainID, calculatePMMaxChildren(l)); err != nil {
		return fmt.Errorf("store PHP-FPM worker limit: %w", err)
	}
	if _, err := enableTenantFPM(db, domainID, systemUser, phpVersion); err != nil {
		log.Printf("tenant PHP-FPM %s: %v", systemUser, err)
	}
	if err := applyDomainQuota(ctx, db, domainID); err != nil {
		log.Printf("xfs user-quota %s: %v", systemUser, err)
	}
	if err := applyMySQLLimits(ctx, db, domainID, l); err != nil {
		log.Printf("mysql governor %s: %v", systemUser, err)
	}
	return nil
}

func nonzero(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// ReassertLimits reapplies a planned domain's limits without restarting its tenant PHP-FPM service.
func ReassertLimits(ctx context.Context, db *sql.DB, domainID int64) error {
	var systemUser string
	var planID sql.NullInt64
	if err := db.QueryRowContext(ctx,
		`SELECT system_user, plan_id FROM domains WHERE id=?`, domainID).
		Scan(&systemUser, &planID); err != nil {
		return err
	}
	if systemUser == "" {
		return fmt.Errorf("system_user is empty")
	}
	if !planID.Valid {
		return nil
	}

	l, err := GetPlanLimits(ctx, db, domainID)
	if err != nil {
		return err
	}

	var reassertErrors []error
	if err := WriteSystemdSlice(systemUser, l); err != nil {
		reassertErrors = append(reassertErrors, fmt.Errorf("systemd slice: %w", err))
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO php_settings(domain_id, subdomain_id, pm_max_children, extra_directives, debug_mode)
		VALUES(?,0,?, "", 0) ON DUPLICATE KEY UPDATE pm_max_children=VALUES(pm_max_children)`,
		domainID, calculatePMMaxChildren(l)); err != nil {
		reassertErrors = append(reassertErrors, fmt.Errorf("store PHP-FPM worker limit: %w", err))
	}
	if err := DomainQuotaApply(ctx, db, domainID); err != nil {
		reassertErrors = append(reassertErrors, fmt.Errorf("XFS user-quota: %w", err))
	}
	if err := ApplyMySQLLimits(ctx, db, domainID, l); err != nil {
		reassertErrors = append(reassertErrors, fmt.Errorf("MariaDB governor: %w", err))
	}
	return errors.Join(reassertErrors...)
}

func planProbeHTTPS(domainName string) int {
	if provisioner.ValidateDomain(domainName) != nil {
		return 0
	}
	output, _ := resourceCommand("curl", "-sk", "--max-time", "10",
		"-o", os.DevNull, "-w", "%{http_code}",
		"-H", "Host: "+domainName, "https://127.0.0.1/").Output()
	status, _ := strconv.Atoi(strings.TrimSpace(string(output)))
	return status
}

func tenantServiceActive(unit string) bool {
	output, _ := resourceCommand("systemctl", "is-active", unit).CombinedOutput()
	return strings.TrimSpace(string(output)) == "active"
}

func tenantCutoverRegressed(baseline, post int) bool {
	return baseline >= 200 && baseline < 500 && post >= 500
}

// HealTenantFPM migrates planned domains to isolated PHP-FPM services with rollback checks.
func HealTenantFPM(ctx context.Context, db *sql.DB) {
	if db == nil {
		return
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, system_user, COALESCE(php_version,'8.3'), domain_name
		 FROM domains WHERE plan_id IS NOT NULL ORDER BY id`)
	if err != nil {
		log.Printf("tenant PHP-FPM healing could not list domains: %v", err)
		return
	}

	type domain struct {
		id         int64
		systemUser string
		phpVersion string
		domainName string
	}
	var domains []domain
	for rows.Next() {
		var item domain
		if err := rows.Scan(&item.id, &item.systemUser, &item.phpVersion, &item.domainName); err != nil {
			log.Printf("tenant PHP-FPM healing skipped an unreadable domain row: %v", err)
			continue
		}
		domains = append(domains, item)
	}
	if err := rows.Err(); err != nil {
		log.Printf("tenant PHP-FPM healing stopped while reading domains: %v", err)
		_ = rows.Close()
		return
	}
	if err := rows.Close(); err != nil {
		log.Printf("tenant PHP-FPM healing could not close domain rows: %v", err)
		return
	}

	var migrated, alreadyActive, rolledBack int
	for _, item := range domains {
		select {
		case <-ctx.Done():
			log.Printf("tenant PHP-FPM healing canceled: migrated=%d active=%d rolled_back=%d", migrated, alreadyActive, rolledBack)
			return
		default:
		}
		if item.systemUser == "" || !strings.HasPrefix(item.systemUser, "c_") {
			continue
		}
		if tenantFPMActive(item.systemUser) {
			if err := reassertLimits(ctx, db, item.id); err != nil {
				log.Printf("tenant PHP-FPM healing failed to reassert limits for %s: %v", item.systemUser, err)
			} else {
				log.Printf("tenant PHP-FPM healing reasserted limits for active tenant %s without restarting it", item.systemUser)
			}
			alreadyActive++
			continue
		}

		baseline := probeHTTPS(item.domainName)
		if err := applyAllLimits(ctx, db, item.id); err != nil {
			log.Printf("tenant PHP-FPM healing failed to apply limits for %s: %v", item.systemUser, err)
		}
		if !tenantFPMActive(item.systemUser) {
			log.Printf("tenant PHP-FPM healing left %s on the shared service after cutover failure", item.systemUser)
			continue
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(cutoverSettle):
		}
		active := serviceActive("php-fpm-" + item.systemUser + ".service")
		post := probeHTTPS(item.domainName)
		if !active || tenantCutoverRegressed(baseline, post) {
			log.Printf("tenant PHP-FPM healing is rolling back %s: active=%v baseline=%d post=%d", item.systemUser, active, baseline, post)
			if err := rollbackToSharedFPM(db, item.id, item.systemUser, item.phpVersion); err != nil {
				log.Printf("tenant PHP-FPM healing rollback failed for %s: %v", item.systemUser, err)
			}
			_ = deleteSlice(item.systemUser)
			rolledBack++
			continue
		}
		log.Printf("tenant PHP-FPM healing completed cutover for %s: baseline=%d post=%d", item.systemUser, baseline, post)
		migrated++
	}
	log.Printf("tenant PHP-FPM healing completed: migrated=%d active_reasserted=%d rolled_back=%d planned=%d", migrated, alreadyActive, rolledBack, len(domains))
}

// HealQuotaOnStartup re-asserts effective XFS user quota (override > plan > default) for ALL
// tenants (c_<sk>) at startup. When the filesystem quota is INACTIVE (noquota — single reboot
// pending) NOTHING is applied; every domain is logged as "skipped" (NEVER a hard error).
// Panel boot is not blocked (called in a background goroutine). Code/plan drift converges on
// every restart. Log: "quota heal: N tenants / M skipped [ (fs noquota)]".
func HealQuotaOnStartup(ctx context.Context, db *sql.DB) {
	if db == nil {
		return
	}
	if !quotaFSCompatible() {
		sentinelDelete()
		var total int
		_ = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM domains WHERE system_user LIKE 'c\_%'`).Scan(&total)
		log.Printf("quota heal: 0 tenants / %d skipped (root filesystem is not XFS; XFS user quota unavailable)", total)
		return
	}
	// Quota enforcement is off: write the reboot-required sentinel (UI visibility) +
	// single log + exit.
	if acc, enf := quotaActive(); !enf {
		sentinelWrite()
		var total int
		_ = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM domains WHERE system_user LIKE 'c\_%'`).Scan(&total)
		if acc {
			log.Printf("quota heal: 0 tenants / %d skipped (XFS accounting on but enforcement OFF — uqnoenforce? limits NOT enforced; sentinel written)", total)
		} else {
			log.Printf("quota heal: 0 tenants / %d skipped (fs noquota — single reboot required; sentinel written)", total)
		}
		return
	}
	// Enforcement is active → remove the stale post-reboot warning (idempotent).
	sentinelDelete()
	rows, err := db.QueryContext(ctx,
		`SELECT id FROM domains WHERE system_user LIKE 'c\_%' ORDER BY id`)
	if err != nil {
		log.Printf("quota heal: could not read domain list: %v", err)
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			// A dropped id is a tenant that keeps its old quota while the summary
			// below reports a run that covered everybody.
			log.Printf("quota heal: skipping an unreadable tenant id: %v", err)
			continue
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		// A tenant missing from this list keeps whatever quota it already had, and
		// the summary below reports a smaller run than the server needed.
		log.Printf("quota heal: could not read the tenant list: %v", err)
	}
	_ = rows.Close()

	var applied, skipped int
	for _, id := range ids {
		select {
		case <-ctx.Done():
			log.Printf("quota heal: cancelled (ctx) — %d tenants / %d skipped", applied, skipped)
			return
		default:
		}
		if e := applyDomainQuota(ctx, db, id); e != nil {
			log.Printf("quota heal: domain %d error: %v", id, e)
			skipped++
			continue
		}
		applied++
	}
	log.Printf("quota heal: %d tenants / %d skipped", applied, skipped)
}
