package provisioner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The distribution's own /etc/logrotate.d/php-fpm globs /var/log/php-fpm/*log,
// which matched every tenant log, and logrotate REFUSES a second rule naming a
// path an earlier rule already claimed ("duplicate log entry ... skipping"), so
// the panel cannot simply add its own rule beside it. Living in a directory the
// distribution does not claim is the entire mechanism.
func TestTheTenantLogIsOutsideTheDistributionsOwnDirectory(t *testing.T) {
	dir := tenantLogDir()
	if dir == legacyTenantLogDir || strings.HasPrefix(dir, legacyTenantLogDir+"/") {
		t.Fatalf("the tenant log directory is %q, which the distribution's own rotation rule already claims", dir)
	}
	if !strings.Contains(renderFPMLogrotate(), dir+"/*.log") {
		t.Fatalf("the rotation rule does not cover %q", dir)
	}
	if strings.Contains(renderFPMLogrotate(), legacyTenantLogDir+"/") {
		t.Fatal("the rotation rule still names the distribution's directory")
	}
}

// Each tenant master writes its pid to /run/php-fpm-<user>/php-fpm.pid. The
// distribution's rule signals only /run/php-fpm/php-fpm.pid, the SYSTEM master's,
// so every tenant master went on writing to a deleted inode after the first
// rotation and its PHP errors were lost for good.
func TestTheRotationRuleSignalsEveryTenantMaster(t *testing.T) {
	body := renderFPMLogrotate()
	if !strings.Contains(body, "/run/php-fpm-*/php-fpm.pid") {
		t.Fatal("the rotation rule does not walk the per-tenant pid files")
	}
	if !strings.Contains(body, "kill -USR1") {
		t.Fatal("the rotation rule never tells a master to reopen its log")
	}
	if !strings.Contains(body, "sharedscripts") {
		t.Fatal("without sharedscripts the reopen loop runs once per rotated file")
	}
}

// The opposite of the decision in internal/laravel, and for a reason that is not
// a preference: php-fpm HAS a reopen signal, so the move-then-reopen sequence
// works and copytruncate would only add a window in which a line is lost.
func TestTheRotationRuleDoesNotCopyAndTruncate(t *testing.T) {
	body := renderFPMLogrotate()
	if strings.Contains(body, "copytruncate") {
		t.Fatal("copytruncate loses lines that php-fpm's own reopen signal does not")
	}
	// `size` REPLACES the time condition rather than adding to it, so a quiet
	// tenant's log would never rotate at all.
	if !strings.Contains(body, "maxsize ") || strings.Contains(body, "\n    size ") {
		t.Fatal("the rotation rule must bound the size with maxsize, not size")
	}
}

// The unit runs with ProtectSystem=strict, so a directory it does not list is
// READ-ONLY to the master however the filesystem permissions read. A global
// config pointing somewhere the unit does not name loses every PHP fatal error,
// which is worse than the rotation bug this replaced.
func TestTheUnitMakesTheLogDirectoryWritable(t *testing.T) {
	t.Setenv("SERVIKA_FPM_LOG_DIR", "/var/log/servika-fpm-probe")
	unit := renderTenantUnit("c_tenant", "/usr/sbin/php-fpm")

	var readWrite string
	for line := range strings.SplitSeq(unit, "\n") {
		if rest, ok := strings.CutPrefix(line, "ReadWritePaths="); ok {
			readWrite = rest
		}
	}
	if readWrite == "" {
		t.Fatal("the unit declares no writable paths at all")
	}
	if !strings.Contains(unit, "ProtectSystem=strict") {
		t.Fatal("this test is vacuous without ProtectSystem=strict in the unit")
	}
	if !strings.Contains(readWrite, tenantLogDir()) {
		t.Fatalf("ReadWritePaths is %q, which does not cover the log directory %q", readWrite, tenantLogDir())
	}
}

// The two files carry the same decision and are written by different code paths,
// so they are the pair most likely to drift apart.
func TestTheGlobalConfigLogsWhereTheUnitAllows(t *testing.T) {
	t.Setenv("SERVIKA_FPM_LOG_DIR", "/var/log/servika-fpm-probe")
	global := renderTenantGlobalConfig("c_tenant")

	want := "error_log = " + filepath.Join(tenantLogDir(), "c_tenant.log")
	if !strings.Contains(global, want+"\n") {
		t.Fatalf("the global config does not carry %q:\n%s", want, global)
	}
	if strings.Contains(global, legacyTenantLogDir+"/") {
		t.Fatal("the global config still logs into the distribution's directory")
	}
}

// A deleted tenant leaves nothing behind, and the sweep cannot reach a
// neighbour: the literal ".log" after the name means c_a.log* never matches
// c_ab.log.
func TestRemovingATenantTakesItsRotatedLogsButNotANeighbours(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVIKA_FPM_LOG_DIR", dir)

	mine := []string{"c_a.log", "c_a.log.1", "c_a.log.2.gz"}
	neighbour := []string{"c_ab.log", "c_ab.log.1"}
	for _, name := range append(append([]string{}, mine...), neighbour...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	removeTenantLogs("c_a")

	for _, name := range mine {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("%s survived the tenant's removal", name)
		}
	}
	for _, name := range neighbour {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s belongs to another tenant and was removed: %v", name, err)
		}
	}
}

// An unvalidated name reaches a glob that deletes files, so the guard is the
// boundary rather than a courtesy.
func TestRemovingLogsRefusesAnythingThatIsNotATenant(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVIKA_FPM_LOG_DIR", dir)

	kept := filepath.Join(dir, "c_a.log")
	if err := os.WriteFile(kept, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, name := range []string{"", "..", "c_a/../c_a", "*", "root"} {
		removeTenantLogs(name)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("a refused name still reached the sweep: %v", err)
	}
}

// systemd runs php-fpm from an httpd_exec_t binary and the targeted policy
// transitions it to httpd_t, which is allowed `create open read setattr` on
// httpd_log_t:file but on var_log_t:file only `append getattr ioctl lock`
// (measured against the AlmaLinux 10 shipped policy). A fresh directory under
// /var/log defaults to var_log_t, so without this type php-fpm cannot create its
// error log, and it treats that as fatal: the tenant would stop serving PHP
// rather than merely lose a log.
func TestTheLogDirectoryCarriesTheOnlyTypePHPFPMCanWrite(t *testing.T) {
	if fpmLogSELinuxType != "httpd_log_t" {
		t.Fatalf("the log directory is labelled %q, which httpd_t cannot create a file under", fpmLogSELinuxType)
	}
}

// The label is read back rather than assumed, so the reader has to be right in
// both directions: a "?" from stat must not pass for a type.
func TestAnUnreadableContextIsNotMistakenForAType(t *testing.T) {
	if got := parseSELinuxType("system_u:object_r:httpd_log_t:s0\n"); got != "httpd_log_t" {
		t.Fatalf("a real context read as %q", got)
	}
	for _, unreadable := range []string{"?", "", "\n", "unlabeled"} {
		if got := parseSELinuxType(unreadable); got != "" {
			t.Fatalf("%q read as the type %q", unreadable, got)
		}
	}
}

// The directory holds whatever a tenant's PHP printed as it died, which
// routinely includes the application's own database credentials.
func TestTheLogDirectoryIsClosedToEveryoneButRoot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "servika-fpm")
	t.Setenv("SERVIKA_FPM_LOG_DIR", dir)

	if err := EnsureTenantFPMLogDir(); err != nil {
		t.Fatalf("create: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Fatalf("the log directory is mode %04o", mode)
	}
}

// The unit is re-rendered against the interpreter it is ALREADY running, not
// against whatever the tenant's PHP version says today: a version that moved on
// since the unit was written would otherwise replace a working service with a
// failed one.
func TestTheInterpreterIsReadBackFromTheInstalledUnit(t *testing.T) {
	unit := renderTenantUnit("c_tenant", "/opt/remi/php83/root/usr/sbin/php-fpm")
	if got := execStartBinary(unit); got != "/opt/remi/php83/root/usr/sbin/php-fpm" {
		t.Fatalf("read back %q", got)
	}
	for _, bad := range []string{
		"[Service]\nExecStart=php-fpm --nodaemonize\n",
		"[Service]\nExecStart=\n",
		"[Service]\nType=notify\n",
	} {
		if got := execStartBinary(bad); got != "" {
			t.Fatalf("a unit without a usable interpreter answered %q", got)
		}
	}
}
