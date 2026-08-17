package provisioner

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"servika/internal/config"
)

// legacyTenantLogDir is where a tenant's PHP-FPM error log lived before it
// moved. Nothing writes there any more; only teardown still names it, so a
// tenant deleted after an upgrade does not leave its old log behind.
const legacyTenantLogDir = "/var/log/php-fpm"

// fpmLogSELinuxType is the only type the targeted policy lets php-fpm create a
// file under; see EnsureTenantFPMLogDir.
const fpmLogSELinuxType = "httpd_log_t"

// fpmLogrotatePathVar is the panel's own rotation rule for those logs. It is a
// var only so a test can point it somewhere writable.
var fpmLogrotatePathVar = "/etc/logrotate.d/servika-fpm-logs"

// tenantLogDir holds one PHP-FPM error log per tenant, each 0600 root:root
// inside a 0700 root directory. It is NOT the distribution's own
// /var/log/php-fpm; see config.DefaultTenantFPMLogDir for why that directory
// silently destroyed these logs.
func tenantLogDir() string { return config.TenantFPMLogDir() }

func tenantLogPath(systemUser string) string {
	return filepath.Join(tenantLogDir(), systemUser+".log")
}

func legacyTenantLogPath(systemUser string) string {
	return filepath.Join(legacyTenantLogDir, "tenant-"+systemUser+".log")
}

// removeTenantLogs takes a deleted tenant's PHP error log away with it,
// including the rotated copies. The glob cannot reach a neighbour: the literal
// ".log" after the name means c_a.log* never matches c_ab.log.
func removeTenantLogs(systemUser string) {
	if !tenantUserPattern.MatchString(systemUser) {
		return
	}
	matches, err := filepath.Glob(tenantLogPath(systemUser) + "*")
	if err != nil {
		log.Printf("tenant PHP-FPM log cleanup for %s: %v", systemUser, err)
	}
	for _, path := range matches {
		_ = os.Remove(path)
	}
	_ = os.Remove(legacyTenantLogPath(systemUser))
}

// renderFPMLogrotate builds the rotation rule for the tenant PHP-FPM logs.
//
// There is no copytruncate, which is the OPPOSITE of the decision in
// internal/laravel and the same one as internal/slowquery. php-fpm reopens its
// error log on SIGUSR1, so the documented move-then-reopen sequence works and no
// line is lost; systemd's `StandardOutput=append:` target, which the Laravel
// workers use, has no such signal.
//
// The postrotate loop is why this rule has to exist at all. The distribution's
// own /etc/logrotate.d/php-fpm globs /var/log/php-fpm/*log, which matched every
// tenant log, and then signals ONLY /run/php-fpm/php-fpm.pid, the system
// master's. Each tenant master runs from its own pid file under
// /run/php-fpm-<user>/, was never told to reopen, and went on writing to a
// deleted inode: the tenant's PHP errors were lost for good from the first
// rotation onward (measured on AlmaLinux 10). Adding a second rule for the same
// paths is not an option either, because logrotate refuses a duplicate entry and
// then skips the file altogether, so the logs had to move out of that directory.
func renderFPMLogrotate() string {
	// maxsize, not size: `size` REPLACES the time condition, so a quiet log would
	// never rotate at all.
	//
	// There is no `create` line. php-fpm creates the file itself on reopen, 0600
	// root:root (measured), and a `create` line would be a second declaration of
	// a mode the daemon already sets correctly.
	return fmt.Sprintf(`# Managed by Servika.
%s/*.log {
    daily
    maxsize 10M
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    su root root
    sharedscripts
    postrotate
        for pidfile in /run/php-fpm-*/php-fpm.pid; do
            [ -r "$pidfile" ] || continue
            kill -USR1 "$(cat "$pidfile")" 2>/dev/null || true
        done
    endscript
}
`, tenantLogDir())
}

// EnsureTenantFPMLogDir creates the log directory and gives it the SELinux type
// php-fpm is allowed to write, refusing rather than reporting success when it
// cannot.
//
// The label is not a detail. systemd runs php-fpm from a binary labelled
// httpd_exec_t and the targeted policy transitions it to httpd_t, which is
// allowed `create open read setattr` on httpd_log_t:file but on var_log_t:file
// only `append getattr ioctl lock` (measured against the AlmaLinux 10 shipped
// policy). The distribution ships `/var/log/php-fpm(/.*)?` as httpd_log_t, which
// is the only reason the previous location worked; a fresh directory under
// /var/log defaults to var_log_t, where php-fpm cannot CREATE its error log at
// all. It exits when it cannot open that file, so an unlabelled directory would
// not lose a log, it would stop every tenant master on an Enforcing host.
func EnsureTenantFPMLogDir() error {
	dir := tenantLogDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create the tenant PHP-FPM log directory: %w", err)
	}
	// A wrong type here is the difference between a rotation bug and a tenant
	// whose PHP stops serving, so the label is read back rather than assumed.
	if err := ensureSELinuxType(dir, fpmLogSELinuxType); err != nil {
		return fmt.Errorf("the tenant PHP-FPM log directory: %w", err)
	}
	return nil
}

// selinuxType reads the type field out of a path's security context, or "" when
// it cannot be read.
func selinuxType(path string) string {
	output, err := tenantCommand("stat", "-c", "%C", path).Output()
	if err != nil {
		return ""
	}
	return parseSELinuxType(string(output))
}

// parseSELinuxType takes the type out of `user:role:type:level`. stat prints a
// bare "?" when it has no context to report, which must read as unknown rather
// than as a type, or the guard above would pass on a directory that carries no
// label at all.
func parseSELinuxType(context string) string {
	parts := strings.Split(strings.TrimSpace(context), ":")
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// HealTenantFPMLogs gives the tenant PHP-FPM logs a directory of their own and a
// rotation rule that actually reaches the masters writing them.
//
// It also carries an existing installation across: the error_log path lives in
// the tenant's global php-fpm.conf and the writable path lives in its unit, so
// neither the pool drift repair nor a reload can move them.
func HealTenantFPMLogs() {
	if err := EnsureTenantFPMLogDir(); err != nil {
		// Nothing is migrated. The old arrangement rotates a tenant's PHP errors
		// away, which is the bug this repairs; moving them somewhere php-fpm
		// cannot write would stop the tenant serving PHP at all.
		log.Printf("tenant PHP-FPM logs left where they are: %v", err)
		return
	}
	if err := writeIfChanged(fpmLogrotatePathVar, []byte(renderFPMLogrotate()), 0o644); err != nil {
		// /etc/logrotate.d comes from the logrotate package, so a missing
		// directory means the tool is not installed. Saying so is the repair:
		// writing the file somewhere nothing reads would look like success.
		log.Printf("tenant PHP-FPM log rotation rule: %v", err)
	}
	migrateTenantFPMLogPaths()
}

// writeIfChanged writes the drop-in, skipping the write when the content already
// matches so a startup heal does not touch its mtime.
//
// The parent directory is never created, for the reason above.
func writeIfChanged(path string, body []byte, mode os.FileMode) error {
	// #nosec G304 -- path is a package-level variable naming a system config file; no caller supplies it.
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, body) {
		return nil
	}
	// #nosec G306 -- root-owned system integration file that logrotate must read; it carries no secret.
	return os.WriteFile(path, body, mode)
}

// execStartBinary reads the interpreter back out of an installed unit rather
// than re-deriving it from the tenant's PHP version. The version can have moved
// on since the unit was written, and a unit rendered against a binary that is
// not the one already running would replace a working service with a failed one.
func execStartBinary(unit string) string {
	for line := range strings.SplitSeq(unit, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "ExecStart=")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 || !filepath.IsAbs(fields[0]) {
			return ""
		}
		return fields[0]
	}
	return ""
}

// migrateTenantFPMLogPaths repoints every installed tenant master at the new log
// directory.
//
// The two files move TOGETHER or not at all. The unit's ReadWritePaths is what
// makes the directory writable under ProtectSystem=strict, so a global config
// pointing at a path the unit does not list would leave the master unable to
// open its log, which loses every PHP fatal error rather than merely rotating
// them away. That is why a failure at any step restores what was there.
func migrateTenantFPMLogPaths() {
	units, err := filepath.Glob(filepath.Join(tenantUnitDir, "php-fpm-c_*.service"))
	if err != nil {
		log.Printf("tenant PHP-FPM log migration: %v", err)
		return
	}
	for _, unitPath := range units {
		systemUser := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(unitPath), "php-fpm-"), ".service")
		if !tenantUserPattern.MatchString(systemUser) {
			continue
		}
		migrateOneTenantFPMLogPath(systemUser, unitPath)
	}
}

func migrateOneTenantFPMLogPath(systemUser, unitPath string) {
	// #nosec G304 -- path is built from a validated tenant identifier under the root-owned systemd unit directory.
	currentUnit, err := os.ReadFile(unitPath)
	if err != nil {
		return
	}
	fpmBinary := execStartBinary(string(currentUnit))
	if fpmBinary == "" {
		log.Printf("tenant PHP-FPM log migration: %s has no usable ExecStart", systemUser)
		return
	}
	globalPath := filepath.Join(tenantCfgDir(systemUser), "php-fpm.conf")
	// #nosec G304 -- path is built from a validated tenant identifier under the root-owned config directory.
	currentGlobal, err := os.ReadFile(globalPath)
	if err != nil {
		return // No global config to repoint; EnableTenantFPM writes one.
	}

	wantedUnit := renderTenantUnit(systemUser, fpmBinary)
	wantedGlobal := renderTenantGlobalConfig(systemUser)
	if string(currentUnit) == wantedUnit && string(currentGlobal) == wantedGlobal {
		return
	}

	// Move the existing log first. The master still holds a descriptor on the
	// inode, so it keeps writing there until the restart and nothing is lost;
	// leaving it behind would drop the history the operator is looking at.
	if _, err := os.Stat(tenantLogPath(systemUser)); os.IsNotExist(err) {
		_ = os.Rename(legacyTenantLogPath(systemUser), tenantLogPath(systemUser))
	}

	restore := func() {
		// #nosec G306 G703 -- root-owned system integration file that php-fpm and systemd must read; it carries no secret.
		_ = os.WriteFile(globalPath, currentGlobal, 0644)
		// #nosec G306 G703 -- root-owned system integration file that php-fpm and systemd must read; it carries no secret.
		_ = os.WriteFile(unitPath, currentUnit, 0644)
		_, _ = tenantCommand("systemctl", "daemon-reload").CombinedOutput()
	}

	// #nosec G306 -- root-owned system integration file that php-fpm must read; it carries no secret.
	if err := os.WriteFile(globalPath, []byte(wantedGlobal), 0644); err != nil {
		log.Printf("tenant PHP-FPM log migration: %s global config: %v", systemUser, err)
		return
	}
	if output, err := tenantCommand(fpmBinary, "-t", "-y", globalPath).CombinedOutput(); err != nil {
		restore()
		log.Printf("tenant PHP-FPM log migration: %s php-fpm -t failed, rolled back: %s", systemUser, strings.TrimSpace(string(output)))
		return
	}
	// #nosec G306 -- root-owned system integration file that systemd must read; it carries no secret.
	if err := os.WriteFile(unitPath, []byte(wantedUnit), 0644); err != nil {
		restore()
		log.Printf("tenant PHP-FPM log migration: %s unit: %v", systemUser, err)
		return
	}
	if output, err := tenantCommand("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		restore()
		log.Printf("tenant PHP-FPM log migration: %s daemon-reload failed, rolled back: %s", systemUser, strings.TrimSpace(string(output)))
		return
	}
	// A restart, not a reload: USR2 re-reads the configuration but keeps the mount
	// namespace the unit gave the master, so the new directory would still be
	// read-only to it.
	if output, err := tenantCommand("systemctl", "restart", tenantUnitName(systemUser)).CombinedOutput(); err != nil {
		restore()
		_, _ = tenantCommand("systemctl", "restart", tenantUnitName(systemUser)).CombinedOutput()
		log.Printf("tenant PHP-FPM log migration: %s restart failed, rolled back: %s", systemUser, strings.TrimSpace(string(output)))
		return
	}
	log.Printf("tenant PHP-FPM log migration: %s now logs to %s", systemUser, tenantLogPath(systemUser))
}
