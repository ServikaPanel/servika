package slowquery

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"servika/internal/config"
	"servika/internal/credentials"
)

// dropInPath makes the setting survive a MariaDB restart. The panel applies the
// same values with SET GLOBAL so the change takes effect immediately.
// logrotatePath rotates the file the panel owns, leaving any slow log the
// operator configured themselves alone.
//
// Both are variables rather than constants so a test can exercise the writes in
// a temporary directory instead of the host's real /etc.
var (
	dropInPath    = "/etc/my.cnf.d/servika-slowlog.cnf"
	logrotatePath = "/etc/logrotate.d/servika-mariadb-slow"
)

// setPaths redirects the two managed files. Test-only.
func setPaths(dropIn, rotate string) {
	dropInPath, logrotatePath = dropIn, rotate
}

const (
	// minThresholdSeconds and maxThresholdSeconds bound what may reach
	// long_query_time. The value is rendered into a configuration file and into
	// a SET GLOBAL statement, so it is validated as a number in a range and
	// formatted, never interpolated as text.
	minThresholdSeconds = 0.1
	maxThresholdSeconds = 60.0
	// defaultThresholdSeconds matches the migration's column default.
	defaultThresholdSeconds = 2.0
)

// healCommand is a variable so a test can substitute a stub and inspect what the
// process actually receives.
var healCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args and no shell; nothing here is caller input.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
	}
	return cmd
}

// rootSQL is a variable for the same reason: a test proves the statements travel
// on stdin without a MariaDB to talk to.
var rootSQL = credentials.RunRootSQL

// ValidThreshold reports whether a threshold may be stored and applied.
//
// The check runs on the WRITE path, not only where a screen draws the field: a
// value outside the range would be rendered into MariaDB's own configuration
// file, and a file MariaDB refuses stops it from starting on the next restart.
func ValidThreshold(seconds float64) bool {
	return seconds >= minThresholdSeconds && seconds <= maxThresholdSeconds
}

// HealConfig applies the stored setting to MariaDB at startup.
//
// It never restarts MariaDB. A startup heal that did would drop every site's
// database connections, so the drop-in carries the setting across a restart and
// SET GLOBAL makes it current now.
func HealConfig(db *sql.DB) {
	if db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	enabled, seconds, err := readSetting(ctx, db)
	if err != nil {
		log.Printf("slow query log: could not read the setting: %v", err)
		return
	}
	if err := Apply(ctx, enabled, seconds); err != nil {
		log.Printf("slow query log: %v", err)
	}
}

// Apply writes the drop-in, hardens the log's permissions and makes the values
// current. It is idempotent, so it is safe on every startup and on every save.
func Apply(ctx context.Context, enabled bool, seconds float64) error {
	if !ValidThreshold(seconds) {
		seconds = defaultThresholdSeconds
	}
	path := config.MariaDBSlowLog()

	if err := writeDropIn(enabled, seconds, path); err != nil {
		return fmt.Errorf("could not write %s: %w", dropInPath, err)
	}
	if err := writeLogrotate(path); err != nil {
		return fmt.Errorf("could not write %s: %w", logrotatePath, err)
	}
	// The permissions come BEFORE the setting is turned on. The file records
	// every tenant's SQL, so a window in which it exists world-readable is a
	// window in which one tenant can read a neighbour's queries.
	if err := hardenLogPerms(ctx, path); err != nil {
		log.Printf("slow query log: could not harden %s: %v", filepath.Dir(path), err)
	}
	return applyGlobals(enabled, seconds, path)
}

func readSetting(ctx context.Context, db *sql.DB) (bool, float64, error) {
	var enabled int
	var seconds float64
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(slow_query_enabled,0), COALESCE(slow_query_seconds,?)
		   FROM panel_settings WHERE id=1`, defaultThresholdSeconds).Scan(&enabled, &seconds)
	if err == sql.ErrNoRows {
		return false, defaultThresholdSeconds, nil
	}
	if err != nil {
		return false, defaultThresholdSeconds, err
	}
	return enabled == 1, seconds, nil
}

// writeDropIn renders the permanent configuration, and skips the write when the
// content is unchanged so a startup heal does not touch the file's mtime.
func writeDropIn(enabled bool, seconds float64, path string) error {
	on := 0
	if enabled {
		on = 1
	}
	body := fmt.Sprintf(`# Managed by Servika. Regenerated from panel_settings on every startup.
#
# The panel reads this file with internal/slowquery and attributes each entry to
# a tenant through db_accounts. Only the query SHAPE is stored; literals are
# replaced before anything reaches the panel's database.
[mysqld]
slow_query_log            = %d
slow_query_log_file       = %s
long_query_time           = %.3f
# query_plan adds the Full_scan line, which is the cheapest signal that a query
# has no usable index. It costs nothing per entry.
log_slow_verbosity        = query_plan
# Administrative statements are the panel's own work, not a tenant's.
log_slow_admin_statements = 0
`, on, path, seconds)
	return writeIfChanged(dropInPath, []byte(body), 0o644)
}

// writeLogrotate rotates the panel's own slow log.
//
// copytruncate is deliberately absent: it races with mysqld's write. The
// documented sequence is to move the file and ask the server to reopen it, which
// is what flush-slow-logs does.
func writeLogrotate(path string) error {
	body := fmt.Sprintf(`# Managed by Servika.
%s {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    create 0600 mysql mysql
    su mysql mysql
    postrotate
        /usr/bin/mysqladmin flush-slow-logs >/dev/null 2>&1 || true
    endscript
}
`, path)
	return writeIfChanged(logrotatePath, []byte(body), 0o644)
}

// writeIfChanged writes one of the two managed files, skipping the write when
// the content already matches so a startup heal does not touch its mtime.
//
// The parent directory is never created. /etc/my.cnf.d and /etc/logrotate.d come
// from the MariaDB and logrotate packages, so a missing one means the service
// this configures is not installed, and the error that follows says so rather
// than leaving a configuration file somewhere nothing reads it.
func writeIfChanged(path string, body []byte, mode os.FileMode) error {
	// #nosec G304 -- path is one of two package-level constants naming a system config file; no caller supplies it.
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, body) {
		return nil
	}
	return os.WriteFile(path, body, mode)
}

// hardenLogPerms closes the slow log to everyone but root and mysql.
//
// This is not optional. The file carries every tenant's SQL text, so a tenant
// with shell access could otherwise read a neighbour's WHERE clauses and the
// e-mail addresses and tokens in them. The directory loses group and other
// entirely and the file becomes 0600, both owned by mysql: mysqld writes as
// mysql and the panel reads as root, so neither is affected. This mirrors
// provisioner.HealNginxLogPerms, which closes the same hole for nginx.
func hardenLogPerms(ctx context.Context, path string) error {
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		// The directory appears when MariaDB first writes; nothing to harden yet.
		return nil
	}
	if info.Mode().Perm() != 0o700 {
		// #nosec G302 -- 0700 is the minimum for a DIRECTORY the owner must traverse, and this tightens the mode rather than loosening it.
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
		log.Printf("slow query log: %s set to 0700 (cross-tenant query reading closed)", dir)
	}
	// chown by name rather than a hardcoded uid: the mysql account's id differs
	// between distributions and between a package install and a container.
	if out, err := healCommand(ctx, "chown", "mysql:mysql", dir).CombinedOutput(); err != nil {
		log.Printf("slow query log: could not set the owner of %s: %s", dir, bytes.TrimSpace(out))
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
		log.Printf("slow query log: %s set to 0600", path)
	}
	return nil
}

// applyGlobals makes the values current without a restart.
//
// Every value is formatted from a validated number or a configured path, never
// from caller text, and the statements travel on stdin through
// credentials.RunRootSQL rather than on argv.
func applyGlobals(enabled bool, seconds float64, path string) error {
	on := 0
	if enabled {
		on = 1
	}
	statements := []string{
		fmt.Sprintf("SET GLOBAL slow_query_log_file = %s;", quoteSQLString(path)),
		fmt.Sprintf("SET GLOBAL long_query_time = %.3f;", seconds),
		"SET GLOBAL log_slow_verbosity = 'query_plan';",
		"SET GLOBAL log_slow_admin_statements = 0;",
		// The switch goes LAST so the file, the threshold and the verbosity are
		// already in force for the first entry written.
		fmt.Sprintf("SET GLOBAL slow_query_log = %d;", on),
	}
	if err := rootSQL(statements...); err != nil {
		return fmt.Errorf("could not apply the slow query settings: %w", err)
	}
	return nil
}

// quoteSQLString renders a value as a MariaDB string literal. The only caller
// passes a configured absolute path, but the quoting is here rather than assumed
// because the value crosses into SQL text.
func quoteSQLString(value string) string {
	var out []byte
	out = append(out, '\'')
	for i := 0; i < len(value); i++ {
		switch c := value[i]; c {
		case '\'', '\\':
			out = append(out, '\\', c)
		case 0:
			// A NUL cannot appear in a path the kernel returned, and dropping it
			// is safer than emitting an escape MariaDB would read as data.
		default:
			out = append(out, c)
		}
	}
	return string(append(out, '\''))
}
