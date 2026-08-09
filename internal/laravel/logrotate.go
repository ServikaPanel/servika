package laravel

import (
	"bytes"
	"fmt"
	"log"
	"os"

	"servika/internal/config"
)

// logrotatePathVar is the drop-in that rotates every log a long-running tenant
// process writes: Laravel queue workers and deploy jobs here, and the Node and
// Python applications of internal/apps.
//
// One file covers both directories because the rotation rule is identical and
// the reason it has to be copytruncate is identical too.
//
// It is a var only so a test can point it somewhere writable.
var logrotatePathVar = "/etc/logrotate.d/servika-app-logs"

// HealLogRotation installs the rotation rule for the panel's long-running
// process logs.
//
// Without it these files grow without bound. A queue worker in a restart loop
// writes a stack trace every five seconds, and nothing was ever truncating it.
//
// copytruncate is REQUIRED here, and that is the opposite of the decision in
// internal/slowquery, where it is deliberately absent. There the file belongs to
// mysqld, which can be told to reopen it with flush-slow-logs, so the documented
// move-then-reopen sequence works. systemd's `StandardOutput=append:` target has
// no such signal: it opens the file once and holds the descriptor, so renaming
// the file leaves every worker writing to the old inode, so the rotated file
// stays empty while the original keeps growing under a name nothing reads.
//
// The trade is that a line written during the copy can be lost. Against a log
// that otherwise grows for good, that is the cheaper failure.
func HealLogRotation() {
	// maxsize, not size: `size` REPLACES the time condition (measured on
	// AlmaLinux 10, logrotate says "note: 'size' overrides previously specified
	// 'daily'"), so a quiet log would never rotate at all. maxsize adds an early
	// rotation on top of the daily one, which is what a worker in a restart loop
	// needs.
	//
	// There is no `create` line. copytruncate never creates a file, so one would
	// be silently unused; the live file keeps the 0600 root mode EnsureWorkerLog
	// gave it, and logrotate copies that mode onto the rotated file (measured).
	body := fmt.Sprintf(`# Managed by Servika.
%s/*.log
%s/*.log {
    daily
    maxsize 10M
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    su root root
    # systemd holds the append: descriptor open and has no reopen signal, so a
    # rename would leave every worker writing to the old inode.
    copytruncate
}
`, config.LaravelLogDir(), config.AppLogDir())

	if err := writeIfChanged(logrotatePathVar, []byte(body), 0o644); err != nil {
		// /etc/logrotate.d comes from the logrotate package, so a missing
		// directory means the tool is not installed. Saying so is the repair:
		// writing the file somewhere nothing reads would look like success.
		log.Printf("laravel: could not install the log rotation rule: %v", err)
	}
}

// writeIfChanged writes the drop-in, skipping the write when the content already
// matches so a startup heal does not touch its mtime.
//
// The parent directory is never created, for the reason above.
func writeIfChanged(path string, body []byte, mode os.FileMode) error {
	// #nosec G304 -- path is a package-level constant naming a system config file; no caller supplies it.
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, body) {
		return nil
	}
	// #nosec G306 -- root-owned system integration file that logrotate must read; it carries no secret.
	return os.WriteFile(path, body, mode)
}
