package system

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// servika-update and servika-restore replace the same six classes of
// release-owned asset before they restart the service: the frontend, the
// migrations, the ops tools and src/scripts, the mail templates,
// /etc/nginx/conf.d/_panel.conf and /etc/php-fpm.d/roundcube.conf.
//
// They share no library, so a fix in one does not reach the other. That is how
// restore_release_assets came to exist in the updater alone, leaving the
// EMERGENCY repair tool rolling back the binary and the database only. The
// migration half is fatal rather than cosmetic: the restored old binary re-runs
// the new migrations against a rolled-back schema that already carries their
// partial objects, and the runner calls log.Fatalf on the statement error, so
// the panel does not start at all.

var opsScripts = []string{"../../assets/ops/servika-update", "../../assets/ops/servika-restore"}

func TestBothReleaseToolsRestoreEveryAssetOnRollback(t *testing.T) {
	// Each asset, named by the line that puts it back.
	assets := map[string]string{
		"frontend":       `mv "${FDIST}.old" "$FDIST"`,
		"migrations":     `cp -a "$ROLLBACK_DIR/migrations" "$MIGR"`,
		"mail templates": `cp -a "$ROLLBACK_DIR/mail-templates" "$MAIL_TMPL"`,
		"_panel.conf":    `cp -a "$ROLLBACK_DIR/_panel.conf" /etc/nginx/conf.d/_panel.conf`,
		"roundcube.conf": `cp -a "$ROLLBACK_DIR/roundcube.conf" /etc/php-fpm.d/roundcube.conf`,
		"ops tools":      `"$ROLLBACK_DIR"/opsbin/*`,
		"src/scripts":    `cp -a "$ROLLBACK_DIR/scripts" "$SCRIPTS"`,
	}
	for _, script := range opsScripts {
		body := readScript(t, script)
		for name, line := range assets {
			if !strings.Contains(body, line) {
				t.Errorf("%s does not restore the %s on rollback", script, name)
			}
		}
		if !regexp.MustCompile(`(?m)^\s*restore_release_assets\s*$`).MatchString(body) {
			t.Errorf("%s never calls restore_release_assets", script)
		}
	}
}

// The recovery dump is applied on the one path that exists to undo damage, so a
// truncated one must be refused rather than half-applied.
func TestBothReleaseToolsValidateTheRecoveryDump(t *testing.T) {
	for _, script := range opsScripts {
		if !strings.Contains(readScript(t, script), "gzip -t") {
			t.Errorf("%s applies the recovery dump without validating it", script)
		}
	}
}

func readScript(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

// The whole `-c` script is an element of lftp's argv, and /proc/<pid>/cmdline is
// mode 444 while /proc/<pid>/environ is 400. Every c_* tenant on this host has
// shell and cron, so `open -u user,pass` handed them the credentials of the
// destination that holds the panel's OWN database dumps — every tenant's rows,
// the users table and the encrypted secret columns.
//
// Measured with a real lftp: with the old form the password appears in the lftp
// process's own cmdline; with --env-password it does not.
// The uploader now lives in servika-offsite-lib, which servika-db-backup and
// servika-system-backup both source, so the assertions follow the code.
func TestThePanelDatabaseUploadKeepsThePasswordOutOfArgv(t *testing.T) {
	body := readScript(t, "../../assets/ops/servika-offsite-lib")

	if strings.Contains(body, `open -u "%s","%s"`) {
		t.Error("the offsite upload still puts the password in the lftp script")
	}
	if n := strings.Count(body, `open -u "%s" --env-password`); n != 3 {
		t.Errorf("%d of the 3 lftp scripts use --env-password", n)
	}
	if n := strings.Count(body, `LFTP_PASSWORD="$pass" lftp -c`); n != 3 {
		t.Errorf("%d of the 3 lftp calls supply LFTP_PASSWORD", n)
	}
	// Per command rather than exported, so no other subprocess of the script
	// inherits the destination password.
	if strings.Contains(body, `export LFTP_PASSWORD`) {
		t.Error("LFTP_PASSWORD is exported to every subprocess instead of set per command")
	}
	// Neither caller may reach lftp on its own, or the guarantee above would hold
	// for the library while the script beside it kept its own copy.
	for _, caller := range []string{
		"../../assets/ops/servika-db-backup",
		"../../assets/ops/servika-system-backup",
	} {
		script := readScript(t, caller)
		if strings.Contains(script, "lftp -c") {
			t.Errorf("%s builds its own lftp command instead of using the shared uploader", caller)
		}
		if !strings.Contains(script, "servika-offsite-lib") {
			t.Errorf("%s does not source the shared uploader", caller)
		}
	}
}
