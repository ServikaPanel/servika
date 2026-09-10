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
