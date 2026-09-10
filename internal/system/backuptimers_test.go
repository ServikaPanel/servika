package system

import (
	"strings"
	"testing"
)

const verifyTool = "../../assets/ops/servika-verify"

// servika-db-backup produces the ONLY artifact the panel database can be
// recovered from, and the one servika-update and servika-restore both roll back
// to. servika-system-backup produces the only host-state artifact. Both are
// enabled at install time, and after that nothing observed them: the tool
// checked only that the SCRIPT was on disk, while the OPTIONAL antivirus timer
// beside it got six checks. A backup timer that stops firing is by definition
// not noticed.
func TestBothBackupTimersAreVerified(t *testing.T) {
	body := readScript(t, verifyTool)

	for _, unit := range []string{"servika-db-backup.timer", "servika-system-backup.timer"} {
		if !strings.Contains(body, unit) {
			t.Errorf("servika-verify never mentions %s", unit)
		}
	}
	if !strings.Contains(body, "check_backup_timer()") {
		t.Fatal("there is no backup-timer check")
	}
}

// Three different states, three different findings. is-enabled alone reports a
// unit left failed as healthy, and an enabled timer that has never produced
// anything is not the same as one producing stale artifacts.
func TestTheTimerCheckSeparatesItsThreeFailures(t *testing.T) {
	check := timerCheckBody(t)

	for name, fragment := range map[string]string{
		"not installed":   "the unit is not installed",
		"not enabled":     "NOT enabled",
		"last run failed": "its last run FAILED",
		"never produced":  "no artifact has been written yet",
		"stale artifact":  "the newest artifact is",
	} {
		if !strings.Contains(check, fragment) {
			t.Errorf("the check does not report %q as its own outcome", name)
		}
	}
	// is-failed on the SERVICE, because the timer unit itself does not carry the
	// failure of the job it started.
	if !strings.Contains(check, `systemctl is-failed "${unit%.timer}.service"`) {
		t.Error("the check reads the timer's failed state rather than its service's")
	}
}

// This tool is a gate that servika-update and servika-restore exit 1 on, and a
// freshly installed server has no dump until 03:30. The backup root above
// carries the same reasoning after a critical check failed a healthy server.
func TestEveryBackupTimerFindingIsAWarning(t *testing.T) {
	check := timerCheckBody(t)

	if strings.Contains(check, "fail ") {
		t.Fatalf("a backup-timer finding is critical, which would fail a healthy fresh server:\n%s", check)
	}
	if !strings.Contains(check, "warn ") {
		t.Fatal("the check reports nothing")
	}
	if !strings.Contains(check, "pass ") {
		t.Fatal("a healthy timer produces no positive result")
	}
}

// The age is measured from mtime, not from the stamped file name: a name is what
// the producer intended to write and the mtime is when a byte last landed, and a
// run that died half way leaves the first without the second.
func TestTheArtifactAgeIsMeasuredFromTheFileItself(t *testing.T) {
	body := readScript(t, verifyTool)
	helper := sectionBetween(t, body, "newest_age_days() {", "\n}\n")

	if !strings.Contains(helper, "-printf '%T@ %p\\n'") {
		t.Errorf("the age is not read from the entry's mtime:\n%s", helper)
	}
	// A missing directory answers "nothing", which the caller reports as "no
	// artifact yet" rather than as a stale one.
	if !strings.Contains(helper, `[ -d "$dir" ] || return 0`) {
		t.Error("a missing directory is not distinguished from a stale artifact")
	}
	// Both producers are covered: the database dumps are files, the host backups
	// are stamped directories.
	if !strings.Contains(body, `newest_age_days \"$DB_BACKUP_DIR\" f 'panel-*.sql.gz'`) {
		t.Error("the database dumps are not measured by their own name pattern")
	}
	if !strings.Contains(body, `newest_age_days \"$SYSTEM_BACKUP_DIR\" d '20*'`) {
		t.Error("the host backups are not measured as stamped directories")
	}
}

// timerCheckBody returns the body of check_backup_timer.
func timerCheckBody(t *testing.T) string {
	t.Helper()
	return sectionBetween(t, readScript(t, verifyTool), "check_backup_timer() {", "\n}\n")
}

// sectionBetween returns the text from the first marker to the next terminator.
func sectionBetween(t *testing.T, body, start, end string) string {
	t.Helper()
	at := strings.Index(body, start)
	if at < 0 {
		t.Fatalf("%q is not in servika-verify", start)
	}
	section, _, found := strings.Cut(body[at:], end)
	if !found {
		t.Fatalf("%q has no %q after it", start, end)
	}
	return section
}
