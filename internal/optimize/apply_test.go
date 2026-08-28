package optimize

import (
	"path/filepath"
	"strings"
	"testing"
)

// Every write in this package goes through knownTarget. A revert reads its
// target path out of a database ROW, and a row outlives the code that wrote it:
// an operator editing the table, a restored backup from an older version, or a
// future migration can all put a path there that the current specs table never
// produced. Refusing anything outside the tuned set is what keeps that from
// reaching os.WriteFile with root's hands.
func TestOnlyTheTunedFilesCanBeWritten(t *testing.T) {
	for _, item := range specs {
		if !knownTarget(item.file) {
			t.Errorf("%s is tuned by this package but knownTarget refuses it", item.file)
		}
	}
	for _, path := range []string{
		"", "/etc/passwd", "/etc/shadow", "/etc/nginx/nginx.conf.bak",
		"/etc/my.cnf.d/servika-tuning.cnf/../../shadow",
		"/home/c_example/public_html/index.php",
		"/etc/sysctl.d/90-servika.conf ", // a trailing space is a different file
	} {
		if knownTarget(path) {
			t.Errorf("%q is not a file this package tunes but was accepted", path)
		}
		if err := writeFileAs(path, "x"); err == nil {
			t.Errorf("writeFileAs wrote to %q", path)
		}
		if _, err := backupFile(path); err == nil {
			t.Errorf("backupFile read %q", path)
		}
		if err := restore(path, ""); err == nil {
			t.Errorf("restore deleted %q", path)
		}
	}
}

// The sysctl drop-in was renamed to sort last (99-zz-). A change written under
// the OLD name must still be revertable, so knownTarget accepts it even though it
// is no longer in the specs table. A path that merely resembles it stays refused,
// the same way the trailing-space case above is.
func TestTheOldSysctlPathStaysRevertable(t *testing.T) {
	if !knownTarget(sysctlOldPath) {
		t.Errorf("the pre-rename sysctl path %q must stay revertable", sysctlOldPath)
	}
	if knownTarget(sysctlOldPath + " ") {
		t.Errorf("a path resembling the old sysctl file must not be accepted")
	}
}

// The backup name is built from the target path, so it must flatten to
// something that can only land directly in the backup directory. A name that
// kept its separators would make filepath.Join place the copy under whatever
// the target path spelled.
func TestABackupNameCannotCarryAPath(t *testing.T) {
	for _, path := range []string{
		"/etc/nginx/nginx.conf",
		"/etc/my.cnf.d/servika-tuning.cnf",
		"/etc/php-fpm.d/www.conf",
		"/etc/sysctl.d/99-zz-servika.conf",
	} {
		name := backupName(path)
		if name != filepath.Base(name) {
			t.Errorf("%s produced the backup name %q, which is a path", path, name)
		}
		if strings.Contains(name, "/") || strings.Contains(name, "..") {
			t.Errorf("%s produced the backup name %q", path, name)
		}
		if !strings.HasSuffix(name, ".bak") {
			t.Errorf("%s produced %q, which is not marked as a backup", path, name)
		}
	}
}

// Two names taken from the same file must differ, or a second apply overwrites
// the copy the first one needs to undo itself.
func TestTwoBackupsOfOneFileDoNotCollide(t *testing.T) {
	first := backupName(nginxPath)
	second := backupName(nginxPath)
	if first == second {
		t.Errorf("both backups of %s are named %q", nginxPath, first)
	}
}

// A refusal has to reach the screen as a CODE, because the screen writes the
// sentence in twelve languages and cannot translate one this package composed.
func TestARefusalCarriesItsReasonCode(t *testing.T) {
	err := refuse(ReasonNotApplied, "MariaDB is still running on %q", "128M")
	if got := ReasonOf(err); got != ReasonNotApplied {
		t.Errorf("reason read as %q, want %q", got, ReasonNotApplied)
	}
	// A wrapped refusal still answers, because applyFile wraps.
	wrapped := &Refusal{Reason: ReasonValidateFailed, Message: "nginx refused"}
	if got := ReasonOf(wrapped); got != ReasonValidateFailed {
		t.Errorf("wrapped reason read as %q", got)
	}
	// Anything that is not a refusal has no code, and the handler answers 500
	// rather than presenting an unexplained conflict.
	if got := ReasonOf(errPlain{}); got != "" {
		t.Errorf("a plain error produced the reason %q", got)
	}
}

type errPlain struct{}

func (errPlain) Error() string { return "disk is full" }
