package laravel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installRotation writes the drop-in into a temporary directory and returns it.
func installRotation(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	previous := logrotatePathVar
	logrotatePathVar = filepath.Join(dir, "servika-app-logs")
	t.Cleanup(func() { logrotatePathVar = previous })

	t.Setenv("SERVIKA_LARAVEL_LOG_DIR", filepath.Join(dir, "laravel"))
	t.Setenv("SERVIKA_APP_LOG_DIR", filepath.Join(dir, "apps"))

	HealLogRotation()
	body, err := os.ReadFile(logrotatePathVar)
	if err != nil {
		t.Fatalf("the rotation rule was not written: %v", err)
	}
	return string(body)
}

// systemd's append: target has no reopen signal: it opens the file once and
// holds the descriptor, so renaming leaves every worker writing to the old
// inode and the rotated file stays empty while the original grows under a name
// nothing reads. This is the opposite of internal/slowquery, where mysqld can be
// told to reopen and copytruncate is deliberately absent.
func TestTheRotationTruncatesInsteadOfRenaming(t *testing.T) {
	body := installRotation(t)
	if !strings.Contains(body, "copytruncate") {
		t.Error("the rule renames the log, which leaves every worker writing to the old inode")
	}
}

// `size` REPLACES the time condition rather than adding to it (measured on
// AlmaLinux 10: logrotate answers "note: 'size' overrides previously specified
// 'daily'"), so a quiet log would never rotate and never be compressed.
func TestAQuietLogStillRotates(t *testing.T) {
	body := installRotation(t)
	if !strings.Contains(body, "daily") {
		t.Error("the rule has no time condition")
	}
	if strings.Contains(body, "\n    size ") {
		t.Error("size overrides daily, so a log below the threshold would never rotate")
	}
	if !strings.Contains(body, "maxsize") {
		t.Error("a worker in a restart loop can fill the disk before the daily rotation")
	}
}

// Both directories are covered by one rule, because the reason they need
// copytruncate is the same: systemd holds the descriptor for a Laravel worker
// and for a Node or Python application alike.
func TestBothLongRunningLogDirectoriesAreCovered(t *testing.T) {
	body := installRotation(t)
	for _, want := range []string{"laravel/*.log", "apps/*.log"} {
		if !strings.Contains(body, want) {
			t.Errorf("the rule does not cover %s", want)
		}
	}
}

// /etc/logrotate.d belongs to the logrotate package, so a missing directory
// means the tool is not installed. Creating it would leave a configuration file
// somewhere nothing reads and look like success.
func TestTheRuleIsNotWrittenIntoADirectoryTheToolDoesNotOwn(t *testing.T) {
	body := sourceOf(t, "logrotate.go")
	if strings.Contains(body, "MkdirAll") {
		t.Error("the heal creates /etc/logrotate.d, so a host without logrotate gets a file nothing reads")
	}
}

// A second run must not touch the file, or every panel restart changes its
// mtime and every backup sees a change that is not one.
func TestAsecondRunLeavesTheFileAlone(t *testing.T) {
	installRotation(t)
	first, err := os.Stat(logrotatePathVar)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(logrotatePathVar, first.ModTime(), first.ModTime()); err != nil {
		t.Fatal(err)
	}
	HealLogRotation()
	second, err := os.Stat(logrotatePathVar)
	if err != nil {
		t.Fatal(err)
	}
	if !second.ModTime().Equal(first.ModTime()) {
		t.Error("an unchanged rule was rewritten")
	}
}
