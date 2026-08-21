package antivirus

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"servika/internal/avsettings"
)

// Only what a server executes or serves is opened. Watching every file turns a
// cache directory into an event storm, and a webshell cannot be a .jpg because
// nothing executes one; a .jpg.php is caught by the path rule instead.
func TestOnlyExecutableKindsAreOpened(t *testing.T) {
	watched := []string{
		"/home/c_x/public_html/index.php", "/home/c_x/x.phtml", "/home/c_x/x.inc",
		"/home/c_x/app.js", "/home/c_x/app.mjs",
		"/home/c_x/.htaccess", "/home/c_x/.user.ini",
	}
	ignored := []string{
		"/home/c_x/photo.jpg", "/home/c_x/dump.sql", "/home/c_x/style.css",
		"/home/c_x/wp-content/cache/page.html", "/var/lib/mysql/ibdata1",
	}
	for _, p := range watched {
		if !watchable(p) {
			t.Errorf("%s is not watched but a server executes or serves it", p)
		}
	}
	for _, p := range ignored {
		if watchable(p) {
			t.Errorf("%s is watched, which is cost with no possible finding", p)
		}
	}
}

// The watcher inspects the content through the descriptor the EVENT carried,
// never by re-opening the path. The path sits in a directory a tenant writes
// to, so resolving it again as root can answer with a different file.
func TestTheContentComesFromTheEventDescriptorAndNotFromThePath(t *testing.T) {
	source := sourceOf(t, "watch_linux.go")
	if strings.Contains(source, "os.ReadFile(path)") || strings.Contains(source, "os.Open(path)") {
		t.Error("the watcher re-opens the event's path instead of reading its descriptor")
	}
	if !strings.Contains(source, "readEventFile(file, limit)") {
		t.Error("the watcher no longer reads through the event descriptor")
	}
	// The read itself is shared with the sweep, so an oversized file is judged
	// on its head and tail here too rather than being skipped.
	if !strings.Contains(source, "readOpenForScan(file, limit)") {
		t.Error("the watcher no longer shares the sweep's reader, so a size limit is an escape again")
	}
	// And the regular-file test is on the descriptor rather than on a stat of
	// the path, which is the rule every root-run read here follows. It lives in
	// the shared reader now, so it is asserted where it actually is.
	shared := sourceOf(t, "antivirus.go")
	if !strings.Contains(shared, "func readOpenForScan(f *os.File, limit int64)") {
		t.Fatal("readOpenForScan moved; this test has to follow it")
	}
	if !strings.Contains(shared, "info, err := f.Stat()") ||
		!strings.Contains(shared, "info.Mode().IsRegular()") {
		t.Error("the regular-file test no longer runs on the descriptor")
	}
}

// A metadata version this build does not understand is FATAL, not a skipped
// event: every field after it, the descriptor included, is being read at an
// offset this binary does not know, so carrying on means closing arbitrary
// descriptors of our own.
func TestAnUnknownEventLayoutStopsTheWatcher(t *testing.T) {
	source := sourceOf(t, "watch_linux.go")
	version := strings.Index(source, "meta.Vers != unix.FANOTIFY_METADATA_VERSION")
	length := strings.Index(source, "meta.Event_len < eventMetaSize")
	switch {
	case version < 0:
		t.Fatal("the event layout version is no longer checked")
	case length < 0:
		t.Fatal("the event length is no longer checked")
	case version > length:
		t.Error("the length is read before the layout it is read from is known to match")
	}
	if !strings.Contains(source, `return fmt.Errorf("the kernel reports fanotify metadata version %d, "+`) {
		t.Error("a version mismatch no longer stops the watcher")
	}
}

// Every event carries a descriptor and the watcher must close each one. The
// kernel hands one out per event, so a leak here runs a busy server's watcher
// out of its file limit rather than leaking slowly.
func TestEveryEventDescriptorIsClosed(t *testing.T) {
	source := sourceOf(t, "watch_linux.go")
	if !strings.Contains(source, "defer func() { _ = file.Close() }()") {
		t.Error("the event descriptor is no longer closed on every path")
	}
	if !strings.Contains(source, "_ = unix.Close(fd)") {
		t.Error("a descriptor os.NewFile refused to wrap is no longer closed")
	}
}

// Notification mode, never permission mode. FAN_OPEN_PERM makes every open wait
// for the watcher, so a watcher that hangs freezes every site on the server. An
// antivirus feature must not be able to take the hosting down.
func TestTheWatcherCannotBlockAccessToAFile(t *testing.T) {
	source := sourceOf(t, "watch_linux.go")
	// The flags are matched with their unix. prefix, so the comment explaining
	// why permission mode was refused does not read as the code using it.
	if strings.Contains(source, "unix.FAN_OPEN_PERM") || strings.Contains(source, "unix.FAN_CLASS_CONTENT") {
		t.Error("the watcher runs in permission mode, where it can freeze file access")
	}
	if !strings.Contains(source, "unix.FAN_CLASS_NOTIF") {
		t.Error("the watcher is no longer in notification mode")
	}
	// CLOSE_WRITE, not MODIFY: MODIFY fires on every write() and a large upload
	// would be inspected hundreds of times, each time half-written.
	if !strings.Contains(source, "unix.FAN_CLOSE_WRITE") || strings.Contains(source, "unix.FAN_MODIFY") {
		t.Error("the watcher no longer inspects a file once, when its writer is done")
	}
}

// Turning the setting off ends the watcher with a ZERO status, or
// Restart=on-failure brings it straight back and it exits again for as long as
// the unit is enabled.
func TestTurningTheSettingOffEndsTheWatcherCleanly(t *testing.T) {
	source := sourceOf(t, "watch.go")
	if !strings.Contains(source, "errors.Is(err, errWatchDisabled)") {
		t.Fatal("a disabled watcher is no longer separated from a failing one")
	}
	if strings.Count(source, "errors.Is(err, errWatchDisabled)") < 2 {
		t.Error("the disabled case is handled at startup but not on a later refresh")
	}
}

// A settings read that FAILS keeps the settings the watcher already has. The
// other direction turns a database hiccup into a detection layer silently
// switching off, which is the opposite of what a watcher is for.
func TestAFailedRefreshKeepsTheCurrentSettings(t *testing.T) {
	source := sourceOf(t, "watch.go")
	idx := strings.Index(source, "settings, err := avsettings.Read(ctx, w.db)")
	if idx < 0 {
		t.Fatal("the refresh no longer reads the settings")
	}
	after := source[idx:]
	if !strings.Contains(after, "keeping the current ones") || !strings.Contains(after, "return nil") {
		t.Error("a failed refresh no longer keeps the settings the watcher has")
	}
}

// Each detection is its own finished scan row. One row held open for the
// watcher's lifetime would sit at 'running' for weeks, and HealRunningScans
// would mark it failed at the next panel restart, reporting every real-time
// detection as a scan that broke.
func TestADetectionIsRecordedAsItsOwnFinishedScan(t *testing.T) {
	source := sourceOf(t, "watch.go")
	if !strings.Contains(source, `"realtime", "finished", 1, 1, "heuristic", confined`) {
		t.Error("a detection is no longer recorded as one finished realtime scan")
	}
	if !strings.Contains(source, "insertSweepFinding(w.db, sid, domainID, finding)") {
		t.Error("the detection no longer writes a finding row")
	}
	// Whether the kernel confined it is read from this process's own cgroup,
	// never from what the unit asked for.
	if !strings.Contains(source, `strings.Contains(w.cgroup, "/"+avsettings.SliceName+"/")`) {
		t.Error("confinement is no longer decided by what the kernel actually did")
	}
}

// Location rules are judged against the TENANT HOME.
//
// The root decides exactly one rule and in one direction: a root that itself
// sits under a dotted directory leaves nothing dotted in the relative path, so
// every file beneath it stops looking hidden. The tenant home never contains a
// dot, which is why it is the root to use. The uploads and cache rules test the
// relative path with Contains and answer the same from any root above the file,
// so they cannot show the difference and are not what this is about.
func TestLocationRulesAreJudgedAgainstTheTenantHome(t *testing.T) {
	source := sourceOf(t, "watch.go")
	if !strings.Contains(source, "locationMatches(homePrefix+user, path)") {
		t.Error("the watcher no longer judges a path against the tenant home")
	}

	const hidden = "/home/c_demo/public_html/.cache/x.php"
	fromHome := locationMatches("/home/c_demo", hidden)
	fromInside := locationMatches("/home/c_demo/public_html/.cache", hidden)
	if !hasRule(fromHome, "Location.HiddenDirectory") {
		t.Error("a file in a hidden directory is not judged hidden from the tenant home")
	}
	if hasRule(fromInside, "Location.HiddenDirectory") {
		t.Error("this test no longer distinguishes the two roots")
	}
}

func hasRule(matches []match, name string) bool {
	for _, m := range matches {
		if m.name == name {
			return true
		}
	}
	return false
}

// The exclusion list is applied before anything is read, because on a
// single-filesystem host the mark covers the whole mount and the list is the
// only thing narrowing what the watcher touches.
func TestTheExclusionListIsAppliedBeforeTheFileIsRead(t *testing.T) {
	w := &watcher{settings: avsettings.Settings{
		RuleEngine:        true,
		CriticalThreshold: 100,
		ExcludedPaths:     "/var/lib/mysql\n/opt/servika",
	}}
	read := false
	w.inspect(context.Background(), "/var/lib/mysql/evil.php", func(int64) ([]byte, error) {
		read = true
		return []byte("<?php system($_GET['c']);"), nil
	})
	if read {
		t.Error("an excluded path was read")
	}
}

// A file the rules convict has to reach the record path. This exercises inspect
// itself rather than the fanotify plumbing, which needs a kernel.
func TestAWebshellClearsTheThresholdThroughTheWatchersOwnPath(t *testing.T) {
	dir := t.TempDir()
	shell := filepath.Join(dir, "shell.php")
	if err := os.WriteFile(shell, []byte("<?php system($_GET['cmd']);"), 0o600); err != nil {
		t.Fatal(err)
	}
	matches := evaluate(".php", []byte("<?php system($_GET['cmd']);"))
	_, _, _, level := verdict(matches, 100)
	if level != LevelCritical {
		t.Fatalf("the sample is not critical (%q), so this test proves nothing", level)
	}
	// And the watcher would open it: the extension is one it watches.
	if !watchable(shell) {
		t.Error("the watcher would not open the file it is meant to catch")
	}
}

// The mark kind, pinned on the CALL rather than on the comment beside it. The
// comment names both constants, so matching the bare word would pass whichever
// one the code actually uses.
//
// Measured against real systemd with the shipped unit, which carries
// ProtectSystem=strict: a mount mark is ACCEPTED, fanotify_mark returns
// success, and not one event is ever delivered, because strict builds the
// service its own namespace out of read-only binds and the mark lands on the
// service's private clone while tenants write through the host's. A filesystem
// mark is on the superblock both share and the event arrives. PrivateMounts=yes
// alone did not break the mount mark, so this is specific to what the unit
// ships. Nothing reports the broken state, which is why it is pinned.
func TestTheMarkIsOnTheFilesystemAndNotOnTheMount(t *testing.T) {
	body, err := os.ReadFile("watch_linux.go")
	if err != nil {
		t.Fatalf("the fanotify loop: %v", err)
	}
	src := string(body)
	if !strings.Contains(src, "unix.FAN_MARK_FILESYSTEM") {
		t.Error("the mark is not placed on the filesystem, so hardening leaves the watcher blind")
	}
	if strings.Contains(src, "unix.FAN_MARK_MOUNT") {
		t.Error("a mount mark is still placed; under ProtectSystem=strict it delivers no events at all")
	}
}

// The unit is what makes the limits real and the containment possible, and
// three of its lines are load-bearing in ways nothing in Go can check. Each was
// measured against real systemd with the shipped unit, and each has a falling
// path recorded beside it here.
func TestTheWatcherUnitCarriesWhatContainmentNeeds(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "assets", "systemd", "servika-av-watch.service"))
	if err != nil {
		t.Fatalf("the watcher unit: %v", err)
	}
	unit := string(body)

	// Without this the unit joins system.slice and every limit the settings
	// screen reports is enforced on nothing.
	if !strings.Contains(unit, "Slice="+avsettings.SliceName) {
		t.Error("the unit does not join the antivirus slice")
	}
	// The quarantine store lives OUTSIDE the tenant home, so /home alone is not
	// enough. Measured: with the store dropped from ReadWritePaths the watcher
	// still DETECTED the webshell and left it in the document root.
	if !strings.Contains(unit, "ReadWritePaths=/home -/var/lib/servika") {
		t.Error("the unit does not open both the tenant tree and the quarantine store for writing")
	}
	// The leading dash. Measured: with ProtectSystem=strict and the directory
	// absent, the unit dies at 226/NAMESPACE before the binary runs, so a
	// server that has never quarantined anything loses detection as well.
	if strings.Contains(unit, "ReadWritePaths=/home /var/lib/servika") {
		t.Error("the quarantine store is named without the leading dash, so an absent directory stops the unit")
	}
	// Reading a tenant file needs DAC_READ_SEARCH; REMOVING one from a
	// tenant-owned 0750 directory needs DAC_OVERRIDE. Measured: dropping it
	// left the watcher detecting and every containment failing.
	if !strings.Contains(unit, "CAP_DAC_OVERRIDE") {
		t.Error("the unit cannot remove a file from a tenant-owned directory")
	}
}
