package avsettings

// Handing the nightly sweep to a systemd timer.
//
// The panel has always swept from an in-process Go scheduler, and that is still
// the default. What a timer buys is a sweep that runs while the panel is down;
// what it costs is a SECOND thing that can start one, so the two must never be
// armed at once. `internal/backups` refuses a timer outright for exactly that
// reason, and the only thing that makes this different is this file: the hour
// the operator picked is written INTO the timer, and the in-process scheduler
// stands down whenever the timer is enabled.
//
// Every rule below was measured against real systemd, and each closes a hole
// that is invisible from the unit file alone.

import (
	"fmt"
	"os"
	"strings"
)

const (
	// ScanTimer is the systemd timer that starts `servika-server -av-sweep`.
	ScanTimer = "servika-av-scan.timer"
	// ScanService is the unit the timer starts. It is named here because
	// disabling the feature has to stop a sweep that is running right now, and
	// stopping a timer does not stop the service it already started.
	ScanService = "servika-av-scan.service"

	scanTimerDropInDir  = sliceDir + "/" + ScanTimer + ".d"
	scanTimerDropInFile = "10-servika-hour.conf"
)

// These are variables so a test can assert what was written without root and
// without touching the host's systemd directory.
var (
	scanTimerDropInDirForTest = scanTimerDropInDir
	scanTimerDropInPath       = scanTimerDropInDir + "/" + scanTimerDropInFile
)

// ScanTimerDropIn is the drop-in body for an hour.
//
// The EMPTY `OnCalendar=` is the whole point and is not tidiness. OnCalendar is
// a LIST, and a drop-in ADDS to whatever the unit file already declares:
// measured, a base of 04:00 plus a drop-in of 07:00 leaves the timer firing at
// BOTH, so an operator who moved the sweep to the morning would get two sweeps
// a day and the old hour would never go away. An empty assignment resets the
// list, and the value after it is then the only one.
func ScanTimerDropIn(hour int) string {
	return fmt.Sprintf("# Written by Servika from av_settings.scheduled_hour. Do not edit.\n"+
		"[Timer]\nOnCalendar=\nOnCalendar=*-*-* %02d:00:00\n", hour)
}

// ApplyScheduleTimer brings the timer into line with the settings.
//
// Turning the feature OFF disables the timer AND stops the service, because a
// sweep already under way is not stopped by disarming the thing that started
// it, and an operator who switches the sweep off while one is running means the
// running one.
//
// Turning it ON writes the drop-in, reloads, and enables. A `restart` of the
// timer is deliberately absent: measured, `daemon-reload` alone re-arms a
// running timer against the new calendar (NextElapseUSecRealtime moved from
// 07:00 to 21:00 without one), so a restart would only be a disarm-and-rearm
// with no effect anybody could observe.
func ApplyScheduleTimer(s Settings) error {
	if !systemdRunning() {
		return nil
	}
	if !s.ScheduledScan {
		if out, err := sliceCommand("systemctl", "disable", "--now", ScanTimer).CombinedOutput(); err != nil {
			return fmt.Errorf("stop the scheduled sweep timer: %s: %w",
				strings.TrimSpace(string(out)), err)
		}
		// Stopping the timer does not stop a sweep it already started.
		if out, err := sliceCommand("systemctl", "stop", ScanService).CombinedOutput(); err != nil {
			return fmt.Errorf("stop a sweep already running: %s: %w",
				strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	// #nosec G301 -- a systemd drop-in directory is read by the manager as root and carries no secret.
	if err := os.MkdirAll(scanTimerDropInDirForTest, 0o755); err != nil {
		return fmt.Errorf("create the sweep timer drop-in directory: %w", err)
	}
	// #nosec G306 -- systemd reads unit files as root; 0644 matches every other unit this panel writes.
	if err := os.WriteFile(scanTimerDropInPath, []byte(ScanTimerDropIn(s.ScheduledHour)), 0644); err != nil {
		return fmt.Errorf("write the sweep hour: %w", err)
	}
	if out, err := sliceCommand("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("reload systemd after writing the sweep hour: %s: %w",
			strings.TrimSpace(string(out)), err)
	}
	if out, err := sliceCommand("systemctl", "enable", "--now", ScanTimer).CombinedOutput(); err != nil {
		return fmt.Errorf("start the scheduled sweep timer: %s: %w",
			strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ScanTimerEnabled reports whether systemd owns the schedule right now.
//
// The in-process scheduler asks this before every tick, so the two can never be
// armed at once. It answers FALSE on a host with no systemd and on any failure,
// which is the safe direction here: the in-process scheduler is the default and
// the one that works everywhere, and the sweep process refuses a second sweep
// inside the gap anyway, so the worst a wrong answer costs is a sweep started
// by the panel instead of by the timer.
func ScanTimerEnabled() bool {
	if !systemdRunning() {
		return false
	}
	return sliceCommand("systemctl", "is-enabled", "--quiet", ScanTimer).Run() == nil
}

// ScanTimerHour reports the hour the drop-in on disk actually names, and
// whether it could be read at all.
//
// The panel reads the FILE rather than the database, because the two are what a
// disagreement is between: a drop-in that failed to write leaves the timer
// firing at the old hour while the settings screen shows the new one, and
// nothing else on the server would say so.
func ScanTimerHour() (int, bool) {
	b, err := os.ReadFile(scanTimerDropInPath)
	if err != nil {
		return 0, false
	}
	// The LAST assignment wins in systemd, which is the same rule
	// panelport.ReadEnvListen follows, and here it is also what makes the empty
	// reset above safe to parse past.
	hour, found := -1, false
	for line := range strings.SplitSeq(string(b), "\n") {
		line = strings.TrimSpace(line)
		value, ok := strings.CutPrefix(line, "OnCalendar=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue // the reset
		}
		var h, m, sec int
		if _, err := fmt.Sscanf(value, "*-*-* %d:%d:%d", &h, &m, &sec); err != nil {
			continue
		}
		if h < 0 || h > 23 {
			continue
		}
		hour, found = h, true
	}
	return hour, found
}
