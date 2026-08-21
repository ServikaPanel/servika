package avsettings

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// OnCalendar is a LIST and a drop-in ADDS to it. Measured against real systemd:
// a base unit of 04:00 plus a drop-in naming 07:00 leaves the timer reporting
// BOTH, so an operator who moved the sweep to the morning would get two sweeps a
// day and the old hour would never go away. The empty assignment resets the
// list, and after it the drop-in's value is the only one.
func TestTheDropInResetsTheCalendarBeforeSettingIt(t *testing.T) {
	body := ScanTimerDropIn(21)
	reset := strings.Index(body, "OnCalendar=\n")
	value := strings.Index(body, "OnCalendar=*-*-* 21:00:00")
	switch {
	case reset < 0:
		t.Fatal("the drop-in no longer resets the calendar, so the placeholder hour survives beside it")
	case value < 0:
		t.Fatal("the drop-in no longer sets an hour")
	case reset > value:
		t.Error("the reset comes after the value, so it erases the hour it just set")
	}
	if !strings.Contains(body, "[Timer]") {
		t.Error("the drop-in has no [Timer] section, so systemd ignores the setting")
	}
}

// The hour is zero-padded. systemd accepts `4:00:00`, but the value is also read
// back by ScanTimerHour and by servika-verify, and one spelling everywhere is
// what lets those compare it without normalising first.
func TestTheHourIsWrittenWithTwoDigits(t *testing.T) {
	if !strings.Contains(ScanTimerDropIn(4), "*-*-* 04:00:00") {
		t.Error("a single-digit hour is not padded")
	}
}

// What the panel reads back is the FILE, because a drop-in that failed to write
// leaves the timer firing at the old hour while the settings screen shows the
// new one, and nothing else on the server would say so.
func TestTheHourIsReadBackFromTheFileThatWasWritten(t *testing.T) {
	dir := t.TempDir()
	restore := scanTimerDropInPath
	scanTimerDropInPath = dir + "/10-servika-hour.conf"
	t.Cleanup(func() { scanTimerDropInPath = restore })

	if _, ok := ScanTimerHour(); ok {
		t.Error("an absent drop-in reported an hour")
	}
	if err := os.WriteFile(scanTimerDropInPath, []byte(ScanTimerDropIn(7)), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	hour, ok := ScanTimerHour()
	if !ok || hour != 7 {
		t.Errorf("read back hour %d ok=%v, want 7 true", hour, ok)
	}
	// The reset line must not be read as an hour, and the LAST assignment wins.
	if err := os.WriteFile(scanTimerDropInPath,
		[]byte("[Timer]\nOnCalendar=*-*-* 03:00:00\nOnCalendar=\nOnCalendar=*-*-* 19:00:00\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if hour, ok := ScanTimerHour(); !ok || hour != 19 {
		t.Errorf("read back hour %d ok=%v, want 19 true", hour, ok)
	}
}

// Switching the sweep off has to stop a sweep that is running right now.
// Disarming a timer does not stop the service it already started, so an operator
// who turns the feature off while a sweep is under way would watch it carry on.
func TestSwitchingTheSweepOffAlsoStopsASweepAlreadyRunning(t *testing.T) {
	restoreSystemd := systemdRunning
	systemdRunning = func() bool { return true }
	t.Cleanup(func() { systemdRunning = restoreSystemd })

	var calls [][]string
	restore := sliceCommand
	sliceCommand = func(name string, arg ...string) *exec.Cmd {
		calls = append(calls, append([]string{name}, arg...))
		return exec.Command("true")
	}
	t.Cleanup(func() { sliceCommand = restore })

	if err := ApplyScheduleTimer(Settings{ScheduledScan: false}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	var disabled, stopped bool
	for _, c := range calls {
		line := strings.Join(c, " ")
		if strings.Contains(line, "disable --now "+ScanTimer) {
			disabled = true
		}
		if strings.Contains(line, "stop "+ScanService) {
			stopped = true
		}
	}
	if !disabled {
		t.Error("the timer is no longer disarmed")
	}
	if !stopped {
		t.Error("a sweep already running is no longer stopped")
	}
}

// systemd is reloaded BEFORE the timer is enabled, or the enable arms the timer
// against the calendar systemd still has in memory, which is the previous hour.
func TestTheHourReachesSystemdBeforeTheTimerIsArmed(t *testing.T) {
	restoreSystemd := systemdRunning
	systemdRunning = func() bool { return true }
	t.Cleanup(func() { systemdRunning = restoreSystemd })

	var calls []string
	restore := sliceCommand
	sliceCommand = func(name string, arg ...string) *exec.Cmd {
		calls = append(calls, strings.Join(append([]string{name}, arg...), " "))
		return exec.Command("true")
	}
	t.Cleanup(func() { sliceCommand = restore })

	dir := t.TempDir()
	restorePath := scanTimerDropInPath
	restoreDir := scanTimerDropInDirForTest
	scanTimerDropInPath = dir + "/10-servika-hour.conf"
	scanTimerDropInDirForTest = dir
	t.Cleanup(func() {
		scanTimerDropInPath = restorePath
		scanTimerDropInDirForTest = restoreDir
	})

	if err := ApplyScheduleTimer(Settings{ScheduledScan: true, ScheduledHour: 5}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	reload, enable := -1, -1
	for i, c := range calls {
		if strings.Contains(c, "daemon-reload") {
			reload = i
		}
		if strings.Contains(c, "enable --now "+ScanTimer) {
			enable = i
		}
	}
	switch {
	case reload < 0:
		t.Fatal("systemd is never reloaded, so the new hour is not read")
	case enable < 0:
		t.Fatal("the timer is never armed")
	case reload > enable:
		t.Error("the timer is armed before systemd re-reads the hour, so it arms on the previous one")
	}
	body, err := os.ReadFile(scanTimerDropInPath)
	if err != nil {
		t.Fatalf("the drop-in was not written: %v", err)
	}
	if !strings.Contains(string(body), "*-*-* 05:00:00") {
		t.Errorf("the drop-in does not carry the chosen hour: %s", body)
	}
}
