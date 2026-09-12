package antivirus

import (
	"context"
	"errors"
	"testing"
	"time"

	"servika/internal/avsettings"
)

// The process watcher read process_monitor once at startup and never again, so
// it only ever stopped when avsettings.ApplyProcessMonitor ran systemctl
// disable. That call is skipped as soon as an earlier apply step fails, and the
// watcher then ran on with the setting stored as off. These tests measure the
// second line of defence the file watcher already had: the loop re-reads the
// switch and ends when it is off.

// procSwitchDB answers the settings read with one row carrying the switch.
func procSwitchDB(t *testing.T, on bool) *sqlScript {
	t.Helper()
	script := newScript()
	script.rows[avSettingsQuery] = avSettingsRow(avsettings.Settings{Scope: "home", ProcessMonitor: on})
	return script
}

func TestTheWatcherStopsWhenProcessMonitoringIsTurnedOff(t *testing.T) {
	script := procSwitchDB(t, false)

	if procMonitorStillOn(context.Background(), scriptDB(t, script)) {
		t.Error("the watcher goes on although the switch is off")
	}
}

func TestTheWatcherGoesOnWhileProcessMonitoringIsOn(t *testing.T) {
	script := procSwitchDB(t, true)

	if !procMonitorStillOn(context.Background(), scriptDB(t, script)) {
		t.Error("the watcher stopped although the switch is on")
	}
}

// A database that cannot be read must not turn a detection layer off. The file
// watcher makes the same choice in watcher.refresh.
func TestASettingsReadThatFailsKeepsTheWatcherRunning(t *testing.T) {
	script := newScript()
	script.fail[avSettingsQuery] = errors.New("connection reset")

	if !procMonitorStillOn(context.Background(), scriptDB(t, script)) {
		t.Error("a database hiccup stopped the watcher")
	}
}

// The two periodic jobs of the loop run on their own schedules, and each one
// re-arms when it fires: a deadline that stayed due would sweep and re-read on
// every single event.
func TestTheLoopsPeriodicWorkComesDueOnItsOwnSchedule(t *testing.T) {
	start := time.Now()
	timers := &procTimers{sweep: start, settings: start}

	if sweep, recheck := timers.due(start); sweep || recheck {
		t.Fatalf("work came due at once: sweep=%v recheck=%v", sweep, recheck)
	}
	atSweep := start.Add(procSweepInterval)
	sweep, recheck := timers.due(atSweep)
	if !sweep || recheck {
		t.Fatalf("at the sweep deadline: sweep=%v recheck=%v", sweep, recheck)
	}
	if sweep, _ := timers.due(atSweep); sweep {
		t.Error("the sweep deadline did not re-arm")
	}
	if _, recheck := timers.due(start.Add(procSettingsRefresh)); !recheck {
		t.Error("the switch was not re-read at its deadline")
	}
	if _, recheck := timers.due(start.Add(procSettingsRefresh)); recheck {
		t.Error("the settings deadline did not re-arm")
	}
}
