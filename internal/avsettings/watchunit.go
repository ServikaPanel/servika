package avsettings

// Starting and stopping the real-time watcher.
//
// The unit is named here rather than in internal/antivirus for the same reason
// the slice is: this package owns what the operator asked for, and the watcher
// is one of those things. A unit name is a string, so owning it costs this
// package no import.

import (
	"fmt"
	"os"
	"strings"
)

// WatchUnit is the systemd unit that runs `servika-server -av-watch`.
const WatchUnit = "servika-av-watch.service"

// systemdRunning reports whether there is a systemd to talk to at all.
//
// A development machine or a container has none, and failing the operator's
// save there would be reporting their input as wrong when nothing about it is.
// This is the same test internal/antivirus makes before it tries to confine a
// scan.
func systemdRunning() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// ApplyWatcher brings the watcher into line with the setting.
//
// A RESTART rather than a plain start, because the scan roots are read once
// when the watcher places its fanotify marks: a scope changed from host to
// server would otherwise take effect at the next reboot, while the screen said
// it was already in force.
//
// The result is NOT swallowed. A watcher the panel believes it started and
// systemd never did is the failure this whole feature is least able to notice
// on its own: nothing is watched, and nothing says so.
func ApplyWatcher(s Settings) error {
	if !systemdRunning() {
		return nil
	}
	if !s.Realtime {
		if out, err := sliceCommand("systemctl", "disable", "--now", WatchUnit).CombinedOutput(); err != nil {
			return fmt.Errorf("stop the antivirus watcher: %s: %w",
				strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	if out, err := sliceCommand("systemctl", "enable", WatchUnit).CombinedOutput(); err != nil {
		return fmt.Errorf("enable the antivirus watcher: %s: %w",
			strings.TrimSpace(string(out)), err)
	}
	// `enable --now` does NOT restart a unit that is already running, which is
	// the measured trap servika-install.sh carries a comment about. A settings
	// save has to reach a watcher that was already up, so the start is explicit
	// and unconditional.
	if out, err := sliceCommand("systemctl", "restart", WatchUnit).CombinedOutput(); err != nil {
		return fmt.Errorf("start the antivirus watcher: %s: %w",
			strings.TrimSpace(string(out)), err)
	}
	return nil
}

// WatchState is what systemd reports for the watcher right now, so the screen
// can show whether it is really running rather than whether it was asked to.
func WatchState() string {
	if !systemdRunning() {
		return KernelUnmeasured
	}
	// is-active prints the state on stdout AND exits non-zero for anything but
	// active, so a non-zero status is an ANSWER rather than a failure to
	// measure. Only an empty output is unmeasured. Take the FIRST line, because
	// that is the state and anything after it is not.
	out, _ := sliceCommand("systemctl", "is-active", WatchUnit).CombinedOutput()
	state := strings.TrimSpace(string(out))
	if i := strings.IndexByte(state, '\n'); i >= 0 {
		state = strings.TrimSpace(state[:i])
	}
	if state == "" {
		return KernelUnmeasured
	}
	return state
}
