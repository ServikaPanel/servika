package avsettings

// Starting and stopping the process-behaviour watcher.
//
// It is a SEPARATE unit from the file watcher: the two answer different
// questions (files written vs processes executed), need different kernel
// capabilities (CAP_SYS_ADMIN for fanotify vs CAP_NET_ADMIN for the netlink proc
// connector), and are switched independently on the settings screen. The unit
// name is a string, so owning it here costs no import, exactly like WatchUnit.

import (
	"fmt"
	"strings"
)

// ProcWatchUnit is the systemd unit that runs `servika-server -proc-watch`.
const ProcWatchUnit = "servika-proc-watch.service"

// ApplyProcessMonitor brings the process watcher into line with the setting.
//
// It mirrors ApplyWatcher: a RESTART rather than a plain start, because the
// watcher subscribes to the netlink stream once at startup, and the result is
// NOT swallowed, because a watcher the panel believes it started and systemd
// never did watches nothing and says nothing.
func ApplyProcessMonitor(s Settings) error {
	if !systemdRunning() {
		return nil
	}
	if !s.ProcessMonitor {
		if out, err := sliceCommand("systemctl", "disable", "--now", ProcWatchUnit).CombinedOutput(); err != nil {
			return fmt.Errorf("stop the process watcher: %s: %w",
				strings.TrimSpace(string(out)), err)
		}
		return nil
	}
	if out, err := sliceCommand("systemctl", "enable", ProcWatchUnit).CombinedOutput(); err != nil {
		return fmt.Errorf("enable the process watcher: %s: %w",
			strings.TrimSpace(string(out)), err)
	}
	if out, err := sliceCommand("systemctl", "restart", ProcWatchUnit).CombinedOutput(); err != nil {
		return fmt.Errorf("start the process watcher: %s: %w",
			strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ProcWatchState is what systemd reports for the process watcher right now, so
// the screen can show whether it is really running rather than whether it was
// asked to. It mirrors WatchState.
func ProcWatchState() string {
	if !systemdRunning() {
		return KernelUnmeasured
	}
	out, _ := sliceCommand("systemctl", "is-active", ProcWatchUnit).CombinedOutput()
	state := strings.TrimSpace(string(out))
	if i := strings.IndexByte(state, '\n'); i >= 0 {
		state = strings.TrimSpace(state[:i])
	}
	if state == "" {
		return KernelUnmeasured
	}
	return state
}
