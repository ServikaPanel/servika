package apps

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// Status is what the panel can say about a running application.
type Status struct {
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	Restarts    string `json:"restarts"`
	Installed   bool   `json:"installed"`
}

// UnitStatus reads systemd's view of one application.
func UnitStatus(id int64) Status {
	status := Status{}
	if _, err := os.Stat(UnitPath(id)); err == nil {
		status.Installed = true
	}
	output, err := runSystemCommand("systemctl", "show",
		"-p", "ActiveState", "-p", "SubState", "-p", "NRestarts", UnitName(id)).Output()
	if err != nil {
		return status
	}
	for line := range strings.SplitSeq(string(output), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch key {
		case "ActiveState":
			status.ActiveState = strings.TrimSpace(value)
		case "SubState":
			status.SubState = strings.TrimSpace(value)
		case "NRestarts":
			status.Restarts = strings.TrimSpace(value)
		}
	}
	return status
}

// InstallUnit writes the unit file and reloads systemd.
func InstallUnit(id int64, body string) error {
	// #nosec G306 -- root-owned systemd unit that PID 1 must read; the secrets live in the EnvironmentFile beside it.
	if err := os.WriteFile(UnitPath(id), []byte(body), 0o644); err != nil {
		return fmt.Errorf("write the unit: %w", err)
	}
	if output, err := runSystemCommand("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("reload systemd: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// Enable starts an application and makes it survive a reboot.
func Enable(id int64) error {
	if output, err := runSystemCommand("systemctl", "enable", "--now", UnitName(id)).CombinedOutput(); err != nil {
		return fmt.Errorf("start the application: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// Disable stops an application and keeps it stopped across a reboot.
//
// Stopping alone is not enough anywhere it matters: the unit carries
// Restart=always, so a process killed by anything other than systemd comes
// straight back.
func Disable(id int64) error {
	if output, err := runSystemCommand("systemctl", "disable", "--now", UnitName(id)).CombinedOutput(); err != nil {
		return fmt.Errorf("stop the application: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// Restart restarts an application in place.
func Restart(id int64) error {
	if output, err := runSystemCommand("systemctl", "restart", UnitName(id)).CombinedOutput(); err != nil {
		return fmt.Errorf("restart the application: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// Teardown removes everything one application left on the host. It is best
// effort per step so a missing piece does not strand the rest.
func Teardown(id int64) {
	_, _ = runSystemCommand("systemctl", "disable", "--now", UnitName(id)).CombinedOutput()
	_ = os.Remove(UnitPath(id))
	_, _ = runSystemCommand("systemctl", "daemon-reload").CombinedOutput()
	_, _ = runSystemCommand("systemctl", "reset-failed", UnitName(id)).CombinedOutput()
	_ = os.Remove(EnvPath(id))
	_ = os.Remove(LogPath(id))
}

// maxLogBytes bounds what a log poll pulls into memory.
const maxLogBytes = 60000

// LogTail returns the end of an application's log.
//
// The open is O_NOFOLLOW with a regular-file check on the DESCRIPTOR because the
// application itself runs as the tenant: even though the panel owns the
// directory, the file the tenant's process appends to is read back here.
func LogTail(id int64) string {
	path := LogPath(id)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	// #nosec G304 -- a fixed path this package owns, named after a row id.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return ""
	}
	if stat.Size() > maxLogBytes {
		if _, err := file.Seek(-maxLogBytes, io.SeekEnd); err != nil {
			return ""
		}
	}
	body, err := io.ReadAll(io.LimitReader(file, maxLogBytes))
	if err != nil {
		return ""
	}
	return string(body)
}
