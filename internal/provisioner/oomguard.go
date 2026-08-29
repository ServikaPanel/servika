package provisioner

// oomguard.go — keep the database alive when the host runs out of memory.
//
// Production incident (2026-08-22): under a heavy NSS query load (a recursive
// find/getfacl scan) systemd-userdbd workers piled up to 4105 processes /
// 3.9 GB. The server had NO swap, so the kernel went straight to the OOM-killer
// and took the largest-RSS process, MariaDB. With the database dead every site
// answered 500/503, and it was killed a second time.
//
// Three measures break every link of that chain:
//  1. A CRITICAL notification when there is no swap: swap is the only buffer
//     between the panel and the OOM-killer. This file exposes SwapPresent; the
//     notification is raised in main, which imports internal/notifications
//     (provisioner cannot, because notifications imports middleware, which
//     imports back into provisioner). No swap file is created here, because that
//     spends disk and is the operator's decision to undo; the installer does it.
//  2. A memory and task ceiling on systemd-userdbd: a leak then kills that
//     service, not the sites, and systemd restarts it.
//  3. OOMScoreAdjust=-700 and Restart=always on MariaDB: the database is every
//     site's shared dependency, so it goes LAST on the OOM candidate list and
//     brings itself back up if it is killed anyway.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	userdbdOOMDropIn = "/etc/systemd/system/systemd-userdbd.service.d/servika-limits.conf"
	mariadbOOMDropIn = "/etc/systemd/system/mariadb.service.d/servika-oom.conf"
)

// SwapPresent reports whether /proc/swaps lists at least one active swap area.
// An unreadable table returns true so the caller does not raise a false alarm.
func SwapPresent() bool {
	b, err := os.ReadFile("/proc/swaps")
	if err != nil {
		return true
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return len(lines) > 1 // the first line is the header
}

// EnsureOOMGuard writes the two systemd drop-ins idempotently and reloads the
// manager when either changed. It does NOT restart either service: a restart
// would cut the running database, and the drop-in applies on the next start
// anyway. OOMScoreAdjust is the one setting that needs a restart, which the
// crash it defends against provides.
func EnsureOOMGuard() {
	changed := false

	userdbd := `[Service]
# Servika: a heavy NSS query load piled systemd-userdbd workers up to 3.9 GB and
# let the OOM-killer take MariaDB (2026-08-22 incident). This ceiling kills the
# service, not the sites, if it leaks; systemd then restarts it.
MemoryMax=384M
TasksMax=128
`
	if writeDropIn(userdbdOOMDropIn, userdbd, "MemoryMax=384M") {
		changed = true
	}

	mariadb := `[Service]
# Servika: the database is every site's shared dependency, so it goes LAST on the
# OOM candidate list. If it is killed anyway it brings itself back up.
OOMScoreAdjust=-700
Restart=always
RestartSec=5
`
	if writeDropIn(mariadbOOMDropIn, mariadb, "OOMScoreAdjust=-700") {
		changed = true
	}

	if changed {
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}
}

// writeDropIn writes content when the file is absent or does not already carry
// key. It reports whether it wrote, so the caller reloads systemd only on a real
// change.
func writeDropIn(path, content, key string) bool {
	// #nosec G304 -- path is a hardcoded systemd drop-in constant, never request input.
	if b, err := os.ReadFile(path); err == nil && strings.Contains(string(b), key) {
		return false
	}
	// #nosec G301 -- a systemd drop-in directory under /etc/systemd/system, 0755 per the systemd convention; it carries no secret.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false
	}
	// #nosec G306 -- a systemd drop-in the manager reads as root; it carries no secret.
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return false
	}
	return true
}
