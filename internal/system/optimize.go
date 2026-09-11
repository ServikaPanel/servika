// Package system provides server-level operations: usage, services, updates, and optimization.
package system

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"
)

const optimizeUnit = "servika-optimize-run"

func optimizeLogPath() string { return filepath.Join(config.LogDir(), "optimize.log") }

func optimizeWrapper() string { return filepath.Join(config.LogDir(), "optimize-run.sh") }

// optimizeWrapperContent is a FIXED wrapper script. No user input enters argv.
// dnf/yum -y update + servika-optimize. Each step is idempotent and safe.
const optimizeWrapperContent = `#!/usr/bin/env bash
set -uo pipefail
echo "========== Server Optimization -- $(date "+%Y-%m-%d %H:%M:%S") =========="
echo
echo "1/2 System package update (AlmaLinux)"
if command -v dnf >/dev/null 2>&1; then
  dnf -y update
elif command -v yum >/dev/null 2>&1; then
  yum -y update
else
  echo "  (dnf/yum not found -- package update skipped)"
fi
echo
echo "2/2 MariaDB / nginx / PHP performance tuning"
if command -v servika-optimize >/dev/null 2>&1; then
  servika-optimize
else
  echo "  (servika-optimize not found -- tuning skipped)"
fi
echo
echo "========== Optimization complete =========="
`

// optimizeRunning checks if the transient unit is still active.
func optimizeRunning() (bool, string) {
	d := strings.TrimSpace(runOutput("systemctl", "is-active", optimizeUnit))
	return d == "active" || d == "activating", d
}

func runOutput(name string, args ...string) string {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

// writeOptimizeWrapper atomically writes the wrapper script (0700).
func writeOptimizeWrapper() error {
	wrapper := optimizeWrapper()
	tmp := wrapper + ".tmp"
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(tmp, []byte(optimizeWrapperContent), 0o700); err != nil {
		return err
	}
	return os.Rename(tmp, wrapper)
}

// OptimizeStatus returns GET /system/optimize.
func OptimizeStatus(w http.ResponseWriter, r *http.Request) {
	running, status := optimizeRunning()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"running": running,
		"status":  status,
	})
}

// OptimizeStart starts POST /system/optimize/start.
func OptimizeStart(w http.ResponseWriter, r *http.Request) {
	running, _ := optimizeRunning()
	if running {
		httpx.WriteError(w, http.StatusConflict, "optimization is already running")
		return
	}
	if err := writeOptimizeWrapper(); err != nil {
		httpx.LogR(r, "optimize: write wrapper: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not start optimization")
		return
	}
	logPath := optimizeLogPath()
	wrapper := optimizeWrapper()
	if err := os.MkdirAll(filepath.Dir(logPath), 0o750); err != nil {
		httpx.LogR(r, "optimize: prepare log directory %s: %v", filepath.Dir(logPath), err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not start optimization")
		return
	}
	header := fmt.Sprintf("=== Optimization started: %s ===\n", time.Now().Format("2006-01-02 15:04:05"))
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(logPath, []byte(header), 0o640); err != nil {
		httpx.LogR(r, "optimize: open log %s: %v", logPath, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not start optimization")
		return
	}
	// systemd-run: transient unit under PID 1; output via append: to log file.
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	cmd := exec.Command("systemd-run",
		"--collect",
		"--unit", optimizeUnit,
		"--description", "Servika server optimization",
		"-p", "StandardOutput=append:"+logPath,
		"-p", "StandardError=append:"+logPath,
		wrapper)
	if out, err := cmd.CombinedOutput(); err != nil {
		httpx.LogR(r, "optimize: systemd-run start: %v: %s", err, strings.TrimSpace(string(out)))
		httpx.WriteError(w, http.StatusInternalServerError, "could not start optimization")
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

// OptimizeLog returns GET /system/optimize/log.
func OptimizeLog(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(optimizeLogPath())
	if err != nil {
		b = nil
	}
	s := string(b)
	const maxLog = 60000
	if len(s) > maxLog {
		s = s[len(s)-maxLog:]
	}
	running, status := optimizeRunning()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"log":     s,
		"running": running,
		"status":  status,
	})
}
