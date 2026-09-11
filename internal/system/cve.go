package system

// CVE / security audit — AlmaLinux dnf updateinfo (ALSA→CVE mapping) summary of known
// vulnerabilities on the server's own OS + one-click security update.
//
// SECURITY: commands are FIXED (argv-only, no user input). Scan is read-only.
// Patch (dnf --security) takes a long time and may affect services — runs via
// systemd-run in a SEPARATE transient unit under PID 1 (survives tab/panel close,
// dnf-lock safe). Same pattern as optimise/update.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"
)

const cveUnit = "servika-cve-update"

func cveLogPath() string { return config.CVELog() }

const cveWrapper = "/opt/servika/cve-update.sh"

// CveEntry represents a single CVE advisory.
type CveEntry struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // critical | important | moderate | low
	Package  string `json:"package"`
}

// CveSummary is the full CVE status payload for the dashboard widget.
type CveSummary struct {
	Critical        int        `json:"critical"`
	Important       int        `json:"important"`
	Moderate        int        `json:"moderate"`
	Low             int        `json:"low"`
	TotalCves       int        `json:"total_cves"`
	TotalAdvisories int        `json:"total_advisories"`
	LastScan        string     `json:"last_scan"`
	TopCves         []CveEntry `json:"top_cves"`
	UpdateRunning   bool       `json:"update_running"`
	RebootRequired  bool       `json:"reboot_required"`
	KernelCare      KcStatus   `json:"kernelcare"`
}

var (
	cveMu      sync.Mutex
	cveCache   *CveSummary
	cveCacheTs time.Time
)

const cveCacheTTL = 30 * time.Minute

// cveRunShell runs dnf with a timeout (prevents hung metadata fetch).
func cveRunShell(d time.Duration, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	out, _ := exec.CommandContext(ctx, "dnf", args...).Output()
	return string(out)
}

func cveUpdateRunning() bool {
	s := strings.TrimSpace(runOutput("systemctl", "is-active", cveUnit))
	return s == "active" || s == "activating"
}

// rebootRequired returns true when the latest INSTALLED kernel differs from the
// running kernel. A security-patched kernel was installed but not yet booted,
// so kernel CVEs remain "open" (dnf: "installed security update" ≠ "running").
func rebootRequired() bool {
	running := strings.TrimSpace(runOutput("uname", "-r"))
	if running == "" {
		return false
	}
	// rpm -q --last kernel: most recently installed kernel is the first line.
	for ln := range strings.SplitSeq(runOutput("rpm", "-q", "--last", "kernel"), "\n") {
		f := strings.Fields(ln)
		if len(f) == 0 {
			continue
		}
		newest := strings.TrimPrefix(f[0], "kernel-")
		return newest != "" && newest != running
	}
	return false
}

var cveWeight = map[string]int{"critical": 4, "important": 3, "moderate": 2, "low": 1}

func cveLabel(sev string) string {
	switch {
	case strings.Contains(sev, "critical"):
		return "critical"
	case strings.Contains(sev, "important"):
		return "important"
	case strings.Contains(sev, "moderate"):
		return "moderate"
	case strings.Contains(sev, "low"):
		return "low"
	}
	return ""
}

// cveScan parses dnf updateinfo output (read-only).
// The same CVE may appear for multiple packages → counts UNIQUE CVEs
// (highest severity per CVE). Returns the real distinct vulnerability count,
// not raw line count.
func cveScan() *CveSummary {
	s := &CveSummary{LastScan: time.Now().Format("2006-01-02 15:04")}
	// CVE list line: "CVE-2025-68724  Important/Sec. kernel-...x86_64"
	sevOf := map[string]string{} // cveID → highest severity label
	pkgOf := map[string]string{} // cveID → example package at that severity
	for ln := range strings.SplitSeq(cveShell(150*time.Second, "-q", "updateinfo", "list", "cves"), "\n") {
		f := strings.Fields(ln)
		if len(f) < 3 || !strings.HasPrefix(f[0], "CVE-") {
			continue
		}
		id, label, pkg := f[0], cveLabel(strings.ToLower(f[1])), f[len(f)-1]
		if label == "" {
			continue
		}
		if cveWeight[label] > cveWeight[sevOf[id]] {
			sevOf[id] = label
			pkgOf[id] = pkg
		}
	}
	// Unique CVE counts + collect for priority-sorted top list.
	var criticalIDs, importantIDs []string
	for id, sev := range sevOf {
		s.TotalCves++
		switch sev {
		case "critical":
			s.Critical++
			criticalIDs = append(criticalIDs, id)
		case "important":
			s.Important++
			importantIDs = append(importantIDs, id)
		case "moderate":
			s.Moderate++
		case "low":
			s.Low++
		}
	}
	// Top list: critical first (sorted by ID), then important — at most 10 (deterministic).
	sort.Strings(criticalIDs)
	sort.Strings(importantIDs)
	for _, id := range append(criticalIDs, importantIDs...) {
		if len(s.TopCves) >= 10 {
			break
		}
		s.TopCves = append(s.TopCves, CveEntry{ID: id, Severity: sevOf[id], Package: pkgOf[id]})
	}
	// Total advisory count (summary): "    15 Security notice(s)"
	for ln := range strings.SplitSeq(cveShell(60*time.Second, "-q", "updateinfo", "--summary"), "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasSuffix(t, "Security notice(s)") &&
			!strings.Contains(t, "Critical") && !strings.Contains(t, "Important") &&
			!strings.Contains(t, "Moderate") && !strings.Contains(t, "Low") {
			var n int
			if _, err := fmt.Sscanf(t, "%d", &n); err == nil {
				s.TotalAdvisories = n
			}
		}
	}
	return s
}

// CveStatus — GET /system/cve : cached summary (refresh=1 to force re-scan).
func CveStatus(w http.ResponseWriter, r *http.Request) {
	cveMu.Lock()
	defer cveMu.Unlock()
	updating := cveUpdateRunning()
	kc := kernelcareStatus()
	// KernelCare live-patches the running kernel → reboot NOT required (rebootless protection).
	reboot := rebootRequired() && !kc.Active
	force := r.URL.Query().Get("refresh") == "1"
	// While a security update is in progress dnf/rpm holds the lock; re-running
	// dnf updateinfo would hit the lock → return the current cache without refresh.
	if cveCache != nil && (updating || (!force && time.Since(cveCacheTs) <= cveCacheTTL)) {
		s := *cveCache
		s.UpdateRunning = updating
		s.RebootRequired = reboot
		s.KernelCare = kc
		httpx.WriteJSON(w, http.StatusOK, s)
		return
	}
	if updating { // no cache + update in progress: don't hit the lock, return the flag.
		httpx.WriteJSON(w, http.StatusOK, CveSummary{UpdateRunning: true, RebootRequired: reboot, KernelCare: kc})
		return
	}
	cveCache = cveScan()
	cveCacheTs = time.Now()
	s := *cveCache
	s.RebootRequired = reboot
	s.KernelCare = kc
	httpx.WriteJSON(w, http.StatusOK, s)
}

const cveWrapperContent = `#!/usr/bin/env bash
set -uo pipefail
echo "════════ Security updates — $(date "+%Y-%m-%d %H:%M:%S") ════════"
echo
if command -v dnf >/dev/null 2>&1; then
  dnf -y --refresh update --security
elif command -v yum >/dev/null 2>&1; then
  yum -y update --security
else
  echo "  (dnf/yum not found — update skipped)"
fi
echo
echo "════════ ✓ Security updates complete ════════"
`

func cveWriteWrapper() error {
	tmp := cveWrapper + ".tmp"
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(tmp, []byte(cveWrapperContent), 0o700); err != nil {
		return err
	}
	return os.Rename(tmp, cveWrapper)
}

// CveUpdate — POST /system/cve/update : install security updates in background.
func CveUpdate(w http.ResponseWriter, r *http.Request) {
	if cveUpdateRunning() {
		httpx.WriteError(w, http.StatusConflict, "security update is already in progress")
		return
	}
	if running, _ := optimizeRunning(); running {
		httpx.WriteError(w, http.StatusConflict, "optimization is in progress — try again when it finishes")
		return
	}
	if running := updateRunning(); running {
		httpx.WriteError(w, http.StatusConflict, "panel update is in progress — try again when it finishes")
		return
	}
	logPath := cveLogPath()
	_ = os.MkdirAll(filepath.Dir(logPath), 0o750)
	if err := cveWriteWrapper(); err != nil {
		httpx.LogR(r, "cve update: prepare wrapper: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not start security update")
		return
	}
	header := fmt.Sprintf("=== Security update started: %s ===\n", time.Now().Format("2006-01-02 15:04:05"))
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(logPath, []byte(header), 0o640); err != nil {
		httpx.LogR(r, "cve update: open log %s: %v", logPath, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not start security update")
		return
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	cmd := exec.Command("systemd-run",
		"--collect",
		"--unit", cveUnit,
		"--description", "Servika security updates",
		"-p", "StandardOutput=append:"+logPath,
		"-p", "StandardError=append:"+logPath,
		cveWrapper)
	if out, err := cmd.CombinedOutput(); err != nil {
		httpx.LogR(r, "cve update: systemd-run start: %v: %s", err, strings.TrimSpace(string(out)))
		httpx.WriteError(w, http.StatusInternalServerError, "could not start security update")
		return
	}
	// Reset cache — post-update re-scan refreshes.
	cveMu.Lock()
	cveCache = nil
	cveMu.Unlock()
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

// CveLog — GET /system/cve/log : update log tail + status.
func CveLog(w http.ResponseWriter, r *http.Request) {
	b, _ := os.ReadFile(cveLogPath())
	s := string(b)
	if len(s) > 60000 {
		s = s[len(s)-60000:]
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"log":     s,
		"running": cveUpdateRunning(),
	})
}
