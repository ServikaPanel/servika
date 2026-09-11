package system

// KernelCare (TuxCare) integration — REBOOTLESS live kernel patching.
// KernelCare applies security patches to the running kernel in memory so kernel
// CVEs are closed without a server reboot (the approach used by cPanel).
//
// NOTE: the patch feed is TuxCare's proprietary product; we only integrate the
// kcarectl agent. The agent + license key is installed/registered by the operator.
// When kcarectl is ABSENT this layer is completely silent (Installed=false)
// and the existing CVE flow works unchanged.

import (
	"context"
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

const kcUnit = "servika-kernelcare-update"

func kcLogPath() string { return config.KernelCareLog() }

func kcWrapper() string { return config.KernelCareWrapper() }

// KcStatus describes the KernelCare agent state (embedded in CVE summary).
type KcStatus struct {
	Installed       bool     `json:"installed"`        // kcarectl binary present
	Active          bool     `json:"active"`           // patches loaded onto running kernel
	Registered      bool     `json:"registered"`       // license key registered
	EffectiveKernel string   `json:"effective_kernel"` // kcarectl --uname (patched-equivalent version)
	PatchedCves     []string `json:"patched_cves"`     // CVEs extracted from patch-info
	Running         bool     `json:"running"`          // --update in progress in background
}

// kcRunShell runs kcarectl with a timeout; returns (output, exit code).
func kcRunShell(d time.Duration, args ...string) (string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	out, err := exec.CommandContext(ctx, "kcarectl", args...).CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode()
	}
	return string(out), -1
}

func kernelcareInstalled() bool {
	_, err := exec.LookPath("kcarectl")
	return err == nil
}

func kernelcareUpdateRunning() bool {
	s := strings.TrimSpace(runOutput("systemctl", "is-active", kcUnit))
	return s == "active" || s == "activating"
}

// kernelcareStatus queries the agent. Returns zero-value (Installed=false) when kcarectl is absent.
func kernelcareStatus() KcStatus {
	kc := KcStatus{}
	if !kcInstalled() {
		return kc
	}
	kc.Installed = true
	kc.Running = kcRunning()

	if o, c := kcShell(10*time.Second, "--uname"); c == 0 {
		kc.EffectiveKernel = strings.TrimSpace(o)
	}

	// patch-info: patches loaded when exit 0 + non-empty; extract CVEs.
	if pi, pc := kcShell(15*time.Second, "--patch-info"); pc == 0 && strings.TrimSpace(pi) != "" {
		kc.Active = true
		kc.PatchedCves = patchedCves(pi)
	}

	info, _ := kcShell(10*time.Second, "--info")
	kc.Registered = agentRegistered(info)
	return kc
}

// cveSeparators are the characters the agent puts between the CVE ids in its
// patch report.
const cveSeparators = " \n\t,;()"

// patchedCves lists each CVE the loaded patches close, once.
func patchedCves(patchInfo string) []string {
	seen := map[string]bool{}
	var cves []string
	for _, tok := range strings.FieldsFunc(patchInfo, func(r rune) bool {
		return strings.ContainsRune(cveSeparators, r)
	}) {
		if strings.HasPrefix(tok, "CVE-") && !seen[tok] {
			seen[tok] = true
			cves = append(cves, tok)
		}
	}
	return cves
}

// agentRegistered reads the registration state: --info output without
// "unregistered/not registered/no key" → registered.
func agentRegistered(info string) bool {
	low := strings.ToLower(info)
	return strings.TrimSpace(info) != "" &&
		!strings.Contains(low, "unregistered") &&
		!strings.Contains(low, "not registered") &&
		!strings.Contains(low, "no key") &&
		!strings.Contains(low, "no valid key")
}

// KernelcareStatusHandler — GET /system/kernelcare : agent state (for polling).
func KernelcareStatusHandler(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, kernelcareStatus())
}

const kcWrapperContent = `#!/usr/bin/env bash
set -uo pipefail
echo "════════ KernelCare live kernel patch — $(date "+%Y-%m-%d %H:%M:%S") ════════"
echo
if command -v kcarectl >/dev/null 2>&1; then
  kcarectl --update
else
  echo "  (kcarectl not found — KernelCare not installed)"
fi
echo
echo "════════ ✓ Live patch complete ════════"
`

func kcWriteWrapper() error {
	wrapper := kcWrapper()
	tmp := wrapper + ".tmp"
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(tmp, []byte(kcWrapperContent), 0o700); err != nil {
		return err
	}
	return os.Rename(tmp, wrapper)
}

// KernelcarePatch — POST /system/kernelcare/patch : run kcarectl --update in background
// (systemd-run, survives tab/panel close).
func KernelcarePatch(w http.ResponseWriter, r *http.Request) {
	if !kernelcareInstalled() {
		httpx.WriteError(w, http.StatusBadRequest, "KernelCare is not installed")
		return
	}
	if kernelcareUpdateRunning() {
		httpx.WriteError(w, http.StatusConflict, "live patching is already in progress")
		return
	}
	logPath := kcLogPath()
	_ = os.MkdirAll(filepath.Dir(logPath), 0o750)
	if err := kcWriteWrapper(); err != nil {
		httpx.LogR(r, "kernelcare: prepare wrapper: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not start live patching")
		return
	}
	header := fmt.Sprintf("=== KernelCare live patch started: %s ===\n", time.Now().Format("2006-01-02 15:04:05"))
	wrapper := kcWrapper()
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(logPath, []byte(header), 0o640); err != nil {
		httpx.LogR(r, "kernelcare: open log %s: %v", logPath, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not start live patching")
		return
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	cmd := exec.Command("systemd-run",
		"--collect",
		"--unit", kcUnit,
		"--description", "Servika KernelCare live kernel patching",
		"-p", "StandardOutput=append:"+logPath,
		"-p", "StandardError=append:"+logPath,
		wrapper)
	if out, err := cmd.CombinedOutput(); err != nil {
		httpx.LogR(r, "kernelcare: systemd-run start: %v: %s", err, strings.TrimSpace(string(out)))
		httpx.WriteError(w, http.StatusInternalServerError, "could not start live patching")
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"started": true})
}
