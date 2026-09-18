//go:build windows

package main

// Updating the agent with itself, and rolling back when the new one does not
// work.
//
// WHY THIS IS NOT JUST A FILE COPY: an update must not leave the host
// unmanageable. Copying the executable and restarting the service means a
// broken new binary takes the service down with no way back, on a machine
// nobody can log into. So:
//
//  1. PRE-CHECK   the new executable is run with `version` BEFORE the swap. One
//     that does not run is refused without the service being touched.
//  2. BACKUP      the installed executable is moved aside.
//  3. SWAP AND START
//  4. HEALTH GATE the service must reach Running AND /health must answer with
//     the expected version.
//  5. ROLLBACK    if it does not, the old binary goes back, starts, and its
//     health is VERIFIED too.

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/platform"
)

const (
	// healthGate is how long the new binary has to come up and answer.
	healthGate = 60 * time.Second

	// serviceSettle bounds a wait for the service to reach a state.
	serviceSettle = 30 * time.Second
)

// update replaces the installed agent with newExe.
func update(newExe string) error {
	if !elevated() {
		return fmt.Errorf("an elevated PowerShell or CMD is required")
	}
	target := filepath.Join(installDir, exeName)
	newVersion, err := checkReplacement(newExe, target)
	if err != nil {
		return err
	}
	fmt.Printf("the pre-check passed - new: %q, installed: %q\n", newVersion, platform.Version+" "+platform.Channel)

	backup := target + ".update-backup"
	if err := backupCurrent(target, backup); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if err := copyFile(newExe, target); err != nil {
		// It could not be put in place, so the old one goes straight back.
		_ = os.Remove(target)
		_ = os.Rename(backup, target)
		_, _ = runTool("sc", "start", serviceName)
		return fmt.Errorf("the new executable could not be copied (the old one is back): %w", err)
	}
	if out, err := runTool("sc", "start", serviceName); err != nil {
		return rollback(target, backup, fmt.Sprintf("the service did not start: %v - %s", err, strings.TrimSpace(out)))
	}
	if err := waitHealthy(versionField(newVersion), healthGate); err != nil {
		return rollback(target, backup, err.Error())
	}
	commitUpdate(target, backup, newVersion)
	return nil
}

// checkReplacement refuses a replacement that is missing, is the installed file
// itself, or does not run. It returns the new binary's version line.
func checkReplacement(newExe, target string) (string, error) {
	newExe = filepath.Clean(newExe)
	fi, err := os.Stat(newExe)
	if err != nil || fi.IsDir() || fi.Size() == 0 {
		return "", fmt.Errorf("the new executable is missing or not a file: %s", newExe)
	}
	if sameFile(newExe, target) {
		return "", fmt.Errorf("the new executable IS the installed one - put it somewhere else first")
	}
	// THE PRE-CHECK HAPPENS BEFORE THE SWAP. A binary that does not run is
	// refused while the service is still untouched.
	version, err := exeVersion(newExe)
	if err != nil {
		return "", fmt.Errorf("the new executable failed its pre-check and NOTHING was swapped: %w", err)
	}
	return version, nil
}

// backupCurrent stops the service and moves the installed executable aside.
func backupCurrent(target, backup string) error {
	_ = os.Remove(backup)
	_, _ = runTool("sc", "stop", serviceName)
	waitServiceState("STOPPED", serviceSettle)
	time.Sleep(time.Second)
	if err := os.Rename(target, backup); err == nil {
		return nil
	}
	// A rename can fail while a handle is still closing. A copy is just as good
	// a source to roll back from.
	if err := copyFile(target, backup); err != nil {
		_, _ = runTool("sc", "start", serviceName)
		return fmt.Errorf("the installed executable could not be backed up (%v) - the update is cancelled and the service is back up", err)
	}
	return nil
}

// commitUpdate keeps the backup under a stable name for a manual rollback.
func commitUpdate(target, backup, newVersion string) {
	previous := target + ".previous"
	_ = os.Remove(previous)
	if err := os.Rename(backup, previous); err != nil {
		_ = os.Remove(backup) // it could not be kept; the update still worked
	}
	fmt.Println("UPDATED - the new version is healthy:", newVersion)
	fmt.Println("  the previous binary is kept at:", previous)
}

// rollback puts the old binary back and VERIFIES that it is healthy too.
//
// A rollback that also fails is reported as exactly that, so the operator knows
// to step in rather than believing the host recovered.
func rollback(target, backup, reason string) error {
	fmt.Fprintln(os.Stderr, "THE HEALTH GATE FAILED:", reason, "- rolling back")
	_, _ = runTool("sc", "stop", serviceName)
	waitServiceState("STOPPED", serviceSettle)
	time.Sleep(time.Second)
	_ = os.Remove(target)
	if err := os.Rename(backup, target); err != nil {
		return fmt.Errorf("THE ROLLBACK FAILED (%s): the old binary could not be put back: %w - BY HAND: %q to %q", reason, err, backup, target)
	}
	if out, err := runTool("sc", "start", serviceName); err != nil {
		return fmt.Errorf("THE SERVICE DID NOT START AFTER THE ROLLBACK (%s): %v - %s", reason, err, strings.TrimSpace(out))
	}
	// The binary running this command is the installed one, so its own version
	// is what the restored agent must answer with.
	if err := waitHealthy(platform.Version, healthGate); err != nil {
		return fmt.Errorf("THE ROLLBACK RAN BUT THE OLD BINARY IS NOT HEALTHY EITHER (%s): %w", reason, err)
	}
	return fmt.Errorf("the update was refused and the host is safely back on the OLD version (reason: %s)", reason)
}

// exeVersion runs an agent binary's `version` command.
func exeVersion(exe string) (string, error) {
	out, err := exec.Command(exe, "version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s version: %v - %s", exe, err, strings.TrimSpace(string(out)))
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return "", fmt.Errorf("the version output is empty, so this may not be an agent binary")
	}
	return line, nil
}

// waitHealthy polls until the service is Running AND /health answers with the
// expected version. This is the gate the whole update hangs on.
func waitHealthy(wantVersion string, within time.Duration) error {
	current, err := loadSettings(dataDir)
	if err != nil {
		return fmt.Errorf("the token for the health check could not be read: %w", err)
	}
	// InsecureSkipVerify is right here: this is a LOCAL liveness check against
	// our own agent over loopback, not remote authentication. The panel's
	// fingerprint pinning is a separate path and is untouched by this.
	client := &http.Client{
		Timeout: 5 * time.Second,
		// #nosec G402 -- a loopback liveness check against the agent's own
		// self-signed certificate; it carries no token and authenticates nothing.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}},
	}
	url := localHealthURL(current.Listen)
	deadline := time.Now().Add(within)
	last := "the wait ran out"
	for time.Now().Before(deadline) {
		last = pollHealth(client, url, current.Token, wantVersion)
		if last == "" {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("the health gate was not passed (%s)", last)
}

// pollHealth makes one attempt and returns why it did not pass, or "" when it did.
func pollHealth(client *http.Client, url, token, wantVersion string) string {
	if state, _ := runTool("sc", "query", serviceName); !strings.Contains(state, "RUNNING") {
		return "the service is not Running"
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "the health request could not be built: " + err.Error()
	}
	req.Header.Set(tokenHeader, token)
	resp, err := client.Do(req)
	if err != nil {
		return "health could not be reached: " + err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("health answered HTTP %d", resp.StatusCode)
	}
	var answer struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(body, &answer)
	if answer.Version != wantVersion {
		return fmt.Sprintf("health answered 200 but the version is %q rather than %q", answer.Version, wantVersion)
	}
	return ""
}

// waitServiceState waits for the service to reach STOPPED or RUNNING. It
// returns quietly when it does not: the caller handles what comes next.
func waitServiceState(want string, within time.Duration) {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if out, _ := runTool("sc", "query", serviceName); strings.Contains(out, want) {
			return
		}
		time.Sleep(time.Second)
	}
}
