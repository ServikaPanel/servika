package system

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"
)

const updateUnit = "servika-update"

func updateScript() string { return config.OpsTool("servika-update") }

func updateRawURL() string { return config.UpdateBootstrapURL() }

func updateLogPath() string { return config.UpdateLog() }

func updateRunning() bool {
	output, _ := exec.Command("systemctl", "is-active", updateUnit).CombinedOutput()
	state := strings.TrimSpace(string(output))
	return state == "active" || state == "activating"
}

// UpdateStatus reports whether the update tool exists and an update is running.
func UpdateStatus(w http.ResponseWriter, _ *http.Request) {
	_, statError := os.Stat(updateScript())
	running := updateRunning()
	status := "idle"
	if running {
		status = "running"
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"tool_available": statError == nil,
		"running":        running,
		"status":         status,
	})
}

// updateBootstrapKeyHex is the Ed25519 public key the bootstrap signature is
// checked against, set at build time (-X). It is EMPTY by default, exactly as
// the release signing key embedded in install.sh is: an installation that has no
// key configured keeps working, and once a key is set the signature is REQUIRED,
// including when the .sig is absent. "Verify it if a signature is present" is not
// a check, because the attacker chooses whether to publish one.
var updateBootstrapKeyHex = ""

// maxUpdateRedirects bounds the redirect chain. Go's default follows ten.
const maxUpdateRedirects = 5

// updateToolClient refuses a redirect that leaves TLS.
//
// The scheme is compared against the FIRST request, not the previous hop, so a
// chain cannot step down through an intermediate. A download that STARTED on
// plain http is left alone, because SERVIKA_UPDATE_BOOTSTRAP_URL accepts one
// deliberately and refusing there would break an operator's own mirror.
func updateToolClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= maxUpdateRedirects {
				return fmt.Errorf("stopped after %d redirects", maxUpdateRedirects)
			}
			if via[0].URL.Scheme == "https" && request.URL.Scheme != "https" {
				return fmt.Errorf("refusing a redirect from https to %s", request.URL.Scheme)
			}
			return nil
		},
	}
}

// updateBootstrapKey returns the configured verification key.
func updateBootstrapKey() (ed25519.PublicKey, bool) {
	if updateBootstrapKeyHex == "" {
		return nil, false
	}
	raw, err := hex.DecodeString(updateBootstrapKeyHex)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}

// verifyUpdateTool checks the detached signature published beside the bootstrap
// script. The bytes become a file this panel writes 0755 and runs as root in the
// next statement, so a `#!` prefix proves nothing: it proves the body is a
// script, which is exactly what an attacker would supply.
func verifyUpdateTool(client *http.Client, body []byte) error {
	key, ok := updateBootstrapKey()
	if !ok {
		return nil // No key configured; the redirect refusal above is the only guard.
	}
	response, err := client.Get(updateRawURL() + ".sig")
	if err != nil {
		return fmt.Errorf("fetch the update tool signature: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("the update tool signature is not published (HTTP %d)", response.StatusCode)
	}
	signature, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return fmt.Errorf("read the update tool signature: %w", err)
	}
	if !ed25519.Verify(key, body, signature) {
		return fmt.Errorf("the update tool signature does not verify")
	}
	return nil
}

func downloadUpdateTool() error {
	scriptPath := updateScript()
	client := updateToolClient()
	response, err := client.Get(updateRawURL())
	if err != nil {
		return fmt.Errorf("download update tool: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download update tool: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read update tool: %w", err)
	}
	if !strings.HasPrefix(string(body), "#!") {
		return fmt.Errorf("download update tool: unexpected content")
	}
	if err := verifyUpdateTool(client, body); err != nil {
		return fmt.Errorf("download update tool: %w", err)
	}

	temporaryPath := scriptPath + ".tmp"
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(temporaryPath, body, 0o755); err != nil {
		return fmt.Errorf("write update tool: %w", err)
	}
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	if err := os.Chmod(temporaryPath, 0o755); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("make update tool executable: %w", err)
	}
	if err := os.Rename(temporaryPath, scriptPath); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("install update tool: %w", err)
	}
	return nil
}

// StartUpdate bootstraps the update tool when needed and starts it in a transient systemd unit.
func StartUpdate(w http.ResponseWriter, _ *http.Request) {
	if updateRunning() {
		httpx.WriteError(w, http.StatusConflict, "an update is already running")
		return
	}

	toolDownloaded := false
	if _, err := os.Stat(updateScript()); err != nil {
		if err := downloadUpdateTool(); err != nil {
			httpx.WriteError(w, http.StatusBadGateway, "the update tool could not be downloaded")
			return
		}
		toolDownloaded = true
	}

	logPath := updateLogPath()
	if err := os.MkdirAll(filepath.Dir(logPath), 0o750); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the update log could not be prepared")
		return
	}
	logHeader := fmt.Sprintf("=== Update started: %s ===\n", time.Now().Format("2006-01-02 15:04:05"))
	if toolDownloaded {
		logHeader += "(The missing update tool was downloaded.)\n"
	}
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(logPath, []byte(logHeader), 0o640); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the update log could not be prepared")
		return
	}

	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	command := exec.Command("systemd-run",
		"--collect",
		"--unit", updateUnit,
		"--description", "Servika update",
		"/bin/bash", "-lc", fmt.Sprintf("%s >>%s 2>&1", config.ShellQuote(updateScript()), config.ShellQuote(logPath)))
	if _, err := command.CombinedOutput(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the update could not be started")
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"started":         true,
		"tool_downloaded": toolDownloaded,
	})
}

// UpdateLog returns the tail of the update log and the normalized execution state.
func UpdateLog(w http.ResponseWriter, _ *http.Request) {
	body, err := os.ReadFile(updateLogPath())
	if err != nil {
		body = nil
	}
	logText := string(body)
	if len(logText) > 60000 {
		logText = logText[len(logText)-60000:]
	}
	running := updateRunning()
	status := "idle"
	if running {
		status = "running"
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"log":     logText,
		"running": running,
		"status":  status,
	})
}
