package phpversion

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"
)

// Installing or removing a PHP version is detached work.
//
// dnf pulls a whole PHP stack from a mirror, which on a slow one takes longer
// than the router's own 300 second ceiling, so it cannot be done on the request:
// the connection is cut while dnf is still running and the panel never learns
// what happened. It also has to survive the tab being closed, because an
// operator starting an install and walking away is the normal case.
//
// The shape is the one internal/system already uses for security updates and
// optimisation: a transient systemd unit under PID 1 with its output appended to
// a log, plus a status and a log endpoint the screen polls. The wrapper is
// generated rather than shipped because it is built for one operation, with the
// paths for that version already resolved.

const phpOpUnit = "servika-php-op"

// maxOpLogBytes is how much of the log is returned. The same ceiling as the
// security update log: enough to see what dnf did, bounded so a runaway
// transaction cannot be pulled into memory on every poll.
const maxOpLogBytes = 60000

// opDescriptor is what the screen resumes from. It is written beside the log so
// a page reopened during an install can say WHICH version is being worked on,
// which the unit's own state does not carry.
type opDescriptor struct {
	Version  string `json:"version"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// phpOpState reports the transient unit's systemd state. It is a variable so the
// status endpoint can be exercised on a host that has no systemd.
var phpOpState = func() string {
	out, _ := systemCommandContext(context.Background(),
		"systemctl", "is-active", phpOpUnit).CombinedOutput()
	return strings.TrimSpace(string(out))
}

// phpOpRunning reports whether an operation is in flight.
//
// "activating" counts: systemd-run has returned but the unit has not reached
// active yet, and a second dnf started in that window would meet the first one's
// rpm lock.
func phpOpRunning() bool {
	state := phpOpState()
	return state == "active" || state == "activating"
}

// launchPHPOp writes the wrapper and starts it as a transient unit. It is a
// variable so a test can capture the script without systemd.
var launchPHPOp = func(script string) error {
	wrapper := config.PHPOpWrapper()
	tmp := wrapper + ".tmp"
	// #nosec G306 -- root-owned system integration file that systemd must execute; it holds no secret.
	if err := os.WriteFile(tmp, []byte(script), 0o700); err != nil {
		return fmt.Errorf("write the wrapper: %w", err)
	}
	if err := os.Rename(tmp, wrapper); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install the wrapper: %w", err)
	}
	logPath := config.PHPOpLog()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); every value comes from this package's own paths and constants.
	out, err := systemCommandContext(context.Background(), "systemd-run",
		"--collect",
		"--unit", phpOpUnit,
		"--description", "Servika PHP version operation",
		"-p", "StandardOutput=append:"+logPath,
		"-p", "StandardError=append:"+logPath,
		wrapper).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd-run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// startPHPOp prepares the log and descriptor and starts the unit.
func startPHPOp(descriptor opDescriptor, script string) error {
	logPath := config.PHPOpLog()
	// #nosec G301 -- root-owned system directory the panel's own logs live in; no secret material.
	if err := os.MkdirAll(filepath.Dir(logPath), 0o750); err != nil {
		return fmt.Errorf("prepare the log directory: %w", err)
	}
	// The log is TRUNCATED rather than appended to: the screen shows it as the
	// output of the operation it just started, and leaving the previous run's
	// output above would read as part of this one.
	header := fmt.Sprintf("════════ PHP %s (%s) %s — %s ════════\n",
		descriptor.Version, descriptor.Resource, descriptor.Action,
		time.Now().Format("2006-01-02 15:04:05"))
	// #nosec G306 -- an operator-facing log the panel serves back; it holds no secret.
	if err := os.WriteFile(logPath, []byte(header), 0o640); err != nil {
		return fmt.Errorf("open the log: %w", err)
	}
	body, err := json.Marshal(descriptor)
	if err != nil {
		return fmt.Errorf("encode the descriptor: %w", err)
	}
	// #nosec G306 -- a descriptor of which version is being worked on; it holds no secret.
	if err := os.WriteFile(config.PHPOpState(), body, 0o640); err != nil {
		return fmt.Errorf("record the operation: %w", err)
	}
	// A dnf install or remove is about to change which versions exist, so the
	// scan cache stops being an answer about this server the moment the unit
	// starts. Dropped BEFORE launching rather than after, since the launch
	// returns as soon as systemd-run has accepted the unit.
	InvalidateAllVersions()
	return launchPHPOp(script)
}

// readOpDescriptor returns what the last started operation was, or the zero
// value when there was none. A descriptor that cannot be read is not an error
// the screen can act on: the unit's own state still says whether work is
// running, and that is the part the page branches on.
func readOpDescriptor() opDescriptor {
	body, err := os.ReadFile(config.PHPOpState()) // #nosec G304 -- a fixed path this package owns.
	if err != nil {
		return opDescriptor{}
	}
	var descriptor opDescriptor
	if err := json.Unmarshal(body, &descriptor); err != nil {
		log.Printf("php op: the recorded operation could not be read: %v", err)
		return opDescriptor{}
	}
	return descriptor
}

// Status reports whether an install or removal is running, and which one.
// GET /php-versions/status
//
// The screen calls this on load so an operation started in another tab, or
// before this page was opened, is picked up rather than lost.
func (h *Handlers) Status(w http.ResponseWriter, _ *http.Request) {
	descriptor := readOpDescriptor()
	running := phpOpRunning()
	// This is the TRANSITION point, and it is observed for free: the screen polls
	// this endpoint for as long as an operation runs, so the first poll that sees
	// it stopped is the first moment the version list can have changed. Putting
	// phpOpRunning on the cache's READ path instead would trade the 24 execs the
	// cache saves for one `systemctl is-active` on every read.
	if !running {
		InvalidateAllVersions()
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"running":  running,
		"version":  descriptor.Version,
		"resource": descriptor.Resource,
		"action":   descriptor.Action,
		"status":   phpOpState(),
	})
}

// LogTail returns the end of the operation log with the running flag.
// GET /php-versions/log
//
// The flag travels WITH the log rather than being polled separately, so the
// screen cannot read the last lines of a finished run and still believe it is in
// progress.
func (h *Handlers) LogTail(w http.ResponseWriter, _ *http.Request) {
	descriptor := readOpDescriptor()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"log":      readOpLog(),
		"running":  phpOpRunning(),
		"version":  descriptor.Version,
		"resource": descriptor.Resource,
		"action":   descriptor.Action,
	})
}

// readOpLog returns the last maxOpLogBytes of the log. A missing log is an empty
// string: an operation that has not started yet has nothing to show, which is
// not a failure.
func readOpLog() string {
	body, err := os.ReadFile(config.PHPOpLog()) // #nosec G304 -- a fixed path this package owns.
	if err != nil {
		return ""
	}
	if len(body) > maxOpLogBytes {
		return string(body[len(body)-maxOpLogBytes:])
	}
	return string(body)
}

// shellQuote renders a value as a single-quoted shell word.
//
// Everything substituted into the wrapper is a path this package composed or a
// field of a VersionMetadata the request was matched against, so none of it is
// caller text. Quoting anyway is what keeps that true if a future version code
// is ever less tame than "83".
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// installScript renders the wrapper for an installation.
//
// It carries the whole sequence, not just dnf: the pool directory, the Remi
// www.conf that ships disabled, the input-vars drop-in and enabling the service
// all used to run in the handler after dnf returned, and the handler no longer
// waits for anything.
func installScript(m VersionMetadata) string {
	poolDir, _, service, _ := paths(m)
	phpdDir := "/etc/php.d"
	if m.Resource == "remi" {
		phpdDir = "/etc/opt/remi/php" + m.Code + "/php.d"
	}
	packages := make([]string, 0, len(PackageNames(m)))
	for _, name := range PackageNames(m) {
		packages = append(packages, shellQuote(name))
	}

	return `#!/usr/bin/env bash
set -uo pipefail

echo "Installing PHP ` + m.Version + ` from ` + m.Resource + `"
if ! dnf install -y ` + strings.Join(packages, " ") + `; then
  echo "FAILED: dnf could not install the packages"
  exit 1
fi

mkdir -p ` + shellQuote(poolDir) + `
# Remi ships www.conf disabled so a fresh install serves nothing by accident.
# It is enabled only when there is no pool of that name already.
if [ -f ` + shellQuote(poolDir+"/www.conf.disabled") + ` ] && [ ! -f ` + shellQuote(poolDir+"/www.conf") + ` ]; then
  mv ` + shellQuote(poolDir+"/www.conf.disabled") + ` ` + shellQuote(poolDir+"/www.conf") + `
fi

mkdir -p ` + shellQuote(phpdDir) + `
cat > ` + shellQuote(phpdDir+"/99-servika-input.ini") + ` <<'INI'
; Servika: supports large forms and imports (phpMyAdmin, WordPress)
max_input_vars = 10000
INI

systemctl enable --now ` + shellQuote(service) + ` || echo "WARNING: ` + service + ` did not start"
echo "Done: PHP ` + m.Version + ` is installed"
`
}

// removeScript renders the wrapper for a removal. The service is stopped first,
// so dnf is not pulling files out from under a running pool.
func removeScript(m VersionMetadata) string {
	_, _, service, _ := paths(m)
	return `#!/usr/bin/env bash
set -uo pipefail

echo "Removing PHP ` + m.Version + `"
systemctl disable --now ` + shellQuote(service) + ` || true
if ! dnf remove -y ` + shellQuote("php"+m.Code+"-*") + `; then
  echo "FAILED: dnf could not remove the packages"
  exit 1
fi
echo "Done: PHP ` + m.Version + ` is removed"
`
}
