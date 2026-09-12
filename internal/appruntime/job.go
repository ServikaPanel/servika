package appruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"servika/internal/config"
	"servika/internal/logx"
)

// Installing a runtime is detached work, for the same reasons a PHP version is:
// dnf and `n` both pull from a mirror, which on a slow one outlasts the router's
// own ceiling, and an operator who starts an install and closes the tab must
// still get the install.
//
// The shape is the one internal/phpversion already uses: a transient systemd
// unit under PID 1 with its output appended to a log, plus a status and a log
// endpoint the screen polls. The wrapper is generated rather than shipped
// because it is built for one operation, against one already-resolved version.

const opUnit = "servika-runtime-op"

// maxOpLogBytes is how much of the log is returned: enough to see what the
// installer did, bounded so a runaway transaction cannot be pulled into memory
// on every poll.
const maxOpLogBytes = 60000

// opDescriptor is what the screen resumes from. It is written beside the log so
// a page reopened during an install can say WHICH runtime is being worked on,
// which the unit's own state does not carry.
type opDescriptor struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
	Action  string `json:"action"`
}

// systemCommandContext creates a privileged command without inheriting panel secrets.
func systemCommandContext(ctx context.Context, name string, arguments ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
	}
	return command
}

// opState reports the transient unit's systemd state. It is a variable so the
// status endpoint can be exercised on a host that has no systemd.
var opState = func() string {
	out, _ := systemCommandContext(context.Background(), "systemctl", "is-active", opUnit).CombinedOutput()
	return strings.TrimSpace(string(out))
}

// opRunning reports whether an operation is in flight.
//
// "activating" counts: systemd-run has returned but the unit has not reached
// active yet, and a second dnf started in that window would meet the first one's
// rpm lock.
func opRunning() bool {
	state := opState()
	return state == "active" || state == "activating"
}

// launchOp writes the wrapper and starts it as a transient unit. It is a
// variable so a test can capture the script without systemd.
var launchOp = func(script string) error {
	wrapper := config.RuntimeOpWrapper()
	tmp := wrapper + ".tmp"
	// #nosec G306 -- root-owned system integration file that systemd must execute; it holds no secret.
	if err := os.WriteFile(tmp, []byte(script), 0o700); err != nil {
		return fmt.Errorf("write the wrapper: %w", err)
	}
	if err := os.Rename(tmp, wrapper); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install the wrapper: %w", err)
	}
	logPath := config.RuntimeOpLog()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); every value comes from this package's own paths and constants.
	out, err := systemCommandContext(context.Background(), "systemd-run",
		"--collect",
		"--unit", opUnit,
		"--description", "Servika application runtime operation",
		"-p", "StandardOutput=append:"+logPath,
		"-p", "StandardError=append:"+logPath,
		wrapper).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd-run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// startOp prepares the log and descriptor and starts the unit.
//
// Nothing the screen reads is REPLACED until systemd-run has accepted the unit.
// The slot is one fixed unit name, and the guard in front of this is a
// `systemctl is-active` probe, so a second request that arrives while one
// operation runs reaches here and is refused by systemd. Truncating the log and
// overwriting the descriptor first destroyed the running job's only record and
// left the screen reporting a runtime that never started.
func startOp(descriptor opDescriptor, script string) error {
	logPath := config.RuntimeOpLog()
	// #nosec G301 -- root-owned system directory the panel's own logs live in; no secret material.
	if err := os.MkdirAll(filepath.Dir(logPath), 0o750); err != nil {
		return fmt.Errorf("prepare the log directory: %w", err)
	}
	body, err := json.Marshal(descriptor)
	if err != nil {
		return fmt.Errorf("encode the descriptor: %w", err)
	}
	staged := config.RuntimeOpState() + ".tmp"
	// #nosec G306 -- a descriptor of which runtime is being worked on; it holds no secret.
	if err := os.WriteFile(staged, body, 0o640); err != nil {
		return fmt.Errorf("record the operation: %w", err)
	}
	header := fmt.Sprintf("======== %s %s %s ========",
		descriptor.Kind, descriptor.Version, descriptor.Action)
	if err := launchOp(config.ScriptWithLogHeader(script, logPath, header)); err != nil {
		_ = os.Remove(staged)
		return err
	}
	if err := os.Rename(staged, config.RuntimeOpState()); err != nil {
		return fmt.Errorf("record the operation: %w", err)
	}
	return nil
}

// readOpDescriptor returns what the last started operation was, or the zero
// value when there was none.
func readOpDescriptor() opDescriptor {
	body, err := os.ReadFile(config.RuntimeOpState()) // #nosec G304 -- a fixed path this package owns.
	if err != nil {
		return opDescriptor{}
	}
	var descriptor opDescriptor
	if err := json.Unmarshal(body, &descriptor); err != nil {
		logx.Errorf("runtime op: the recorded operation could not be read: %v", err)
		return opDescriptor{}
	}
	return descriptor
}

// readOpLog returns the last maxOpLogBytes of the log. A missing log is an empty
// string: an operation that has not started yet has nothing to show.
func readOpLog() string {
	body, err := os.ReadFile(config.RuntimeOpLog()) // #nosec G304 -- a fixed path this package owns.
	if err != nil {
		return ""
	}
	if len(body) > maxOpLogBytes {
		return string(body[len(body)-maxOpLogBytes:])
	}
	return string(body)
}

// nodeInstallScript installs the `n` version manager when it is missing, then
// the requested major through it.
//
// `n` is used rather than dnf because RHEL 10 delivers Node as module streams,
// which are alternatives: enabling a second one replaces the first. A control
// panel needs them side by side, and `n` unpacks official tarballs into
// per-version directories that do exactly that.
func nodeInstallScript(major string) string {
	quoted := config.ShellQuote(major)
	return `#!/usr/bin/env bash
set -uo pipefail

if ! command -v n >/dev/null 2>&1; then
  echo "Installing the n version manager"
  if ! npm install -g n; then
    echo "FAILED: n could not be installed (is npm present?)"
    exit 1
  fi
fi

echo "Installing Node.js ` + major + `"
# n switches /usr/local/bin/node to whatever it installed last. The panel
# resolves interpreters from the per-version directory instead, so the symlink
# it leaves behind decides nothing here.
if ! n install ` + quoted + `; then
  echo "FAILED: Node.js ` + major + ` could not be installed"
  exit 1
fi
echo "Done: Node.js ` + major + ` is installed"
`
}

// nodeRemoveScript drops one major. `n rm` removes the version directory only,
// so every other major keeps working.
func nodeRemoveScript(major string) string {
	quoted := config.ShellQuote(major)
	return `#!/usr/bin/env bash
set -uo pipefail

echo "Removing Node.js ` + major + `"
if ! n rm ` + quoted + `; then
  echo "FAILED: Node.js ` + major + ` could not be removed"
  exit 1
fi
echo "Done: Node.js ` + major + ` is removed"
`
}

// pythonInstallScript installs an alternative interpreter. RHEL 10 ships these
// as separately named, parallel-installable packages, so unlike Node this needs
// no version manager at all.
func pythonInstallScript(version string) string {
	pkg := config.ShellQuote("python" + version)
	pipPkg := config.ShellQuote("python" + version + "-pip")
	return `#!/usr/bin/env bash
set -uo pipefail

echo "Installing Python ` + version + `"
if ! dnf install -y ` + pkg + `; then
  echo "FAILED: dnf could not install Python ` + version + `"
  exit 1
fi
# pip is a separate package and may not exist for every interpreter; an app can
# still run without it, so a missing one is reported rather than fatal.
dnf install -y ` + pipPkg + ` || echo "WARNING: pip for Python ` + version + ` is unavailable"
echo "Done: Python ` + version + ` is installed"
`
}

func pythonRemoveScript(version string) string {
	pkg := config.ShellQuote("python" + version)
	return `#!/usr/bin/env bash
set -uo pipefail

echo "Removing Python ` + version + `"
if ! dnf remove -y ` + pkg + `; then
  echo "FAILED: dnf could not remove Python ` + version + `"
  exit 1
fi
echo "Done: Python ` + version + ` is removed"
`
}
