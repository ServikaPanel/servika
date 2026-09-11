package apps

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/appruntime"
	"servika/internal/httpx"
)

// installTimeout bounds a dependency install. It is generous because npm and pip
// both fetch from a registry, and short enough that a hung mirror does not hold
// a worker for the life of the panel.
const installTimeout = 10 * time.Minute

// installOutputLimit is how much of the installer's output comes back. The END
// is kept: the start of a long install is scrollback, the end says what failed.
const installOutputLimit = 32 << 10

// tenantEnv is the explicit environment a tenant-run installer gets. The panel's
// own environment carries SERVIKA_SECRET_KEY and the database DSN, so it is
// never inherited.
func tenantEnv(systemUser, appDir string, extra ...string) []string {
	env := []string{
		"HOME=/home/" + systemUser,
		"USER=" + systemUser,
		"LOGNAME=" + systemUser,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"NPM_CONFIG_CACHE=/home/" + systemUser + "/.npm",
		"PIP_CACHE_DIR=/home/" + systemUser + "/.cache/pip",
		"LANG=C.UTF-8",
		"PWD=" + appDir,
	}
	return append(env, extra...)
}

// runAsTenant executes a command as the tenant with a bounded deadline and a
// bounded amount of output.
//
// The deadline comes from context.Background() rather than the request: a
// half-written node_modules is worse than an install that finishes after the
// caller stopped waiting.
func runAsTenant(systemUser, appDir string, env []string, bin string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), installTimeout)
	defer cancel()

	argv := append([]string{"-u", systemUser, "--", bin}, args...)
	// #nosec G204 G702 -- fixed binary (runuser) with separate args (no shell); every value is validated or resolved from disk before exec.
	command := exec.CommandContext(ctx, "runuser", argv...)
	command.Dir = appDir
	command.Env = env
	command.Cancel = func() error { return command.Process.Kill() }

	var buffer bytes.Buffer
	command.Stdout, command.Stderr = &buffer, &buffer
	err := command.Run()

	output := buffer.String()
	if len(output) > installOutputLimit {
		output = output[len(output)-installOutputLimit:]
	}
	if ctx.Err() == context.DeadlineExceeded {
		return output + "\n\n[the installer did not finish within 10 minutes and was stopped]", false
	}
	return output, err == nil
}

// Install runs the dependency install for an application.
// POST /domains/{id}/apps/{aid}/install
//
// Node runs `npm ci` and falls back to `npm install` when there is no lock file.
// Python creates a virtual environment inside the application directory and
// installs requirements.txt into it, which is also where ResolveExec looks for
// gunicorn and uvicorn.
func (h *Handlers) Install(w http.ResponseWriter, r *http.Request) {
	s, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	app, ok := h.loadApp(r, s)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "application not found")
		return
	}
	appDir, err := SafeAppDir(s.SystemUser, app.AppRoot)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if info, err := os.Stat(appDir); err != nil || !info.IsDir() {
		httpx.WriteError(w, http.StatusBadRequest, "the application directory does not exist yet")
		return
	}

	var output string
	var succeeded bool
	switch appruntime.Kind(app.Runtime) {
	case appruntime.Node:
		output, succeeded = installNode(s.SystemUser, appDir, app.Version)
	case appruntime.Python:
		output, succeeded = installPython(s.SystemUser, appDir, app.Version)
	default:
		httpx.WriteError(w, http.StatusBadRequest, "unknown runtime")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": succeeded, "output": output})
}

func installNode(systemUser, appDir, version string) (string, bool) {
	npm, ok := appruntime.NpmBin(version)
	if !ok {
		return "npm is not available for the selected Node.js version", false
	}
	env := tenantEnv(systemUser, appDir)
	// `npm ci` is the reproducible install, but it REQUIRES a lock file and
	// fails outright without one, which is a normal state for a first deploy.
	if _, err := os.Stat(filepath.Join(appDir, "package-lock.json")); err == nil {
		return runAsTenant(systemUser, appDir, env, npm, "ci", "--no-fund", "--no-audit")
	}
	return runAsTenant(systemUser, appDir, env, npm, "install", "--no-fund", "--no-audit")
}

func installPython(systemUser, appDir, version string) (string, bool) {
	interpreter, err := ResolveRuntime(string(appruntime.Python), version)
	if err != nil {
		return err.Error(), false
	}
	env := tenantEnv(systemUser, appDir)
	venv := filepath.Join(appDir, ".venv")
	var transcript strings.Builder

	if _, err := os.Stat(filepath.Join(venv, "bin", "python")); err != nil {
		output, ok := runAsTenant(systemUser, appDir, env, interpreter, "-m", "venv", ".venv")
		transcript.WriteString(output)
		if !ok {
			return transcript.String(), false
		}
	}
	pip := filepath.Join(venv, "bin", "pip")
	if _, err := os.Stat(pip); err != nil {
		transcript.WriteString("\nthe virtual environment has no pip; install the runtime's pip package")
		return transcript.String(), false
	}
	if _, err := os.Stat(filepath.Join(appDir, "requirements.txt")); err != nil {
		transcript.WriteString("\nno requirements.txt found; the virtual environment is ready")
		return transcript.String(), true
	}
	output, ok := runAsTenant(systemUser, appDir, env, pip, "install", "-r", "requirements.txt")
	transcript.WriteString("\n")
	transcript.WriteString(output)
	return transcript.String(), ok
}
