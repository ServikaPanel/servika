package laravel

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"servika/internal/appruntime"
	"servika/internal/httpx"
)

var artisanAllowed = map[string]bool{
	"migrate": true, "migrate:status": true, "migrate:rollback": true, "migrate:fresh": true,
	"db:seed": true, "config:cache": true, "config:clear": true, "route:cache": true,
	"route:clear": true, "route:list": true, "view:cache": true, "view:clear": true,
	"cache:clear": true, "optimize": true, "optimize:clear": true, "queue:restart": true,
	"queue:failed": true, "queue:retry": true, "storage:link": true, "key:generate": true,
	"down": true, "up": true, "schedule:run": true, "schedule:list": true, "about": true,
	"event:list": true, "migrate:install": true,
}

var reArtisanArg = regexp.MustCompile(`^(--?[A-Za-z0-9][A-Za-z0-9=:_./-]*|[A-Za-z0-9][A-Za-z0-9=:_./-]*)$`)

func (h *Handlers) appDir(r *http.Request, id int64, systemUser string) (string, error) {
	rec := h.getRecord(r.Context(), id)
	return safeAppDir(systemUser, rec.AppRoot)
}

func (h *Handlers) Artisan(w http.ResponseWriter, r *http.Request) {
	id, systemUser, phpVersion, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var req struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	parts := strings.Fields(strings.TrimSpace(req.Command))
	if len(parts) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "command is required")
		return
	}
	sub := parts[0]
	if !artisanAllowed[sub] {
		httpx.WriteError(w, http.StatusBadRequest, "artisan command is not allowed")
		return
	}
	argv := []string{"artisan", sub, "--no-interaction"}
	for _, arg := range parts[1:] {
		if !reArtisanArg.MatchString(arg) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid argument")
			return
		}
		argv = append(argv, arg)
	}
	appDir, err := h.appDir(r, id, systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid application directory")
		return
	}
	out, commandOK := tenantExec(r.Context(), systemUser, appDir, phpBin(phpVersion), argv...)
	if maintenanceActive(appDir) != (sub == "down") && (sub == "down" || sub == "up") {
		_, _ = h.DB.ExecContext(r.Context(), `UPDATE cp_laravel_apps SET maintenance=? WHERE domain_id=?`, map[bool]int{true: 1, false: 0}[sub == "down"], id)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": commandOK, "command": "artisan " + strings.Join(parts, " "), "output": out})
}

var composerAllowed = map[string]bool{
	"install": true, "update": true, "require": true, "remove": true,
	"dump-autoload": true, "validate": true, "show": true, "diagnose": true,
}

func (h *Handlers) Composer(w http.ResponseWriter, r *http.Request) {
	id, systemUser, phpVersion, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if _, err := os.Stat(composerBinPath()); err != nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "composer is not installed")
		return
	}
	var req struct {
		Command string `json:"command"`
		Package string `json:"package"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !composerAllowed[req.Command] {
		httpx.WriteError(w, http.StatusBadRequest, "composer command is not allowed")
		return
	}
	appDir, err := h.appDir(r, id, systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid application directory")
		return
	}
	argv := []string{composerBinPath(), req.Command, "--no-interaction", "--no-ansi", "-d", appDir}
	if req.Command == "install" || req.Command == "update" {
		argv = append(argv, "--prefer-dist")
	}
	if req.Command == "require" || req.Command == "remove" {
		pkg := strings.TrimSpace(req.Package)
		if !reComposerPkg.MatchString(pkg) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid package name")
			return
		}
		argv = append(argv, pkg)
	}
	out, commandOK := tenantExec(r.Context(), systemUser, appDir, phpBin(phpVersion), argv...)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": commandOK, "command": "composer " + req.Command, "output": out})
}

// Which interpreters exist is answered in one place, internal/appruntime, so the
// toolkit here and the application manager cannot disagree about what "22" means
// on a given host.
func installedNodeVersions() []string {
	runtimes := appruntime.Installed(appruntime.Node)
	out := make([]string, 0, len(runtimes))
	for _, runtime := range runtimes {
		out = append(out, runtime.Version)
	}
	return out
}

func nodeBinDir(version string) string { return appruntime.NodeBinDir(version) }

var npmAllowed = map[string]bool{"install": true, "ci": true, "run": true, "prune": true, "ls": true, "outdated": true, "audit": true, "--version": true}
var reNpmScript = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9:_-]*$`)

func (h *Handlers) Npm(w http.ResponseWriter, r *http.Request) {
	id, systemUser, _, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var req struct {
		Command       string `json:"command"`
		Script        string `json:"script"`
		NodeVersion   string `json:"node_version"`
		IgnoreScripts bool   `json:"ignore_scripts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !npmAllowed[req.Command] {
		httpx.WriteError(w, http.StatusBadRequest, "npm command is not allowed")
		return
	}
	if req.NodeVersion != "" && req.NodeVersion != "system" && !reNodeVersion.MatchString(req.NodeVersion) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid node version")
		return
	}
	appDir, err := h.appDir(r, id, systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid application directory")
		return
	}
	binDir := nodeBinDirFor(req.NodeVersion)
	npmBin := filepath.Join(binDir, "npm")
	if _, err := os.Stat(npmBin); err != nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "node or npm is not installed")
		return
	}
	argv := []string{req.Command, "--prefix", appDir, "--no-fund", "--no-audit"}
	if req.IgnoreScripts {
		argv = append(argv, "--ignore-scripts")
	}
	if req.Command == "run" {
		script := strings.TrimSpace(req.Script)
		if !reNpmScript.MatchString(script) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid script name")
			return
		}
		argv = []string{"run", script, "--prefix", appDir}
	}
	env := tenantEnv(systemUser)
	for i, item := range env {
		if strings.HasPrefix(item, "PATH=") {
			env[i] = "PATH=" + binDir + ":" + systemPath
		}
	}
	out, commandOK := tenantExecWithEnv(r.Context(), systemUser, appDir, env, npmBin, argv...)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": commandOK, "command": "npm " + req.Command, "output": out, "node_dir": binDir})
}

func (h *Handlers) NodeVersions(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"versions": installedNodeVersions()})
}
