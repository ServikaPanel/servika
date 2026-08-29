// Package phpext provides server-wide PHP extension management.
package phpext

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"
	"servika/internal/phpversion"
	"servika/internal/provisioner"
)

type Version struct {
	Version string `json:"version"`
	IniDir  string `json:"ini_dir"`
	Service string `json:"service"`
	PHPBin  string `json:"php_bin"`
	PECLBin string `json:"pecl_bin"`
}

// Versions dynamically discovers and returns only installed versions.
func Versions() []Version {
	out := []Version{}
	seen := map[string]bool{}
	for _, ds := range phpversion.AllVersions() {
		if !ds.Loaded || seen[ds.Version] {
			continue
		}
		seen[ds.Version] = true
		iniDir := "/etc/php.d"
		peclBin := config.PECLBin()
		if ds.Resource == "remi" {
			iniDir = "/etc/opt/remi/php" + ds.Code + "/php.d"
			peclBin = filepath.Join(config.RemiPECLRoot(), "php"+ds.Code, "root/usr/bin/pecl")
		}
		out = append(out, Version{
			Version: ds.Version,
			IniDir:  iniDir,
			Service: ds.Service,
			PHPBin:  ds.PHPBin,
			PECLBin: peclBin,
		})
	}
	return out
}

func versionByID(id string) (Version, bool) {
	for _, s := range Versions() {
		if s.Version == id {
			return s, true
		}
	}
	return Version{}, false
}

type Extension struct {
	Name    string `json:"name"`
	Enabled bool   `json:"active"`
	INIFile string `json:"ini_file"`
}

// extensionInstallTimeout bounds dnf and pecl, both of which fetch from remote
// repositories and can otherwise wait on an unreachable mirror indefinitely. A
// PECL build compiles from source, so the budget covers a slow compile too.
const extensionInstallTimeout = 15 * time.Minute

type Handlers struct {
	DB *sql.DB // Reserved for future audit storage.
}

// safeName accepts only letters, digits, underscores, and hyphens.
func safeName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func peclEnvironment(phpBin string) []string {
	return []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
		"PHP_PEAR_PHP_BIN=" + phpBin,
	}
}

// List returns enabled and disabled extensions for a version.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	version := r.URL.Query().Get("version")
	if version == "" {
		version = "8.3"
	}
	s, ok := versionByID(version)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported version")
		return
	}
	entries, err := os.ReadDir(s.IniDir)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to read extension directory")
		return
	}
	exts := []Extension{}
	for _, e := range entries {
		name := e.Name()
		if !strings.Contains(name, ".ini") {
			continue
		}
		enabled := strings.HasSuffix(name, ".ini")
		if !enabled && !strings.HasSuffix(name, ".ini.disabled") {
			continue
		}
		// Extract the name from XX-{name}.ini[.disabled].
		clean := strings.TrimSuffix(name, ".disabled")
		clean = strings.TrimSuffix(clean, ".ini")
		// Remove a numeric prefix such as 20-.
		if idx := strings.Index(clean, "-"); idx > 0 && idx < 4 {
			pre := clean[:idx]
			isNum := true
			for _, c := range pre {
				if c < '0' || c > '9' {
					isNum = false
					break
				}
			}
			if isNum {
				clean = clean[idx+1:]
			}
		}
		exts = append(exts, Extension{
			Name:    clean,
			Enabled: enabled,
			INIFile: name,
		})
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i].Name < exts[j].Name })

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"version":  version,
		"total":    len(exts),
		"content":  exts,
		"versions": Versions(),
	})
}

// Toggle renames an ini file and reloads PHP-FPM.
type toggleReq struct {
	Version string `json:"version"`
	INIFile string `json:"ini_file"` // Full file name such as "20-soap.ini" or "20-soap.ini.disabled".
	Enabled bool   `json:"active"`
}

func (h *Handlers) Toggle(w http.ResponseWriter, r *http.Request) {
	var req toggleReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	s, ok := versionByID(req.Version)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported version")
		return
	}
	// Security: ini_file must be a file name, not a path.
	if strings.ContainsAny(req.INIFile, "/\\") || !strings.Contains(req.INIFile, ".ini") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid file name")
		return
	}

	currentPath := filepath.Join(s.IniDir, req.INIFile)
	if _, err := os.Stat(currentPath); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "file not found")
		return
	}

	// Determine the new name.
	var newPath string
	if req.Enabled {
		// disabled -> enabled
		newPath = strings.TrimSuffix(currentPath, ".disabled")
		if currentPath == newPath {
			httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "already enabled"})
			return
		}
	} else {
		// enabled -> disabled
		if strings.HasSuffix(currentPath, ".disabled") {
			httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "already disabled"})
			return
		}
		newPath = currentPath + ".disabled"
	}

	if err := os.Rename(currentPath, newPath); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to update extension state")
		return
	}

	// FPM reload
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	if _, err := exec.Command("systemctl", "reload-or-restart", s.Service).CombinedOutput(); err != nil {
		// Restore the original name when reload fails.
		_ = os.Rename(newPath, currentPath)
		httpx.WriteError(w, http.StatusInternalServerError, "failed to reload PHP-FPM")
		return
	}
	// Each tenant runs its own isolated master, so reload those too or the toggle
	// stays invisible to the tenant's running site.
	provisioner.ReloadAllTenantFPM()

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"version": req.Version,
		"file":    filepath.Base(newPath),
		"active":  req.Enabled,
	})
}

// PECL installation.
type peclReq struct {
	Version string `json:"version"`
	Package string `json:"package"`
}

// PECLInstall starts an asynchronous install and returns a job id at once, because
// a PECL build first installs PEAR and the toolchain and then compiles, which runs
// past the request timeout. The page polls PECLStatus for the live step and output.
func (h *Handlers) PECLInstall(w http.ResponseWriter, r *http.Request) {
	var req peclReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !safeName(req.Package) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid package name")
		return
	}
	s, ok := versionByID(req.Version)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported version")
		return
	}

	prunePECLJobs()
	jobID, err := newPECLJobID()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not start the install job")
		return
	}
	job := &peclJob{state: peclRunning, step: "starting", percent: 2}
	peclJobs.Store(jobID, job)
	go runPECLInstall(job, s, req.Package)

	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"ok":      true,
		"job_id":  jobID,
		"package": req.Package,
		"version": req.Version,
	})
}

// PECLStatus reports the state of an asynchronous PECL install started by PECLInstall.
func (h *Handlers) PECLStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	value, ok := peclJobs.Load(id)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "job not found (it may have finished)")
		return
	}
	job := value.(*peclJob)
	state, step, percent, method, errMsg, logs := job.snapshot()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"state":   string(state),
		"step":    step,
		"percent": percent,
		"method":  method,
		"error":   errMsg,
		"log":     logs,
	})
}

func (h *Handlers) PECLRemove(w http.ResponseWriter, r *http.Request) {
	var req peclReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !safeName(req.Package) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid package name")
		return
	}
	s, ok := versionByID(req.Version)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported version")
		return
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	cmd := exec.Command(s.PECLBin, "uninstall", req.Package)
	cmd.Env = peclEnvironment(s.PHPBin)
	_, _ = cmd.CombinedOutput()

	// Remove the ini file.
	for _, suffix := range []string{".ini", ".ini.disabled"} {
		for _, prefix := range []string{"50-", "40-", "30-", "20-"} {
			path := filepath.Join(s.IniDir, prefix+req.Package+suffix)
			_ = os.Remove(path)
		}
	}

	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_, _ = exec.Command("systemctl", "reload-or-restart", s.Service).CombinedOutput()
	provisioner.ReloadAllTenantFPM() // reload the isolated per-tenant masters too

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"package": req.Package,
		"version": req.Version,
	})
}
