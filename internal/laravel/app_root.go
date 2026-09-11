package laravel

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"servika/internal/httpx"
)

func laravelRootCandidates(systemUser string) []string {
	base := "/home/" + systemUser + "/public_html"
	out := []string{}
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if _, err := os.Stat(filepath.Join(base, "artisan")); err == nil {
		out = append(out, "public_html")
	}
	if entries, err := os.ReadDir(base); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
			if _, err := os.Stat(filepath.Join(base, entry.Name(), "artisan")); err == nil {
				out = append(out, "public_html/"+entry.Name())
			}
		}
	}
	return out
}

func (h *Handlers) AppCandidates(w http.ResponseWriter, r *http.Request) {
	id, systemUser, _, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	rec := h.getRecord(r.Context(), id)
	current := rec.AppRoot
	if current == "" {
		current = "public_html"
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"current": current, "candidates": laravelRootCandidates(systemUser)})
}

func (h *Handlers) SetAppRoot(w http.ResponseWriter, r *http.Request) {
	id, systemUser, _, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var req struct {
		AppRoot string `json:"app_root"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	appDir, err := safeAppDir(systemUser, req.AppRoot)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid application directory")
		return
	}
	appRoot := strings.Trim(strings.TrimSpace(req.AppRoot), "/")
	if appRoot == "" {
		appRoot = "public_html"
	}
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if _, err := os.Stat(appDir); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "application directory was not found")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(), `UPDATE cp_laravel_apps SET app_root=? WHERE domain_id=?`, appRoot, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "application root update failed")
		return
	}
	artisan, _ := laravelInstalled(appDir)
	if artisan {
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		if _, err := os.Stat(filepath.Join(appDir, "public")); err == nil {
			_ = h.setDocroot(r.Context(), id, systemUser, publicSubdirectory(appRoot))
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "app_root": appRoot, "installed": artisan})
}
