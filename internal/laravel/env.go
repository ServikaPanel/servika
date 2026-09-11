package laravel

import (
	"encoding/json"
	"net/http"

	"servika/internal/httpx"
)

func (h *Handlers) EnvRead(w http.ResponseWriter, r *http.Request) {
	id, systemUser, _, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	appDir, err := h.appDir(r, id, systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid application directory")
		return
	}
	content, err := readEnvFile(appDir)
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"exists": false, "content": ""})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"exists": true, "content": content})
}

func (h *Handlers) EnvWrite(w http.ResponseWriter, r *http.Request) {
	id, systemUser, _, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	appDir, err := h.appDir(r, id, systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid application directory")
		return
	}
	if err := writeEnvFile(systemUser, appDir, req.Content); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, ".env write failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handlers) Maintenance(w http.ResponseWriter, r *http.Request) {
	id, systemUser, phpVersion, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	appDir, err := h.appDir(r, id, systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid application directory")
		return
	}
	command := "up"
	if req.Enabled {
		command = "down"
	}
	out, commandOK := TenantExec(r.Context(), systemUser, appDir, phpBin(phpVersion), "artisan", command)
	if commandOK {
		_, _ = h.DB.ExecContext(r.Context(), `UPDATE cp_laravel_apps SET maintenance=? WHERE domain_id=?`, map[bool]int{true: 1, false: 0}[req.Enabled], id)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": commandOK, "maintenance": req.Enabled, "output": out})
}
