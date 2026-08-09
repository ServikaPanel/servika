package laravel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"

	"servika/internal/httpx"
)

func ensureLogDir(systemUser string) {
	dir := "/home/" + systemUser + "/" + logSubdir
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if _, err := os.Stat(dir); err != nil {
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		_ = os.MkdirAll(dir, 0750)
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		_ = exec.Command("chown", systemUser+":"+systemUser, dir).Run()
	}
}

func cronPath(id int64) string { return cronDir + "/servika-laravel-" + fmt.Sprint(id) }

func (h *Handlers) Schedule(w http.ResponseWriter, r *http.Request) {
	id, systemUser, phpVersion, demo, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "schedule cannot be managed for demo subscriptions")
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
	path := cronPath(id)
	if req.Enabled {
		ensureLogDir(systemUser)
		logFile := "/home/" + systemUser + "/" + logSubdir + "/laravel-schedule.log"
		line := fmt.Sprintf("* * * * * %s %s %s/artisan schedule:run >> %s 2>&1\n", systemUser, phpBin(phpVersion), appDir, logFile)
		body := "# Servika Laravel Toolkit schedule for domain " + fmt.Sprint(id) + "\nPATH=" + systemPath + "\n" + line
		// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "cron write failed")
			return
		}
		_, _ = h.DB.ExecContext(r.Context(), `UPDATE cp_laravel_apps SET schedule_enabled=1 WHERE domain_id=?`, id)
	} else {
		_ = os.Remove(path)
		_, _ = h.DB.ExecContext(r.Context(), `UPDATE cp_laravel_apps SET schedule_enabled=0 WHERE domain_id=?`, id)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "schedule_enabled": req.Enabled})
}
