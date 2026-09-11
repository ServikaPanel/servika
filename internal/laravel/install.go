package laravel

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"servika/internal/httpx"
	"servika/internal/netguard"
	"servika/internal/provisioner"
)

func setupUnit(id int64) string       { return fmt.Sprintf("servika-laravel-install-%d", id) }
func setupLog(id int64) string        { return fmt.Sprintf("%s/install-%d.log", logRootDir(), id) }
func setupScriptPath(id int64) string { return fmt.Sprintf("/run/servika-laravel-install-%d.sh", id) }

func mkdirTenant(systemUser, dir string) error {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	if err := exec.Command("runuser", "-u", systemUser, "--", "/bin/mkdir", "-p", dir).Run(); err != nil {
		return fmt.Errorf("directory creation failed")
	}
	return nil
}

func (h *Handlers) setDocroot(ctx context.Context, id int64, systemUser, subdirectory string) error {
	abs, err := provisioner.AbsoluteWebRoot(systemUser, subdirectory)
	if err != nil {
		return err
	}
	if _, err := h.DB.ExecContext(ctx, `UPDATE domains SET web_root=? WHERE id=?`, abs, id); err != nil {
		return err
	}
	return provisioner.RerenderVhost(h.DB, id)
}

func publicSubdirectory(appRoot string) string {
	rel := strings.TrimPrefix(strings.Trim(appRoot, "/"), "public_html")
	rel = strings.Trim(rel, "/")
	if rel == "" {
		return "public"
	}
	return rel + "/public"
}

type installReq struct {
	Mode    string `json:"mode"`
	RepoURL string `json:"repo_url"`
	Branch  string `json:"branch"`
	AppRoot string `json:"app_root"`
}

func (h *Handlers) Install(w http.ResponseWriter, r *http.Request) {
	id, systemUser, phpVersion, demo, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "laravel cannot be installed for demo subscriptions")
		return
	}
	defer lockDomain(id)()
	var currentStatus string
	_ = h.DB.QueryRowContext(r.Context(), `SELECT COALESCE(last_deploy_status,'') FROM cp_laravel_apps WHERE domain_id=?`, id).Scan(&currentStatus)
	if currentStatus == "installing" || currentStatus == "running" {
		httpx.WriteError(w, http.StatusConflict, "an install or deploy operation is already running for this domain")
		return
	}
	var req installReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Mode != "local" && req.Mode != "remote" && req.Mode != "scaffold" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid mode")
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
	if err := mkdirTenant(systemUser, appDir); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "directory creation failed")
		return
	}
	php := phpBin(phpVersion)
	logPath := setupLog(id)
	tmp := "/home/" + systemUser + "/.laravel-skeleton-" + fmt.Sprint(id)
	// The base row must exist before the status updates below target it; abort if
	// it cannot be written rather than proceeding with broken status tracking.
	if err := h.upsertBase(r.Context(), id, appRoot, req.Mode, phpVersion, ""); err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		httpx.LogR(r, "laravel upsertBase domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not initialize Laravel app record")
		return
	}
	_, _ = h.DB.ExecContext(r.Context(), `UPDATE cp_laravel_apps SET last_deploy_status='installing' WHERE domain_id=?`, id)

	switch req.Mode {
	case "local":
		out, gitOK := TenantExec(r.Context(), systemUser, appDir, "/usr/bin/git", "init")
		status := "failed"
		if gitOK {
			status = "ready"
		}
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		_, _ = h.DB.ExecContext(r.Context(), `UPDATE cp_laravel_apps SET last_deploy_status=? WHERE domain_id=?`, status, id)
		// #nosec G703 -- path built from a validated identifier / fixed system path / server-internal temp path; tenant paths use safeio (openat2).
		if _, err := os.Stat(filepath.Join(appDir, "public")); err == nil {
			if err := h.setDocroot(r.Context(), id, systemUser, publicSubdirectory(appRoot)); err != nil {
				// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
				httpx.LogR(r, "laravel setDocroot domain %d: %v (docroot may still serve project root)", id, err)
			}
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": gitOK, "async": false, "output": out, "message": "Empty git repository created. Push code and deploy from the Deploy tab."})
		return
	case "remote":
		if !validRepoURL(req.RepoURL) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid repository URL")
			return
		}
		// validRepoURL is an ARGUMENT filter: it refuses shell metacharacters and
		// a non-Git scheme. It never looks at the host, so without this the clone
		// reached any address the panel host can: the panel's own API, MariaDB
		// and Valkey on loopback, tenant and host applications on their port
		// ranges, RFC1918 neighbours and the cloud metadata endpoint. `git clone`
		// over https issues a GET, and the ssh forms open a raw handshake, so
		// arbitrary TCP ports were probeable, with the failure text returned by
		// the install-status endpoint as the oracle.
		//
		// internal/git guards both of its clone paths with exactly this call. The
		// guard was never carried across when this second entry point grew its
		// own clone.
		if err := netguard.CheckGitURL(req.RepoURL); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "the repository host is not allowed")
			return
		}
		branch := strings.TrimSpace(req.Branch)
		if branch == "" {
			branch = "main"
		}
		if !reArg.MatchString(branch) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid branch name")
			return
		}
		script := remoteInstallScript(appDir, req.RepoURL, branch, php, tmp)
		if err := detachedInstall(id, systemUser, appDir, logPath, script); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "install start failed")
			return
		}
	case "scaffold":
		script := scaffoldInstallScript(appDir, php, tmp)
		if err := detachedInstall(id, systemUser, appDir, logPath, script); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "install start failed")
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "async": true, "unit": setupUnit(id), "message": "Installation started. Poll the status endpoint for progress."})
}

func detachedInstall(id int64, systemUser, appDir, logPath, script string) error {
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	path := setupScriptPath(id)
	// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		return fmt.Errorf("setup script write failed")
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_ = exec.Command("systemctl", "reset-failed", setupUnit(id)+".service").Run()
	return systemdRunDetached(systemUser, appDir, setupUnit(id), logPath, "/bin/bash", path)
}

func scaffoldInstallScript(appDir, php, tmp string) string {
	cp := php + " " + shellQuote(composerBin()) + " create-project --no-interaction --prefer-dist"
	return "#!/bin/bash\nset -e\n" +
		"DEST=" + shellQuote(appDir) + "\nTMP=" + shellQuote(tmp) + "\n" +
		"if [ -z \"$(ls -A \"$DEST\" 2>/dev/null)\" ]; then\n" +
		"  " + cp + " laravel/laravel \"$DEST\" || " + cp + " laravel/laravel:^11 \"$DEST\"\n" +
		"else\n" +
		"  echo '(directory is not empty, installing to a temporary directory and merging)'\n" +
		"  rm -rf \"$TMP\"\n" +
		"  " + cp + " laravel/laravel \"$TMP\" || " + cp + " laravel/laravel:^11 \"$TMP\"\n" +
		// Hardlink the merge within the same filesystem so it does not double the tenant's
		// inode/file-count quota; fall back to a full copy when hardlinking is unavailable.
		"  cp -al \"$TMP\"/. \"$DEST\"/ 2>/dev/null || cp -a \"$TMP\"/. \"$DEST\"/\n" +
		"  rm -rf \"$TMP\"\n" +
		"fi\n" +
		"cd \"$DEST\"\n" +
		"[ -f .env ] || { [ -f .env.example ] && cp .env.example .env; }\n" +
		php + " artisan key:generate --force || true\n"
}

func remoteInstallScript(appDir, repoURL, branch, php, tmp string) string {
	return "#!/bin/bash\nset -e\n" +
		"DEST=" + shellQuote(appDir) + "\nTMP=" + shellQuote(tmp) + "\n" +
		"rm -rf \"$TMP\"\n" +
		"/usr/bin/git clone --depth 1 --branch " + shellQuote(branch) + " -- " + shellQuote(repoURL) + " \"$TMP\"\n" +
		// Hardlink within the same filesystem to preserve the tenant's inode/file-count
		// quota; fall back to a full copy when hardlinking is unavailable.
		"cp -al \"$TMP\"/. \"$DEST\"/ 2>/dev/null || cp -a \"$TMP\"/. \"$DEST\"/\n" +
		"rm -rf \"$TMP\"\n" +
		"cd \"$DEST\"\n" +
		"[ -f .env ] || { [ -f .env.example ] && cp .env.example .env; }\n" +
		php + " " + shellQuote(composerBin()) + " install --no-interaction --prefer-dist || true\n" +
		"[ -f artisan ] && " + php + " artisan key:generate --force || true\n"
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// finalizeInstall transitions a stopped install job to its terminal status. It is a
// no-op while the unit is still running or the record is not in the installing state,
// so it is safe to call from both the status handler and the background reconciler.
// The DB write is a single-winner conditional UPDATE: only the caller that flips the
// row out of 'installing' performs the one-time side effects (docroot, unit cleanup).
func (h *Handlers) finalizeInstall(ctx context.Context, id int64, systemUser string, rec record) record {
	unit := setupUnit(id) + ".service"
	status := unitStatus(unit)
	running := status == "activating" || status == "active" || status == "reloading"
	if running || rec.LastDeployStatus != "installing" {
		return rec
	}
	appDir, _ := safeAppDir(systemUser, rec.AppRoot)
	artisan, _ := laravelInstalled(appDir)
	newStatus := "failed"
	if artisan {
		newStatus = "ready"
	}
	result, err := h.DB.ExecContext(ctx,
		`UPDATE cp_laravel_apps SET last_deploy_status=? WHERE domain_id=? AND last_deploy_status='installing'`,
		newStatus, id)
	if err != nil {
		return rec
	}
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if affected, _ := result.RowsAffected(); affected == 1 {
		if artisan {
			if _, statErr := os.Stat(filepath.Join(appDir, "public")); statErr == nil {
				if err := h.setDocroot(ctx, id, systemUser, publicSubdirectory(rec.AppRoot)); err != nil {
					// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
					log.Printf("laravel setDocroot domain %d: %v (docroot may still serve project root)", id, err)
				}
			}
		}
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		_ = exec.Command("systemctl", "reset-failed", unit).Run()
		_ = os.Remove(setupScriptPath(id))
	}
	rec.LastDeployStatus = newStatus
	return rec
}

func (h *Handlers) InstallStatus(w http.ResponseWriter, r *http.Request) {
	id, systemUser, _, _, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	unit := setupUnit(id) + ".service"
	status := unitStatus(unit)
	running := status == "activating" || status == "active" || status == "reloading"
	logTail := fileTail(setupLog(id), 8<<10)
	rec := h.finalizeInstall(r.Context(), id, systemUser, h.getRecord(r.Context(), id))
	// When the install unit crashed before writing output (e.g. disk or inode quota
	// exhaustion, permission errors), the log tail is empty and the operator sees no
	// cause. Append the unit's recent journal so the real failure reason surfaces.
	if !running && rec.LastDeployStatus == "failed" && len(strings.TrimSpace(logTail)) < 40 {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		if out, err := exec.Command("journalctl", "-u", unit, "-n", "30", "--no-pager").Output(); err == nil {
			logTail += "\n\n[system journal — install unit]\n" + cleanANSI(string(out))
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"running": running, "status": rec.LastDeployStatus, "log": logTail})
}
