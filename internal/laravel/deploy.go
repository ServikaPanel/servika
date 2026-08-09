package laravel

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"servika/internal/httpx"
)

func deployUnit(id int64) string       { return fmt.Sprintf("servika-laravel-deploy-%d", id) }
func deployLog(id int64) string        { return fmt.Sprintf("%s/deploy-%d.log", logRootDir(), id) }
func deployScriptPath(id int64) string { return fmt.Sprintf("/run/servika-laravel-deploy-%d.sh", id) }

func deployScript(appDir, php, nodeDir string, migrate, npmBuild bool) string {
	var b strings.Builder
	b.WriteString("#!/bin/bash\n")
	fmt.Fprintf(&b, "export PATH=%s:%s\n", nodeDir, systemPath)
	fmt.Fprintf(&b, "cd %s || exit 1\n", shellQuote(appDir))
	// FAILED records the first required step that fails. Critical steps no longer use
	// "|| true"; instead a failure is recorded and later steps still run so maintenance
	// mode is always lifted, but the final status reflects the first failure.
	b.WriteString("FAILED=\"\"\n")
	b.WriteString("fail() { [ -z \"$FAILED\" ] && FAILED=\"$1\"; echo \"!! step failed: $1\"; }\n")
	b.WriteString("echo '== enable maintenance mode =='\n")
	fmt.Fprintf(&b, "%s artisan down || true\n", php) // non-critical: ok if not installed yet
	b.WriteString("echo '== git pull =='\n")
	b.WriteString("if [ -d .git ]; then git pull --ff-only 2>&1 || git pull 2>&1 || fail 'git pull'; else echo '(not a git repository, skipped)'; fi\n")
	b.WriteString("echo '== composer install (--no-dev) =='\n")
	fmt.Fprintf(&b, "%s %s install --no-interaction --prefer-dist --no-dev 2>&1 || fail 'composer install'\n", php, shellQuote(composerBin()))
	if npmBuild {
		b.WriteString("echo '== npm ci + build =='\n")
		fmt.Fprintf(&b, "{ %s/npm ci --prefix %s --no-fund --no-audit 2>&1 || %s/npm install --prefix %s 2>&1; } || fail 'npm install'\n", nodeDir, shellQuote(appDir), nodeDir, shellQuote(appDir))
		fmt.Fprintf(&b, "%s/npm run build --prefix %s 2>&1 || fail 'npm build'\n", nodeDir, shellQuote(appDir))
	}
	if migrate {
		b.WriteString("echo '== migrate --force =='\n")
		fmt.Fprintf(&b, "%s artisan migrate --force 2>&1 || fail 'migrate'\n", php)
	}
	b.WriteString("echo '== cache =='\n")
	fmt.Fprintf(&b, "%s artisan config:cache 2>&1 || fail 'config:cache'\n", php)
	fmt.Fprintf(&b, "%s artisan route:cache 2>&1 || fail 'route:cache'\n", php)
	b.WriteString("echo '== disable maintenance mode =='\n")
	fmt.Fprintf(&b, "%s artisan up || true\n", php) // always lift maintenance, even after a failure
	// Emit COMPLETE only when no required step failed; otherwise emit a FAILED marker
	// that the status handler treats as a failed deploy.
	b.WriteString("if [ -z \"$FAILED\" ]; then echo '== DEPLOY COMPLETE =='; else echo \"== DEPLOY FAILED: $FAILED ==\"; exit 1; fi\n")
	return b.String()
}

func (h *Handlers) Deploy(w http.ResponseWriter, r *http.Request) {
	id, systemUser, phpVersion, demo, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "deploy cannot be run for demo subscriptions")
		return
	}
	defer lockDomain(id)()
	var currentStatus string
	_ = h.DB.QueryRowContext(r.Context(), `SELECT COALESCE(last_deploy_status,'') FROM cp_laravel_apps WHERE domain_id=?`, id).Scan(&currentStatus)
	if currentStatus == "installing" || currentStatus == "running" {
		httpx.WriteError(w, http.StatusConflict, "an install or deploy operation is already running for this domain")
		return
	}
	var req struct {
		Migrate     bool   `json:"migrate"`
		NpmBuild    bool   `json:"npm_build"`
		NodeVersion string `json:"node_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
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
	nodeDir := nodeBinDir(req.NodeVersion)
	script := deployScript(appDir, phpBin(phpVersion), nodeDir, req.Migrate, req.NpmBuild)
	path := deployScriptPath(id)
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "deploy script write failed")
		return
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_ = exec.Command("systemctl", "reset-failed", deployUnit(id)+".service").Run()
	if err := systemdRunDetached(systemUser, appDir, deployUnit(id), deployLog(id), "/bin/bash", path); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "deploy start failed")
		return
	}
	_, _ = h.DB.ExecContext(r.Context(), `UPDATE cp_laravel_apps SET last_deploy_status='running', last_deploy_at=NOW() WHERE domain_id=?`, id)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "unit": deployUnit(id)})
}

// deployTerminalStatus maps a deploy log tail to its terminal status: "successful"
// only when the completion marker is present, otherwise "failed".
func deployTerminalStatus(logTail string) string {
	if strings.Contains(logTail, "DEPLOY COMPLETE") {
		return "successful"
	}
	return "failed"
}

// finalizeDeploy transitions a stopped deploy job to its terminal status. It is a
// no-op while the unit is still running or the record is not in the running state,
// so it is safe to call from both the status handler and the background reconciler.
// The DB write is a single-winner conditional UPDATE: only the caller that flips the
// row out of 'running' performs the one-time side effects (unit cleanup, script removal).
func (h *Handlers) finalizeDeploy(ctx context.Context, id int64, systemUser string, rec record) record {
	unit := deployUnit(id) + ".service"
	status := unitStatus(unit)
	running := status == "activating" || status == "active" || status == "reloading"
	if running || rec.LastDeployStatus != "running" {
		return rec
	}
	newStatus := deployTerminalStatus(fileTail(deployLog(id), 16<<10))
	appDir, _ := safeAppDir(systemUser, rec.AppRoot)
	lastCommit := ""
	if out, ok := TenantExec(ctx, systemUser, appDir, "/usr/bin/git", "-C", appDir, "rev-parse", "--short", "HEAD"); ok {
		lastCommit = strings.TrimSpace(out)
	}
	result, err := h.DB.ExecContext(ctx,
		`UPDATE cp_laravel_apps SET last_deploy_status=?, last_commit=? WHERE domain_id=? AND last_deploy_status='running'`,
		newStatus, lastCommit, id)
	if err != nil {
		return rec
	}
	if affected, _ := result.RowsAffected(); affected == 1 {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		_ = exec.Command("systemctl", "reset-failed", unit).Run()
		_ = os.Remove(deployScriptPath(id))
		h.restartWorkersAfterDeploy(ctx, id)
	}
	rec.LastDeployStatus = newStatus
	rec.LastCommit = lastCommit
	return rec
}

// restartWorkersAfterDeploy moves every running worker onto the code that was
// just deployed.
//
// A PHP worker loads the application once and keeps it in memory, so without
// this the old code keeps processing jobs until --max-time expires, which is up
// to an hour after a deploy the customer watched succeed.
//
// The restart goes through systemd rather than `artisan queue:restart`. That
// command writes a cache key the worker polls, so an application whose cache
// driver is misconfigured loses the signal silently, which is exactly the state
// somebody is most likely deploying to fix. systemd is the panel's own path and
// depends on nothing the tenant configured. It is graceful all the same: SIGTERM
// goes first and TimeoutStopSec is rendered above the job timeout, so the job in
// hand finishes.
//
// It is called only from the single-winner branch that flipped the row out of
// 'running', so a deploy restarts its workers exactly once however many callers
// poll the status endpoint.
func (h *Handlers) restartWorkersAfterDeploy(ctx context.Context, domainID int64) {
	workers, err := WorkersForDomain(ctx, h.DB, domainID)
	if err != nil {
		// #nosec G706 -- the logged values are an integer id and a driver error from a SELECT whose only parameter is bound; no raw tenant string with CR/LF reaches the log.
		log.Printf("laravel: deploy of domain %d finished but its workers could not be read: %v", domainID, err)
		return
	}
	for _, worker := range workers {
		if !worker.Enabled {
			continue
		}
		if err := RestartWorker(worker); err != nil {
			// The deploy itself succeeded, so this is reported rather than
			// turned into a failure: saying nothing would leave the old code
			// running with no trace of why.
			// #nosec G706 -- the logged values are integer ids and systemctl output about a unit name derived from those ids; no raw tenant string with CR/LF reaches the log.
			log.Printf("laravel: worker %d of domain %d did not restart after the deploy: %v",
				worker.ID, domainID, err)
		}
	}
}

func (h *Handlers) DeployStatus(w http.ResponseWriter, r *http.Request) {
	id, systemUser, _, _, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	unit := deployUnit(id) + ".service"
	status := unitStatus(unit)
	running := status == "activating" || status == "active" || status == "reloading"
	logTail := fileTail(deployLog(id), 16<<10)
	rec := h.finalizeDeploy(r.Context(), id, systemUser, h.getRecord(r.Context(), id))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"running": running, "status": rec.LastDeployStatus, "last_commit": rec.LastCommit, "log": logTail})
}
