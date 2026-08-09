package laravel

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

type Handlers struct {
	DB *sql.DB
}

type record struct {
	Exists           bool
	AppRoot          string
	DeployMode       string
	PHPVersion       string
	NodeVersion      string
	ScheduleEnabled  bool
	Maintenance      bool
	LastCommit       string
	LastDeployStatus string
}

func (h *Handlers) lookup(r *http.Request) (id int64, systemUser, phpVersion string, demo, ok bool) {
	id, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var isDemo int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, COALESCE(php_version,'8.3'), is_demo FROM domains WHERE id=?`, id).
		Scan(&systemUser, &phpVersion, &isDemo); err != nil {
		return id, "", "", false, false
	}
	return id, systemUser, phpVersion, isDemo == 1, true
}

func (h *Handlers) getRecord(ctx context.Context, id int64) record {
	var rec record
	var schedule, maintenance int
	err := h.DB.QueryRowContext(ctx,
		`SELECT app_root, deploy_mode, php_version, node_version, schedule_enabled,
		        maintenance, last_commit, last_deploy_status
		 FROM cp_laravel_apps WHERE domain_id=?`, id).
		Scan(&rec.AppRoot, &rec.DeployMode, &rec.PHPVersion, &rec.NodeVersion, &schedule,
			&maintenance, &rec.LastCommit, &rec.LastDeployStatus)
	if err != nil {
		return record{AppRoot: "public_html", DeployMode: "remote"}
	}
	rec.Exists = true
	rec.ScheduleEnabled = schedule == 1
	rec.Maintenance = maintenance == 1
	return rec
}

func (h *Handlers) upsertBase(ctx context.Context, id int64, appRoot, deployMode, php, node string) error {
	_, err := h.DB.ExecContext(ctx,
		`INSERT INTO cp_laravel_apps(domain_id, app_root, deploy_mode, php_version, node_version)
		 VALUES(?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE app_root=VALUES(app_root), deploy_mode=VALUES(deploy_mode),
		   php_version=VALUES(php_version), node_version=VALUES(node_version)`,
		id, appRoot, deployMode, php, node)
	return err
}

func laravelInstalled(appDir string) (artisan, composerJSON bool) {
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if _, err := os.Stat(filepath.Join(appDir, "artisan")); err == nil {
		artisan = true
	}
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if _, err := os.Stat(filepath.Join(appDir, "composer.json")); err == nil {
		composerJSON = true
	}
	return
}

func maintenanceActive(appDir string) bool {
	for _, path := range []string{"storage/framework/maintenance.php", "storage/framework/down"} {
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		if _, err := os.Stat(filepath.Join(appDir, path)); err == nil {
			return true
		}
	}
	return false
}

func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	id, systemUser, phpVersion, _, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	rec := h.getRecord(r.Context(), id)
	appRoot := rec.AppRoot
	if appRoot == "" {
		appRoot = "public_html"
	}
	appDir, err := safeAppDir(systemUser, appRoot)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid application directory")
		return
	}
	artisan, composerJSON := laravelInstalled(appDir)
	php := rec.PHPVersion
	if php == "" {
		php = phpVersion
	}
	gitPresent := false
	lastCommit := ""
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if _, err := os.Stat(filepath.Join(appDir, ".git")); err == nil {
		gitPresent = true
		if out, ok := TenantExec(r.Context(), systemUser, appDir, "/usr/bin/git", "-C", appDir, "rev-parse", "--short", "HEAD"); ok {
			lastCommit = strings.TrimSpace(out)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"installed":          artisan,
		"exists":             rec.Exists,
		"app_root":           appRoot,
		"system_user":        systemUser,
		"directory":          appDir,
		"php_version":        php,
		"node_version":       rec.NodeVersion,
		"composer_json":      composerJSON,
		"git_present":        gitPresent,
		"last_commit":        lastCommit,
		"maintenance":        maintenanceActive(appDir),
		"schedule_enabled":   rec.ScheduleEnabled,
		"last_deploy_status": rec.LastDeployStatus,
		"php_binary":         phpBin(php),
	})
}
