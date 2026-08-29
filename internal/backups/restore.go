package backups

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"servika/internal/archivex"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

const restoreCommandPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// newRestoreCommand runs a restore subprocess with an explicit environment
// allowlist, so panel secrets in the server environment are never inherited.
func newRestoreCommand(ctx context.Context, name string, arguments ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"PATH=" + restoreCommandPath, "HOME=/root"}
	return command
}

// restoreRequest is the granular restore body. Every field is optional; an empty
// body means mode "full".
type restoreRequest struct {
	Mode     string   `json:"mode"`      // full | files | database | file | db
	Clean    bool     `json:"clean"`     // mode full/files: rsync --delete (destructive)
	Paths    []string `json:"paths"`     // mode file: archive-relative paths
	Target   string   `json:"target"`    // mode file: "folder" (default) | "in_place"
	DB       string   `json:"db"`        // mode db (required) / database (optional filter)
	TargetDB string   `json:"target_db"` // mode db: "" overwrites, set restores into a new name
}

// Restore handles POST /api/v1/domains/:id/backups/:bid/restore.
// Granular restore: full / files only / databases only / selected files / one database.
// The defaults are NON-DESTRUCTIVE: full and files do not delete files missing from
// the backup (clean=false), selected files land in a separate folder, and a single
// database can be restored into a new name.
func (h *Handlers) Restore(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	backupID, _ := strconv.ParseInt(chi.URLParam(r, "bid"), 10, 64)

	var req restoreRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // an empty body is tolerated
	req.Mode = strings.TrimSpace(req.Mode)
	if req.Mode == "" {
		req.Mode = "full"
	}

	var systemUser, file, domainName string
	var isDemo int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT d.system_user, d.domain_name, d.is_demo, b.file FROM backups b
		 JOIN domains d ON d.id=b.domain_id
		 WHERE b.id=? AND b.domain_id=?`, backupID, id).Scan(&systemUser, &domainName, &isDemo, &file)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "backup not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if isDemo == 1 {
		httpx.WriteError(w, http.StatusForbidden, "restore is unavailable for demo subscriptions")
		return
	}
	if !validSystemUser(systemUser) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid system user")
		return
	}
	if file == "" || filepath.Base(file) != file {
		httpx.WriteError(w, http.StatusBadRequest, "invalid backup file")
		return
	}
	// Reject a restore while another backup/restore runs for this domain, then
	// track this one so the customer sees its stages. Error paths are closed by the
	// deferred guard; the success path closes the record explicitly at the end.
	if progressActive(id) {
		httpx.WriteError(w, http.StatusConflict, "an operation is already running for this domain")
		return
	}
	progressStart(id, "restore", stagePreparing, 0)
	defer func() {
		if progressActive(id) {
			progressFinish(id, "", fmt.Errorf("the restore did not complete"))
		}
	}()

	// Fetch the archive from the off-site destination when the local copy is
	// gone, so a pruned-but-uploaded backup is still restorable.
	progressStage(id, stageDownloading, 0)
	if err := ensureLocalArchive(r.Context(), h.DB, id, backupID, systemUser, file); err != nil {
		httpx.WriteError(w, http.StatusNotFound, err.Error())
		return
	}

	abs := filepath.Join(backupRoot(), systemUser, file)
	archiveType := archivex.DetectType(abs)
	if archiveType == archivex.TypeUnknown || archiveType == archivex.TypeRAR {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported backup archive")
		return
	}
	archiveInfo, err := os.Lstat(abs)
	if err != nil || !archiveInfo.Mode().IsRegular() {
		httpx.WriteError(w, http.StatusNotFound, "backup file not found")
		return
	}

	// Quota-friendly staging: extract ONLY the members the mode needs, as root, into
	// the panel temp dir (TMPDIR, persistent disk) so a second copy of the tenant home
	// never counts against the tenant quota. extractMembersRoot pre-scans members and
	// rejects jail escapes before any extraction.
	allMembers, _ := listArchiveMembers(abs)
	members := membersForMode(req.Mode, systemUser, allMembers, req.Paths)
	if len(members) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "the backup has no content for this restore mode")
		return
	}
	tmpDir, err := os.MkdirTemp("", "servika-restore-*")
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not prepare backup restore")
		return
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	progressStage(id, stageExtracting, 0)
	if _, err := extractMembersRoot(r.Context(), abs, tmpDir, members); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid backup archive")
		return
	}

	result := map[string]any{
		"ok":          true,
		"mode":        req.Mode,
		"domain_name": domainName,
		"file":        file,
	}

	switch req.Mode {
	case "full":
		progressStage(id, stageRestoringHome, 0)
		if err := restoreHome(r.Context(), tmpDir, systemUser, req.Clean); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not restore the home directory")
			return
		}
		progressStage(id, stageImportingDB, 0)
		dbResults := restoreAllDBs(r.Context(), h.DB, id, tmpDir, systemUser, "")
		result["databases"] = dbResults
		restored, skipped, failed, summary := dbSummary(dbResults)
		if failed > 0 {
			httpx.WriteError(w, http.StatusInternalServerError,
				"files were restored but a database import failed — "+summary)
			return
		}
		// Zero databases restored while some were skipped is NOT success: the site
		// files came back but nothing it connects to did.
		if restored == 0 && skipped > 0 {
			httpx.WriteError(w, http.StatusInternalServerError,
				"files were restored but no database was restored — "+summary)
			return
		}
		result["warning"] = overwriteWarning(req.Clean)

	case "files":
		progressStage(id, stageRestoringHome, 0)
		if err := restoreHome(r.Context(), tmpDir, systemUser, req.Clean); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not restore the home directory")
			return
		}
		result["warning"] = overwriteWarning(req.Clean)

	case "database":
		progressStage(id, stageImportingDB, 0)
		dbResults := restoreAllDBs(r.Context(), h.DB, id, tmpDir, systemUser, strings.TrimSpace(req.DB))
		result["databases"] = dbResults
		restored, skipped, failed, summary := dbSummary(dbResults)
		if failed > 0 {
			httpx.WriteError(w, http.StatusInternalServerError, "a database import failed — "+summary)
			return
		}
		// Reporting a database-only restore that restored nothing as success is the
		// exact failure this guards: the whitelist was empty and every database was
		// skipped, yet the job read as done.
		if restored == 0 {
			if skipped == 0 {
				httpx.WriteError(w, http.StatusBadRequest, "the backup has no database to restore")
			} else {
				httpx.WriteError(w, http.StatusBadRequest, "no database was restored — "+summary)
			}
			return
		}
		result["warning"] = fmt.Sprintf("%d database(s) restored — %s", restored, summary)

	case "file":
		if len(req.Paths) == 0 {
			httpx.WriteError(w, http.StatusBadRequest, "no file was selected for restore")
			return
		}
		count, folder, err := restoreSelectedFiles(r.Context(), tmpDir, systemUser, req.Paths, req.Target)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not restore the selected files")
			return
		}
		result["file_count"] = count
		if folder != "" {
			result["target_folder"] = folder
			result["warning"] = "The selected files were extracted into " + folder + "/; existing files were kept."
		} else {
			result["warning"] = "The selected files were written back to their original locations."
		}

	case "db":
		if strings.TrimSpace(req.DB) == "" {
			httpx.WriteError(w, http.StatusBadRequest, "no database was selected")
			return
		}
		message, err := restoreOneDB(r.Context(), h.DB, id, tmpDir, systemUser,
			strings.TrimSpace(req.DB), strings.TrimSpace(req.TargetDB))
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		result["databases"] = message

	default:
		httpx.WriteError(w, http.StatusBadRequest, "invalid restore mode")
		return
	}

	// Close the progress record on success (the deferred guard only catches the
	// error returns above).
	progressFinish(id, "", nil)
	httpx.WriteJSON(w, http.StatusOK, result)
}

// overwriteWarning describes what the chosen file-restore strategy did.
func overwriteWarning(clean bool) string {
	if clean {
		return "Clean restore: files missing from the backup were DELETED and database tables were recreated."
	}
	return "Files from the backup were written over the live ones; active files missing from the backup were kept."
}
