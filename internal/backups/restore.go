package backups

import (
	"context"
	"database/sql"
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

// commandContext builds every command this package runs. It is a variable so a
// test can answer tar, rsync, mysql, lftp and ssh-keyscan without running them;
// nothing outside tests changes it.
var commandContext = exec.CommandContext

// restoreSelected copies the chosen paths out of an extracted archive. The copy
// goes through openat2, which only Linux has, so a test answers it instead;
// nothing outside tests changes it.
var restoreSelected = restoreSelectedFiles

// newRestoreCommand runs a restore subprocess with an explicit environment
// allowlist, so panel secrets in the server environment are never inherited.
func newRestoreCommand(ctx context.Context, name string, arguments ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	command := commandContext(ctx, name, arguments...)
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
	// AllowCorrupt restores from an archive the integrity scan already recorded
	// as corrupt. It is an explicit override rather than a default, because the
	// panel's own evidence that the bytes rotted must not be silently ignored on
	// the one path that writes them over a live site.
	AllowCorrupt bool `json:"allow_corrupt"`
}

// httpRefusal is the status and message a handler step gives up with.
type httpRefusal struct {
	status  int
	message string
}

func (refusal *httpRefusal) write(w http.ResponseWriter) {
	httpx.WriteError(w, refusal.status, refusal.message)
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
	// An EMPTY body is tolerated and means "full"; a body that does not parse is
	// refused. Discarding the error made the two indistinguishable, and the
	// defaults below turn an unparsed body into the WIDEST operation this
	// endpoint offers: a request asking for files-only or one database, arriving
	// truncated, ran as a full restore over the live site and every schema.
	if err := decodeOptionalBody(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Mode = strings.TrimSpace(req.Mode)
	if req.Mode == "" {
		req.Mode = "full"
	}

	source, refusal := h.lookupRestoreSource(r, id, backupID)
	if refusal != nil {
		refusal.write(w)
		return
	}
	// The integrity scan already hashed this archive and recorded that it does not
	// match, and raised a critical notification about it. Applying it over a live
	// site anyway ignores the panel's own evidence, so it takes an explicit
	// override.
	if source.verification == "corrupt" && !req.AllowCorrupt {
		httpx.WriteError(w, http.StatusConflict,
			"this backup is recorded as corrupt; restore it only by confirming that explicitly")
		return
	}
	if refusal := source.invalid(); refusal != nil {
		refusal.write(w)
		return
	}
	// Reject a restore while another backup/restore runs for this domain, then
	// track this one so the customer sees its stages. Error paths are closed by the
	// deferred guard; the success path closes the record explicitly at the end.
	//
	// The CLAIM is the lock, not the progress record. progressActive is a check
	// followed by a separate write, so two callers could both find it free, and
	// the bulk-job and scheduler paths never set it at all. This endpoint does not
	// go through restoreCore, so it takes the lock itself.
	release, ok := lockDomain(id)
	if !ok {
		httpx.WriteError(w, http.StatusConflict, ErrDomainBusy.Error())
		return
	}
	defer release()
	progressStart(id, "restore", stagePreparing, 0)
	defer finishUnfinishedRestore(id)

	tmpDir, cleanup, refusal := stageRestore(r.Context(), h.DB, id, backupID, source, req)
	defer cleanup()
	if refusal != nil {
		refusal.write(w)
		return
	}

	result := map[string]any{
		"ok":          true,
		"mode":        req.Mode,
		"domain_name": source.domainName,
		"file":        source.file,
	}
	run := restoreRun{db: h.DB, id: id, tmpDir: tmpDir, systemUser: source.systemUser, req: req, result: result}
	if refusal := run.apply(r.Context()); refusal != nil {
		refusal.write(w)
		return
	}

	// Close the progress record on success (the deferred guard only catches the
	// error returns above).
	progressFinish(id, "", nil)
	httpx.WriteJSON(w, http.StatusOK, result)
}

// finishUnfinishedRestore closes a progress record the restore left open, which
// only an error return does.
func finishUnfinishedRestore(id int64) {
	if progressActive(id) {
		progressFinish(id, "", fmt.Errorf("the restore did not complete"))
	}
}

// restoreSource is the backup row a restore reads from.
type restoreSource struct {
	systemUser, domainName, file, verification string
}

// lookupRestoreSource reads the backup row, scoped to the domain in the URL.
func (h *Handlers) lookupRestoreSource(r *http.Request, id, backupID int64) (restoreSource, *httpRefusal) {
	var source restoreSource
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT d.system_user, d.domain_name, b.file, COALESCE(b.verification,'') FROM backups b
		 JOIN domains d ON d.id=b.domain_id
		 WHERE b.id=? AND b.domain_id=?`, backupID, id).
		Scan(&source.systemUser, &source.domainName, &source.file, &source.verification)
	if errors.Is(err, sql.ErrNoRows) {
		return source, &httpRefusal{http.StatusNotFound, "backup not found"}
	}
	if err != nil {
		return source, &httpRefusal{http.StatusInternalServerError, "internal server error"}
	}
	return source, nil
}

// invalid refuses a row whose identifiers cannot safely name a path.
func (source restoreSource) invalid() *httpRefusal {
	if !validSystemUser(source.systemUser) {
		return &httpRefusal{http.StatusBadRequest, "invalid system user"}
	}
	if source.file == "" || filepath.Base(source.file) != source.file {
		return &httpRefusal{http.StatusBadRequest, "invalid backup file"}
	}
	return nil
}

// stageRestore fetches the archive when only its off-site copy is left and
// extracts the members the mode needs into a new staging directory. cleanup
// removes that directory and is safe to call when none was made.
func stageRestore(ctx context.Context, db *sql.DB, id, backupID int64, source restoreSource, req restoreRequest) (string, func(), *httpRefusal) {
	noop := func() {}
	// Fetch the archive from the off-site destination when the local copy is
	// gone, so a pruned-but-uploaded backup is still restorable.
	progressStage(id, stageDownloading, 0)
	if err := ensureLocalArchive(ctx, db, id, backupID, source.systemUser, source.file); err != nil {
		return "", noop, &httpRefusal{http.StatusNotFound, err.Error()}
	}

	abs := filepath.Join(backupRoot(), source.systemUser, source.file)
	if refusal := restorableArchive(abs); refusal != nil {
		return "", noop, refusal
	}

	tmpDir, cleanup, failure := stageMembers(ctx, abs, source.systemUser, req.Mode, req.Paths,
		func() { progressStage(id, stageExtracting, 0) })
	if failure != stagedOK {
		return "", cleanup, &httpRefusal{failure.status(), failure.message()}
	}
	return tmpDir, cleanup, nil
}

// stageFailure names the step at which staging an archive's members stopped.
type stageFailure int

const (
	stagedOK stageFailure = iota
	stageNoContent
	stageNoTempDir
	stageBadArchive
)

// message is what a restore answers when staging stopped at f.
func (f stageFailure) message() string {
	switch f {
	case stageNoContent:
		return "the backup has no content for this restore mode"
	case stageNoTempDir:
		return "could not prepare backup restore"
	default:
		return "invalid backup archive"
	}
}

// status is the HTTP status the single-domain restore answers f with.
func (f stageFailure) status() int {
	if f == stageNoTempDir {
		return http.StatusInternalServerError
	}
	return http.StatusBadRequest
}

// stageMembers extracts the members a mode needs from abs into a new staging
// directory. beforeExtract runs once the directory exists. cleanup removes the
// directory and is safe to call when none was made.
//
// Quota-friendly staging: extract ONLY the members the mode needs, as root, into
// the panel temp dir (TMPDIR, persistent disk) so a second copy of the tenant home
// never counts against the tenant quota. extractMembersRoot pre-scans members and
// rejects jail escapes before any extraction.
func stageMembers(ctx context.Context, abs, systemUser, mode string, paths []string, beforeExtract func()) (string, func(), stageFailure) {
	noop := func() {}
	allMembers, _ := listArchiveMembers(abs)
	members := membersForMode(mode, systemUser, allMembers, paths)
	if len(members) == 0 {
		return "", noop, stageNoContent
	}
	tmpDir, err := os.MkdirTemp("", "servika-restore-*")
	if err != nil {
		return "", noop, stageNoTempDir
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }
	beforeExtract()
	if _, err := extractMembersRoot(ctx, abs, tmpDir, members); err != nil {
		return "", cleanup, stageBadArchive
	}
	return tmpDir, cleanup, stagedOK
}

// restorableArchive refuses an archive of a type restore cannot read, or a path
// that is not a regular file.
func restorableArchive(abs string) *httpRefusal {
	archiveType := archivex.DetectType(abs)
	if archiveType == archivex.TypeUnknown || archiveType == archivex.TypeRAR {
		return &httpRefusal{http.StatusBadRequest, "unsupported backup archive"}
	}
	archiveInfo, err := os.Lstat(abs)
	if err != nil || !archiveInfo.Mode().IsRegular() {
		return &httpRefusal{http.StatusNotFound, "backup file not found"}
	}
	return nil
}

// restoreRun is one single-domain restore over its staged archive.
type restoreRun struct {
	db         *sql.DB
	id         int64
	tmpDir     string
	systemUser string
	req        restoreRequest
	result     map[string]any
}

// apply runs the chosen mode and adds its outcome to the answer.
func (run restoreRun) apply(ctx context.Context) *httpRefusal {
	switch run.req.Mode {
	case "full":
		return run.full(ctx)
	case "files":
		return run.files(ctx)
	case "database":
		return run.databases(ctx)
	case "file":
		return run.selectedFiles(ctx)
	case "db":
		return run.oneDatabase(ctx)
	default:
		return &httpRefusal{http.StatusBadRequest, "invalid restore mode"}
	}
}

func (run restoreRun) full(ctx context.Context) *httpRefusal {
	progressStage(run.id, stageRestoringHome, 0)
	if err := restoreHome(ctx, run.tmpDir, run.systemUser, run.req.Clean); err != nil {
		return &httpRefusal{http.StatusInternalServerError, "could not restore the home directory"}
	}
	progressStage(run.id, stageImportingDB, 0)
	dbResults := restoreAllDBs(ctx, run.db, run.id, run.tmpDir, run.systemUser, "")
	run.result["databases"] = dbResults
	restored, _, failed, summary := dbSummary(dbResults)
	if failed > 0 {
		return &httpRefusal{http.StatusInternalServerError,
			"files were restored but a database import failed — " + summary}
	}
	// Zero databases restored is NOT success: the site files came back but
	// nothing it connects to did. The test is on `restored`, never on
	// `skipped > 0`, which encodes one SYMPTOM (an empty ownership whitelist
	// skipping every database) rather than the invariant. An archive that
	// carried no dump at all reports skipped=0 too, and that is exactly what a
	// backup whose dumps failed produces, so the old guard passed it as a
	// successful full recovery.
	if restored == 0 {
		return &httpRefusal{http.StatusInternalServerError,
			"files were restored but no database was restored — " + summary}
	}
	run.result["warning"] = overwriteWarning(run.req.Clean)
	return nil
}

func (run restoreRun) files(ctx context.Context) *httpRefusal {
	progressStage(run.id, stageRestoringHome, 0)
	if err := restoreHome(ctx, run.tmpDir, run.systemUser, run.req.Clean); err != nil {
		return &httpRefusal{http.StatusInternalServerError, "could not restore the home directory"}
	}
	run.result["warning"] = overwriteWarning(run.req.Clean)
	return nil
}

func (run restoreRun) databases(ctx context.Context) *httpRefusal {
	progressStage(run.id, stageImportingDB, 0)
	dbResults := restoreAllDBs(ctx, run.db, run.id, run.tmpDir, run.systemUser, strings.TrimSpace(run.req.DB))
	run.result["databases"] = dbResults
	restored, skipped, failed, summary := dbSummary(dbResults)
	if failed > 0 {
		return &httpRefusal{http.StatusInternalServerError, "a database import failed — " + summary}
	}
	// Reporting a database-only restore that restored nothing as success is the
	// exact failure this guards: the whitelist was empty and every database was
	// skipped, yet the job read as done.
	if restored == 0 {
		if skipped == 0 {
			return &httpRefusal{http.StatusBadRequest, "the backup has no database to restore"}
		}
		return &httpRefusal{http.StatusBadRequest, "no database was restored — " + summary}
	}
	run.result["warning"] = fmt.Sprintf("%d database(s) restored — %s", restored, summary)
	return nil
}

func (run restoreRun) selectedFiles(ctx context.Context) *httpRefusal {
	if len(run.req.Paths) == 0 {
		return &httpRefusal{http.StatusBadRequest, "no file was selected for restore"}
	}
	count, folder, err := restoreSelected(ctx, run.tmpDir, run.systemUser, run.req.Paths, run.req.Target)
	if err != nil {
		return &httpRefusal{http.StatusInternalServerError, "could not restore the selected files"}
	}
	run.result["file_count"] = count
	if folder != "" {
		run.result["target_folder"] = folder
		run.result["warning"] = "The selected files were extracted into " + folder + "/; existing files were kept."
	} else {
		run.result["warning"] = "The selected files were written back to their original locations."
	}
	return nil
}

func (run restoreRun) oneDatabase(ctx context.Context) *httpRefusal {
	if strings.TrimSpace(run.req.DB) == "" {
		return &httpRefusal{http.StatusBadRequest, "no database was selected"}
	}
	message, err := restoreOneDB(ctx, run.db, run.id, run.tmpDir, run.systemUser,
		strings.TrimSpace(run.req.DB), strings.TrimSpace(run.req.TargetDB))
	if err != nil {
		return &httpRefusal{http.StatusBadRequest, err.Error()}
	}
	run.result["databases"] = message
	return nil
}

// overwriteWarning describes what the chosen file-restore strategy did.
func overwriteWarning(clean bool) string {
	if clean {
		return "Clean restore: files missing from the backup were DELETED and database tables were recreated."
	}
	return "Files from the backup were written over the live ones; active files missing from the backup were kept."
}
