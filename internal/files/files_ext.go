package files

// files_ext.go provides Write, Rename, Chmod, and a symlink-aware jail.
// The original jailJoin is in files.go; this file adds handlers and hardening.

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"servika/internal/archivex"
	"servika/internal/httpx"
	"servika/internal/provisioner"
)

// Decompression-bomb defense for tenant-uploaded archives: cap the declared
// uncompressed size and member count before invoking the extractor.
const (
	maxExtractBytes   = 10 << 30 // 10 GiB, matching the upload size cap.
	maxExtractMembers = 200000
)

// relClean reduces a user-supplied path to a home-relative, '..'-cleaned path.
// A "/" prefix is added and Clean is applied to lexically dissolve any '..' entries;
// on Linux the real enforcement is still handled by openat2's RESOLVE_BENEATH flag.
func relClean(userPath string) string {
	return strings.TrimPrefix(filepath.Clean("/"+userPath), "/")
}

// A resolved path STRING is deliberately not offered here. Resolving a path and
// then operating on the result are two steps, and a tenant can swap a component
// for a symlink in between, which is how root ends up writing outside the jail.
// Every operation goes through the openat2 helpers in safeio_linux.go instead,
// where resolution and the operation are one kernel step.

// statusFromPathErr maps what the openat2 helpers report onto a status code. A
// refused resolution (a symlink component, or an attempt to leave home) and a
// missing path are the caller's problem, not the server's; the message stays
// generic either way.
func statusFromPathErr(err error) int {
	switch {
	case errors.Is(err, errEscape), errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.EXDEV):
		return http.StatusForbidden
	case errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

// ----- Write (editor save) -----

type writeRequest struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

func (h *Handlers) Write(w http.ResponseWriter, r *http.Request) {
	home, systemUser, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	var req writeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Content) > 5*1024*1024 {
		httpx.WriteError(w, http.StatusRequestEntityTooLarge, "files over 5 MB cannot be saved with the editor")
		return
	}
	// Preserve permissions when the file already exists.
	mode := uint32(0644)
	if f, err := openAt2Beneath(home, req.Path, 0, 0); err == nil {
		if st, err2 := f.Stat(); err2 == nil {
			mode = uint32(st.Mode().Perm())
		}
		_ = f.Close()
	}
	if err := writeBeneath(home, req.Path, []byte(req.Content), mode, systemUser); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"path": req.Path,
		"size": len(req.Content),
	})
}

// ----- Rename / Move -----

type renameReq struct {
	Old string `json:"old"`
	New string `json:"new"`
}

func (h *Handlers) Rename(w http.ResponseWriter, r *http.Request) {
	home, systemUser, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	var req renameReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Old == "/" || req.New == "/" {
		httpx.WriteError(w, http.StatusBadRequest, "the home directory cannot be moved")
		return
	}
	// Ensure the target parent directory exists (symlink-safe).
	_ = mkdirAllBeneath(home, filepath.Dir(req.New), systemUser)
	if err := renameBeneath(home, req.Old, req.New, systemUser); err != nil {
		httpx.WriteError(w, statusFromPathErr(err), "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "old": req.Old, "new": req.New})
}

// ----- Chmod -----

type chmodReq struct {
	Path string `json:"path"`
	Mode string `json:"mode"` // Octal string such as "0644".
}

func (h *Handlers) Chmod(w http.ResponseWriter, r *http.Request) {
	home, _, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	var req chmodReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mod := strings.TrimPrefix(req.Mode, "0")
	n, err := strconv.ParseUint(mod, 8, 32)
	if err != nil || n > 0o777 {
		httpx.WriteError(w, http.StatusBadRequest, "mode must be octal (0000-0777)")
		return
	}
	if err := chmodBeneath(home, req.Path, uint32(n)); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "path": req.Path, "mode": req.Mode})
}

// ----- Extract ZIP, TAR, RAR, or compressed TAR -----

type extractReq struct {
	Path   string `json:"path"`   // Archive path.
	Target string `json:"target"` // Optional extraction directory. Defaults to the archive directory.
}

func newFileCommand(ctx context.Context, name string, arguments ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	return command
}

// Bounds for the two tree-walking tools. Both are far shorter than the panel's
// 300-second request timeout, which is the only limit they had.
const (
	searchTimeout = 20 * time.Second
	sizeTimeout   = 30 * time.Second
)

// searchArgs and sizeArgs carry the flag that decides whether the walk can leave
// the tenant's tree. -H (find) and -D (du) dereference ONLY the command-line
// argument, which is what makes the /proc/self/fd pin usable while leaving every
// symlink inside the tree unfollowed. -L, the flag both used to carry,
// dereferences everything and puts the whole host within reach of the walk.
func searchArgs(base, pattern string) []string {
	return []string{"-H", base, "-iname", pattern, "-printf", "%p\t%s\t%y\t%T@\n"}
}

func sizeArgs(path string) []string {
	return []string{"-sb", "-D", path}
}

// archiveCommand builds the tool and arguments for one archive request.
//
// zip is given -y so a symbolic link is stored AS a link. Without it Info-ZIP
// follows the link and copies the CONTENT of its target into the archive, which
// is the opposite of tar's default and turns "archive my home" into a way to
// read whatever the link points at. tar needs no flag for this, and must never
// be given -h, which is the same trap.
func archiveCommand(format, output string, sources []string) (tool string, args []string) {
	if format == "zip" {
		return "zip", append([]string{"-r", "-q", "-y", output}, sources...)
	}
	return "tar", append([]string{"-czf", output}, sources...)
}

// tenantFileCommand runs an external file tool under the tenant's own uid. The
// panel runs as root, so a tool that walks a tenant-controlled tree would follow
// tenant symlinks with root's rights; under the tenant uid the kernel's own
// permission checks apply to every file it touches.
func tenantFileCommand(ctx context.Context, systemUser, name string, arguments ...string) *exec.Cmd {
	full := append([]string{"-u", systemUser, "--", name}, arguments...)
	// #nosec G204 G702 -- fixed binary (runuser) with separate args (no shell); systemUser comes from the domains row, not from the request.
	command := exec.CommandContext(ctx, "runuser", full...)
	command.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/home/" + systemUser,
		"USER=" + systemUser,
		"LOGNAME=" + systemUser,
	}
	return command
}

func (h *Handlers) Extract(w http.ResponseWriter, r *http.Request) {
	home, systemUser, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	var req extractReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Symlink-safe stat of the archive: reject non-regular files without a racy
	// path-based os.Lstat that a tenant could redirect via an intermediate symlink.
	//
	// The three outcomes are kept apart. A path that is missing or refused is the
	// caller's, and statusFromPathErr already words that; anything else is the
	// server's and has to say 500 and leave a line behind, because a fault
	// reported as bad input is one nobody goes looking for. Collapsing them into
	// a single 400 is how a helper that failed on every call once passed for a
	// missing file.
	info, err := statBeneath(home, req.Path)
	if err != nil {
		status := statusFromPathErr(err)
		if status == http.StatusInternalServerError {
			// #nosec G706 -- the logged path is relClean-normalised and the error is the kernel's; no raw tenant string with CR/LF reaches the log.
			log.Printf("extract: could not stat %q: %v", relClean(req.Path), err)
		}
		httpx.WriteError(w, status, "operation failed")
		return
	}
	if !info.Mode().IsRegular() {
		httpx.WriteError(w, http.StatusBadRequest, "path is not a regular file")
		return
	}

	target := req.Target
	if target == "" {
		target = filepath.Dir(req.Path)
	}
	// Create the target directory symlink-safe (rejects symlink components and chowns
	// new directories to the tenant), replacing the racy os.MkdirAll + chown on a
	// resolved string that a tenant could swap for a symlink escaping home.
	if err := mkdirAllBeneath(home, target, systemUser); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	// Pin the target directory through a symlink-safe fd. Its kernel-resolved
	// /proc/self/fd path is used for the tenant extraction and the final restorecon,
	// so intermediate components can no longer be raced after this point.
	targetFd, err := openReadBeneath(home, target)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	targetPinned := "/proc/self/fd/" + strconv.Itoa(int(targetFd.Fd()))

	// Resolve the archive through a symlink-safe fd and use its pinned path so the
	// external decompressors read the validated inode, not a raced one.
	archiveFd, err := openReadBeneath(home, req.Path)
	if err != nil {
		_ = targetFd.Close()
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	archivePinned := "/proc/self/fd/" + strconv.Itoa(int(archiveFd.Fd()))

	// The two pinned descriptors are closed here on every synchronous path and on
	// every error. The asynchronous archive branch sets handedOff and its goroutine
	// closes them instead, because the pinned paths must stay valid until the
	// extractor it starts has read them.
	handedOff := false
	defer func() {
		if !handedOff {
			_ = archiveFd.Close()
			_ = targetFd.Close()
		}
	}()

	lowerPath := strings.ToLower(req.Path)
	if strings.HasSuffix(lowerPath, ".gz") && archivex.DetectType(lowerPath) == archivex.TypeUnknown {
		gzipLeaf := strings.TrimSuffix(filepath.Base(req.Path), ".gz")
		// Create the gzip output symlink-safe beneath the pinned target directory.
		gzipRelative := filepath.Join(target, gzipLeaf)
		gzipOutput, err := openAt2Beneath(home, gzipRelative, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_TRUNC, 0644)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
			return
		}
		command := newFileCommand(r.Context(), "gunzip", "-k", "-c", archivePinned)
		command.Stdout = gzipOutput
		runErr := command.Run()
		if runErr == nil {
			// Chown the decompressed file to the tenant on the pinned inode.
			fchownRestoreFd(home, gzipOutput, systemUser)
		}
		closeErr := gzipOutput.Close()
		if runErr != nil || closeErr != nil {
			_ = removeAllBeneath(home, gzipRelative)
			httpx.WriteError(w, http.StatusBadRequest, "invalid gzip file")
			return
		}
	} else {
		if archivex.DetectType(lowerPath) == archivex.TypeUnknown {
			httpx.WriteError(w, http.StatusBadRequest, "unsupported format (zip, rar, tar, tar.gz/tgz, tar.bz2, tar.xz, gz)")
			return
		}
		// Extract as the tenant into the pinned target directory. Extraction runs
		// under the tenant uid, so it cannot escalate; the pinned target prevents a
		// raced symlink from redirecting the destination the panel selected. Limits
		// reject a decompression bomb before the extractor runs.
		//
		// A large archive extracts for longer than the router's 300-second request
		// timeout, so this runs in a goroutine that OWNS the pinned descriptors and
		// the page polls the progress endpoint. The goroutine uses a background
		// context, never the request's, which is cancelled the moment this handler
		// returns.
		limits := archivex.Limits{MaxTotalBytes: maxExtractBytes, MaxMembers: maxExtractMembers}
		jobID, err := newExtractJobID()
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
			return
		}
		job := &extractJob{systemUser: systemUser, state: extractRunning}
		extractJobs.Store(jobID, job)
		handedOff = true
		// #nosec G118 -- the request context is cancelled when this handler returns the job id, which would kill the extraction; runExtractJob deliberately uses a background context with its own timeout.
		go runExtractJob(job, archiveFd, targetFd, archivePinned, targetPinned, systemUser, limits)
		httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
			"ok":     true,
			"job_id": jobID,
			"path":   req.Path,
			"target": target,
		})
		return
	}

	// The gzip branch above is quick and stays synchronous, so it relabels and
	// answers here. The asynchronous archive branch relabels in its goroutine.
	if _, err := newFileCommand(r.Context(), "restorecon", "-R", targetPinned).CombinedOutput(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"path":   req.Path,
		"target": target,
	})
}

// ExtractProgress reports the state of an asynchronous extraction started by
// Extract. It is scoped to the tenant that owns the job, so one domain's owner
// cannot read another's progress even with a guessed id.
func (h *Handlers) ExtractProgress(w http.ResponseWriter, r *http.Request) {
	_, systemUser, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	value, ok := extractJobs.Load(r.URL.Query().Get("job"))
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "unknown extraction job")
		return
	}
	job, _ := value.(*extractJob)
	if job == nil || job.systemUser != systemUser {
		httpx.WriteError(w, http.StatusNotFound, "unknown extraction job")
		return
	}
	total, done, state, code := job.snapshot()
	// A finished job is pruned by the first poll that reads its terminal state.
	if state != extractRunning {
		extractJobs.Delete(r.URL.Query().Get("job"))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"state": string(state),
		"total": total,
		"done":  done,
		"error": code,
	})
}

// ----- Bulk copy and move -----

type bulkMoveCopyReq struct {
	Sources []string `json:"sources"`
	Target  string   `json:"target"` // Target folder that receives the sources.
}

func (h *Handlers) Copy(w http.ResponseWriter, r *http.Request) {
	h.bulkMoveCopy(w, r, false)
}

func (h *Handlers) Move(w http.ResponseWriter, r *http.Request) {
	h.bulkMoveCopy(w, r, true)
}

func (h *Handlers) bulkMoveCopy(w http.ResponseWriter, r *http.Request, move bool) {
	home, systemUser, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	var req bulkMoveCopyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Verify the target is a directory under home (symlink-safe).
	targetDir, err := isDirBeneath(home, req.Target)
	if err != nil || !targetDir {
		httpx.WriteError(w, http.StatusBadRequest, "target is not a directory")
		return
	}

	successful := 0
	errorsList := []string{}
	for _, source := range req.Sources {
		destination := filepath.Join(req.Target, filepath.Base(source))
		if destination == source {
			errorsList = append(errorsList, source+": source and target are identical")
			continue
		}
		var operationErr error
		if move {
			operationErr = renameBeneath(home, source, destination, systemUser)
		} else {
			operationErr = copyTreeBeneath(home, source, destination, systemUser)
		}
		if operationErr != nil {
			errorsList = append(errorsList, source+": operation failed")
			continue
		}
		successful++
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": len(errorsList) == 0, "successful": successful, "errors": errorsList,
	})
}

// ----- Archive selected files -----

type archiveReq struct {
	Resources  []string `json:"resources"`
	OutputPath string   `json:"output_path"` // Example: /public_html/backup.zip.
	Format     string   `json:"format"`      // zip | tar.gz
}

func (h *Handlers) Archive(w http.ResponseWriter, r *http.Request) {
	home, systemUser, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	var req archiveReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Resources) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "source missing")
		return
	}
	if req.Format == "" {
		req.Format = "zip"
	}
	// The archive is written into a directory resolved symlink-safe, and the tool is
	// given the kernel's own path for it so the entry names stay meaningful.
	outputRel := relClean(req.OutputPath)
	if err := mkdirAllBeneath(home, filepath.Dir(outputRel), systemUser); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	outputParent, err := realPathBeneath(home, filepath.Dir(outputRel))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	outputAbs := filepath.Join(outputParent, filepath.Base(outputRel))

	// Every source is resolved before the tool starts. A source that cannot be
	// resolved fails the request: dropping it would hand back an archive silently
	// missing what was asked for.
	sources := make([]string, 0, len(req.Resources))
	for _, resource := range req.Resources {
		resourceAbs, err := realPathBeneath(home, resource)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid request")
			return
		}
		sources = append(sources, resourceAbs)
	}

	// The tool runs under the tenant uid. That is the boundary that matters here:
	// it walks the tree itself, so any symlink it meets on the way is followed with
	// the tenant's own rights instead of root's.
	//
	// The panel's 300-second request timeout already bounds the run, and the
	// request context cancels the tool when the browser goes away.
	tool, args := archiveCommand(req.Format, outputAbs, sources)
	if _, err := tenantFileCommand(r.Context(), systemUser, tool, args...).CombinedOutput(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	// No chown: the tool ran as the tenant, so the archive is already theirs. The
	// relabel stays because restorecon reads the link itself (lgetfilecon) and so
	// cannot be redirected by one.
	_, _ = newFileCommand(r.Context(), "restorecon", outputAbs).CombinedOutput()

	// The archive exists either way, so a failure here is not the request's.
	// But size is OMITTED rather than sent as 0: an archive that was written and
	// one whose size could not be read are different facts, and zero reads as
	// the first. The failure is logged because nothing else would record it.
	response := map[string]any{"ok": true, "output_path": req.OutputPath}
	if info, err := statBeneath(home, outputRel); err != nil {
		// #nosec G706 -- the logged path is relClean-normalised and the error is the kernel's; no raw tenant string with CR/LF reaches the log.
		log.Printf("archive: created %q but could not read its size: %v", outputRel, err)
	} else {
		response["size"] = info.Size()
	}
	httpx.WriteJSON(w, http.StatusOK, response)
}

// ----- New empty file -----

type newFileRequest struct {
	Path string `json:"path"`
}

func (h *Handlers) NewFile(w http.ResponseWriter, r *http.Request) {
	home, systemUser, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	var req newFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := createExclBeneath(home, req.Path, systemUser); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"ok": true, "path": req.Path})
}

// ----- Calculate size with du -sb -----

func (h *Handlers) CalculateSize(w http.ResponseWriter, r *http.Request) {
	home, _, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	rel := r.URL.Query().Get("path")
	// Pin the target through a symlink-safe fd, then run du on the kernel-resolved
	// /proc/self/fd path so an intermediate symlink cannot redirect du outside home.
	pinned, err := openReadBeneath(home, rel)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	defer func() { _ = pinned.Close() }()
	fdPath := "/proc/self/fd/" + strconv.Itoa(int(pinned.Fd()))
	// -D dereferences ONLY the command-line argument, which is what makes the
	// /proc/self/fd pin usable. -L, which was here before, also followed every
	// symlink inside the tree, so a link to / had root measure the whole host and
	// report its size back to the tenant.
	//
	// The bound is its own, well under the panel's 300-second request timeout: a
	// deep tree otherwise keeps a root process busy for five minutes per request.
	sizeCtx, cancelSize := context.WithTimeout(r.Context(), sizeTimeout)
	defer cancelSize()
	out, err := newFileCommand(sizeCtx, "du", sizeArgs(fdPath)...).CombinedOutput()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	parts := strings.Fields(string(out))
	if len(parts) < 1 {
		httpx.WriteError(w, http.StatusInternalServerError, "could not parse du output")
		return
	}
	var b int64
	for _, c := range parts[0] {
		if c < '0' || c > '9' {
			break
		}
		b = b*10 + int64(c-'0')
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"path":   rel,
		"size_b": b,
	})
}

// ----- Recursive search by name pattern -----

func (h *Handlers) Search(w http.ResponseWriter, r *http.Request) {
	home, _, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), "operation failed")
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"content": []any{}, "total": 0})
		return
	}
	rel := r.URL.Query().Get("path")
	if rel == "" {
		rel = "/"
	}
	// Pin the search base through a symlink-safe fd and run find on its kernel-resolved
	// /proc/self/fd path, so the base and its ancestors cannot be swapped for symlinks
	// pointing outside home between validation and the walk.
	baseFd, err := openReadBeneath(home, rel)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	defer func() { _ = baseFd.Close() }()
	fdBase := "/proc/self/fd/" + strconv.Itoa(int(baseFd.Fd()))

	// Security: q is only a file-name pattern. Use iname without a shell to prevent injection.
	q = strings.ReplaceAll(q, "*", "")
	q = strings.ReplaceAll(q, "?", "")
	pattern := "*" + q + "*"

	// -H follows the /proc/self/fd symlink into the real base directory and NOTHING
	// else. -L, which was here before, followed every symlink met during the walk,
	// so a tenant link to / had root search the whole host and hand back its file
	// names, sizes and owners; the os.Lstat below then read those paths too.
	//
	// The search is bounded well under the panel's 300-second request timeout,
	// because an unbounded walk is a cheap way to hold a root process.
	searchCtx, cancelSearch := context.WithTimeout(r.Context(), searchTimeout)
	defer cancelSearch()
	out, _ := newFileCommand(searchCtx, "find", searchArgs(fdBase, pattern)...).Output()
	relBase := "/" + strings.Trim(relClean(rel), "/")
	results := []Entry{}
	for ln := range strings.SplitSeq(string(out), "\n") {
		if ln == "" {
			continue
		}
		parts := strings.SplitN(ln, "\t", 4)
		if len(parts) < 4 {
			continue
		}
		absp := parts[0]
		size := int64(0)
		for _, c := range parts[1] {
			if c < '0' || c > '9' {
				break
			}
			size = size*10 + int64(c-'0')
		}
		ftype := "file"
		switch parts[2] {
		case "d":
			ftype = "folder"
		case "l":
			ftype = "symlink"
		}
		// Rebase the /proc/self/fd/N-prefixed path back to a home-relative path.
		suffix := strings.TrimPrefix(absp, fdBase)
		relativePath := filepath.Clean(relBase + "/" + strings.TrimPrefix(suffix, "/"))
		if relativePath == "" {
			relativePath = "/"
		}
		info, _ := os.Lstat(absp)
		mode, permissions, owner, group := "", "", "", ""
		var changedAt string
		if info != nil {
			mode, permissions, owner, group = fileMetadata(info)
			changedAt = info.ModTime().UTC().Format("2006-01-02T15:04:05Z")
		}
		results = append(results, Entry{
			Name: filepath.Base(absp), Path: filepath.ToSlash(relativePath),
			Type: ftype, SizeBytes: size, Mode: mode, Permissions: permissions,
			Owner: owner, Group: group, Changed: changedAt,
		})
		if len(results) >= 500 {
			break
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"content": results, "total": len(results), "q": q,
	})
}

// ResetPermissions resets ownership and permissions across the tenant's
// public_html to the canonical values used at provisioning: directories 0750,
// files 0644, owned by the site's own system user (the CloudPanel
// "system:permissions:reset" equivalent). The walk is symlink-safe
// (resetTreeBeneath skips symlinks and cannot escape home), and only public_html
// is targeted — the home siblings (logs/tmp/ssl/.cron) are panel-managed and are
// not affected by user file corruption. The nginx read ACL is reapplied
// afterwards because a chmod can strip it.
func (h *Handlers) ResetPermissions(w http.ResponseWriter, r *http.Request) {
	home, systemUser, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), messageFromErr(err))
		return
	}
	if err := resetTreeBeneath(home, "public_html", systemUser, 0o750, 0o644); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not reset permissions")
		return
	}
	provisioner.ReapplyPublicHTMLACL(filepath.Join(home, "public_html"), systemUser)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
