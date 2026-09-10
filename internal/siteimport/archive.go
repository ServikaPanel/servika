package siteimport

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path"

	"servika/internal/archivex"
	"servika/internal/files"
	"servika/internal/httpx"
)

// archiveLimits bounds a declared expansion. The member cap is what stops a
// bomb of millions of empty entries; the byte cap matches the upload cap,
// because anything that expands past it will not fit the tenant's quota either.
var archiveLimits = archivex.Limits{MaxTotalBytes: 40 << 30, MaxMembers: 400000}

// ArchiveSummary is what UploadArchive answers with: the staged upload plus what
// it contains, so the caller can confirm the destination before anything is
// written.
type ArchiveSummary struct {
	StageID     string           `json:"stage_id"`
	FileName    string           `json:"file_name"`
	Bytes       int64            `json:"bytes"`
	Summary     archivex.Summary `json:"summary"`
	App         string           `json:"app"`
	AppDir      string           `json:"app_dir"`
	CanSkipRoot bool             `json:"can_skip_root"`
	Warnings    []string         `json:"warnings"`
}

// UploadArchive stages a site archive and inventories it WITHOUT extracting.
//
// Analysis and extraction are separate calls on purpose: the user has to see the
// container directory and confirm the destination first, and an archive this
// size must not be uploaded twice to do that. The staged file is referenced by
// an opaque id afterwards.
func (h *Handlers) UploadArchive(w http.ResponseWriter, r *http.Request) {
	// This endpoint moves a body far larger than the server's own read and write
	// timeouts allow for, so it lifts them for this request alone.
	if err := httpx.ExtendDeadline(w, r, httpx.LargeTransferDeadline); err != nil {
		log.Printf("archive upload: could not extend the socket deadline: %v", err)
	}

	_, home, systemUser, err := h.domain(r)
	if err != nil {
		httpx.WriteError(w, statusFor(err), importMessage(err))
		return
	}
	sweepStaging(home)

	r.Body = http.MaxBytesReader(w, r.Body, MaxArchiveBytes+(1<<20))
	// MultipartReader rather than ParseMultipartForm: the latter spools the whole
	// upload into the temp directory before the handler sees a byte of it.
	reader, err := r.MultipartReader()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "a multipart body is required")
		return
	}
	var part *multipart.Part
	for {
		next, partErr := reader.NextPart()
		if errors.Is(partErr, io.EOF) {
			break
		}
		if partErr != nil {
			httpx.WriteError(w, http.StatusBadRequest, "the upload could not be read or exceeded the size limit")
			return
		}
		if next.FormName() == "archive" {
			part = next
			break
		}
		_ = next.Close()
	}
	if part == nil {
		httpx.WriteError(w, http.StatusBadRequest, "the archive field is required")
		return
	}
	defer func() { _ = part.Close() }()

	stageID, err := newStageID(part.FileName())
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := files.MkdirAllBeneath(home, stagingDir, systemUser); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the import work area could not be created")
		return
	}
	relative := path.Join(stagingDir, stageID)
	// One byte past the cap, so a body that is exactly at the limit still lands
	// and anything larger is detectable rather than silently truncated.
	written, err := files.StreamIntoBeneath(home, relative, io.LimitReader(part, MaxArchiveBytes+1), systemUser)
	if err != nil {
		_ = files.RemoveAllBeneath(home, relative)
		httpx.WriteError(w, http.StatusInternalServerError, "the archive could not be stored")
		return
	}
	if written > MaxArchiveBytes {
		_ = files.RemoveAllBeneath(home, relative)
		httpx.WriteError(w, http.StatusRequestEntityTooLarge, "the archive exceeds the size limit")
		return
	}

	// Summarized through a pinned descriptor rather than the path just written:
	// the staged file is owned by the tenant, who can replace it with a symlink
	// between the write and this read.
	archive, err := openStagedArchive(home, stageID)
	if err != nil {
		_ = files.RemoveAllBeneath(home, relative)
		httpx.WriteError(w, http.StatusInternalServerError, "the archive could not be stored")
		return
	}
	defer archive.Close()
	archiveType := archive.Type
	summary, err := archivex.Summarize(r.Context(), archive.Pinned, archiveType, archiveLimits, markerFiles)
	if err != nil {
		_ = files.RemoveAllBeneath(home, relative)
		httpx.WriteError(w, http.StatusBadRequest, "the archive could not be read: "+archiveMessage(err))
		return
	}

	answer := ArchiveSummary{
		StageID: stageID, FileName: path.Base(part.FileName()), Bytes: written,
		Summary: summary, Warnings: []string{},
	}
	answer.App, answer.AppDir = archivex.AppRoot(summary)
	answer.CanSkipRoot = summary.ContainerRoot != "" && archivex.StripSupported(archiveType)
	if summary.Members == 0 {
		answer.Warnings = append(answer.Warnings, "empty")
	}
	if summary.ContainerRoot == "" && len(summary.Roots) > 1 {
		answer.Warnings = append(answer.Warnings, "no_container_root")
	}
	if summary.ContainerRoot != "" && !archivex.StripSupported(archiveType) {
		answer.Warnings = append(answer.Warnings, "strip_unavailable")
	}
	httpx.WriteJSON(w, http.StatusOK, answer)
}

type applyArchiveRequest struct {
	StageID   string `json:"stage_id"`
	Target    string `json:"target"`     // home-relative; empty means public_html
	SkipRoot  bool   `json:"skip_root"`  // drop the archive's single container directory
	CleanDest bool   `json:"clean_dest"` // empty the destination first
}

type applyArchiveResponse struct {
	OK          bool   `json:"ok"`
	Target      string `json:"target"`
	SkippedRoot string `json:"skipped_root,omitempty"`
	Cleaned     bool   `json:"cleaned"`
}

// ApplyArchive extracts a staged archive into the chosen directory.
func (h *Handlers) ApplyArchive(w http.ResponseWriter, r *http.Request) {
	_, home, systemUser, err := h.domain(r)
	if err != nil {
		httpx.WriteError(w, statusFor(err), importMessage(err))
		return
	}
	var request applyArchiveRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Held open for the whole request: every reader below addresses the pinned
	// descriptor, so a tenant who swaps the staged name mid-request cannot
	// redirect a root read at a file of their choosing.
	archive, err := openStagedArchive(home, request.StageID)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, err.Error())
		return
	}
	defer archive.Close()
	target, err := targetDirectory(request.Target)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// The destination is created through openat2, so a tenant symlink at any
	// component is refused rather than followed by a root-privileged mkdir.
	if err := files.MkdirAllBeneath(home, target, systemUser); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "the destination could not be prepared")
		return
	}
	if request.CleanDest {
		// Emptied through the same fd-relative walk. A path-based RemoveAll would
		// follow a component the tenant swapped while the request was in flight.
		if err := files.ClearBeneath(home, target); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "the destination could not be emptied")
			return
		}
	}

	strip, skipped := 0, ""
	if request.SkipRoot {
		summary, summaryErr := archivex.Summarize(r.Context(), archive.Pinned, archive.Type, archiveLimits, nil)
		if summaryErr != nil {
			httpx.WriteError(w, http.StatusBadRequest, "the archive could not be read: "+archiveMessage(summaryErr))
			return
		}
		if summary.ContainerRoot == "" {
			httpx.WriteError(w, http.StatusBadRequest,
				"the archive has no single container directory to skip")
			return
		}
		strip, skipped = 1, summary.ContainerRoot
	}

	absoluteTarget := path.Join(home, target)
	if _, err := archivex.ExtractStrip(r.Context(), archive.Pinned, archive.Type, absoluteTarget, systemUser, strip, archiveLimits); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, archivex.ErrStripUnsupported) {
			status = http.StatusNotImplemented
		}
		httpx.WriteError(w, status, "extraction failed: "+archiveMessage(err))
		return
	}
	adoptExtracted(home, target, systemUser)
	// The staged copy has served its purpose and should not keep sitting in the
	// tenant's quota.
	_ = files.RemoveAllBeneath(home, path.Join(stagingDir, request.StageID))

	httpx.WriteJSON(w, http.StatusOK, applyArchiveResponse{
		OK: true, Target: target, SkippedRoot: skipped, Cleaned: request.CleanDest,
	})
}

// adoptExtracted hands the extracted tree to the tenant and restores the labels
// and ACL the web server needs. Each step is best effort: SELinux may be
// disabled and a filesystem may ignore ACLs, and neither should fail an import
// whose files are already in place.
//
// chown takes -h so a symlink inside the extracted tree is retagged rather than
// having its target's ownership changed.
func adoptExtracted(home, target, systemUser string) {
	absolute := path.Join(home, target)
	// #nosec G204 G702 -- fixed binary with separate args (no shell); systemUser matched managedSystemUser and the path is home-relative and openat2-resolved.
	_ = exec.Command("chown", "-Rh", systemUser+":"+systemUser, absolute).Run()
	files.RestoreconBeneath(home, target)
	if _, err := exec.LookPath("setfacl"); err != nil {
		return
	}
	for _, arguments := range [][]string{
		{"-R", "-m", "u:nginx:rX", absolute},
		{"-R", "-d", "-m", "u:nginx:rX", absolute},
	} {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); the path is home-relative and openat2-resolved.
		_ = exec.Command("setfacl", arguments...).Run()
	}
}

// archiveMessage keeps an archivex refusal readable without letting an
// unexpected internal error text reach the client.
func archiveMessage(err error) string {
	for _, known := range []error{
		archivex.ErrUnsupported, archivex.ErrUnsafePath, archivex.ErrUnsafeMember,
		archivex.ErrRARUnavailable, archivex.ErrInvalidArchive,
		archivex.ErrArchiveTooLarge, archivex.ErrTooManyMembers,
		archivex.ErrStripUnsupported, archivex.ErrInvalidTenant,
	} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return "the archive could not be processed"
}

// importMessage surfaces this package's own refusals and nothing else.
func importMessage(err error) string {
	switch {
	case errors.Is(err, errDemo), errors.Is(err, errBadUser):
		return err.Error()
	case errors.Is(err, os.ErrNotExist):
		return "domain not found"
	}
	return "internal server error"
}
