// Package files provides a chrooted file manager API for domain home directories.
package files

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

const (
	// MaxUploadBytes is the maximum accepted multipart request body size.
	MaxUploadBytes     = 10 * 1024 * 1024 * 1024
	maxMultipartMemory = 32 * 1024 * 1024
)

var errUploadTooLarge = errors.New("upload exceeds the size limit")

var managedSystemUserPattern = regexp.MustCompile(`^c_[A-Za-z0-9_]+$`)

type Handlers struct {
	DB *sql.DB
}

// home resolves a domain ID to /home/c_<user>.
func (h *Handlers) home(r *http.Request) (string, string, error) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var systemUser string
	var isDemo int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, is_demo FROM domains WHERE id=?`, id).
		Scan(&systemUser, &isDemo)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", os.ErrNotExist
	}
	if err != nil {
		return "", "", err
	}
	if isDemo == 1 {
		return "", "", errDemo
	}
	if !managedSystemUserPattern.MatchString(systemUser) {
		return "", "", errBadUser
	}
	return "/home/" + systemUser, systemUser, nil
}

var (
	errDemo       = errors.New("files cannot be managed for a demo subscription")
	errBadUser    = errors.New("security: invalid system user")
	errEscape     = errors.New("security: escape from home directory blocked")
	errNotRegular = errors.New("not a regular file")
	errTooLarge   = errors.New("file exceeds the size limit")

	errSafeIOBadTarget = errors.New("security: empty destination path")
)

type Entry struct {
	Name        string `json:"name"`
	Path        string `json:"path"` // Relative to home for the panel UI.
	Type        string `json:"type"` // "folder" | "file" | "symlink"
	SizeBytes   int64  `json:"size_b"`
	Mode        string `json:"mode"`        // "0644"
	Permissions string `json:"permissions"` // "-rw-r--r--"
	Owner       string `json:"owner"`
	Group       string `json:"group"`
	Changed     string `json:"changed"` // RFC3339
}

// dirEntry is one listing row, filled while the directory fd is still pinned.
type dirEntry struct {
	Name    string
	Mode    os.FileMode
	Size    int64
	UID     uint32
	GID     uint32
	ModTime time.Time
}

func fileMetadata(info os.FileInfo) (mode, permissions, owner, group string) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "0" + strconv.FormatInt(int64(info.Mode().Perm()), 8), info.Mode().String(), "", ""
	}
	return describeMode(info.Mode(), stat.Uid, stat.Gid)
}

// describeMode renders one entry's mode and resolves its owner and group names.
// It takes the raw ids rather than an os.FileInfo so a listing can report what
// was read through the pinned directory fd, with no second, path-based stat.
func describeMode(fileMode os.FileMode, uid, gid uint32) (mode, permissions, owner, group string) {
	mode = "0" + strconv.FormatInt(int64(fileMode.Perm()), 8)
	permissions = fileMode.String()
	owner = strconv.FormatUint(uint64(uid), 10)
	if account, err := user.LookupId(owner); err == nil {
		owner = account.Username
	}
	group = strconv.FormatUint(uint64(gid), 10)
	if accountGroup, err := user.LookupGroupId(group); err == nil {
		group = accountGroup.Name
	}
	return mode, permissions, owner, group
}

func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	home, _, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), messageFromErr(err))
		return
	}
	rel := r.URL.Query().Get("path")
	if rel == "" {
		rel = "/"
	}
	// Symlink-safe listing: openat2 rejects any symlink component, so a tenant cannot
	// race a directory into a symlink between validation and the root-side read.
	dir, err := readDirBeneath(home, rel)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	out := make([]Entry, 0, len(dir))
	for _, e := range dir {
		ftype := "file"
		switch {
		case e.Mode.IsDir():
			ftype = "folder"
		case e.Mode&os.ModeSymlink != 0:
			ftype = "symlink"
		}
		mode, permissions, owner, group := describeMode(e.Mode, e.UID, e.GID)
		out = append(out, Entry{
			Name:        e.Name,
			Path:        filepath.ToSlash(filepath.Join(rel, e.Name)),
			Type:        ftype,
			SizeBytes:   e.Size,
			Mode:        mode,
			Permissions: permissions,
			Owner:       owner,
			Group:       group,
			Changed:     e.ModTime.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	// Sort folders first, then alphabetically.
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Type == "folder") != (out[j].Type == "folder") {
			return out[i].Type == "folder"
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"path":    filepath.ToSlash(rel),
		"content": out,
		"total":   len(out),
	})
}

// Download returns raw file content.
func (h *Handlers) Download(w http.ResponseWriter, r *http.Request) {
	// This endpoint moves a body far larger than the server's own read and write
	// timeouts allow for, so it lifts them for this request alone.
	if err := httpx.ExtendDeadline(w, r, httpx.LargeTransferDeadline); err != nil {
		log.Printf("file download: could not extend the socket deadline: %v", err)
	}

	home, _, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), messageFromErr(err))
		return
	}
	rel := r.URL.Query().Get("path")
	// Symlink-safe open: the fd is resolved beneath home following no symlinks, so a
	// tenant cannot race the path into a symlink and have root read a host file.
	f, err := openReadBeneath(home, rel)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	if info.IsDir() {
		httpx.WriteError(w, http.StatusBadRequest, "directories cannot be downloaded")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	// Encode the tenant-controlled filename safely so quotes or semicolons cannot
	// inject additional Content-Disposition parameters.
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": info.Name()})
	if disposition == "" {
		disposition = "attachment"
	}
	w.Header().Set("Content-Disposition", disposition)
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	_, _ = io.Copy(w, f)
}

// Read returns text file content for the editor.
func (h *Handlers) Read(w http.ResponseWriter, r *http.Request) {
	home, _, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), messageFromErr(err))
		return
	}
	rel := r.URL.Query().Get("path")
	// Symlink-safe read with an inline 2 MB cap (single fd, no separate racy stat).
	const maxEditBytes = 2 * 1024 * 1024
	data, info, err := readFileBeneath(home, rel, maxEditBytes)
	if errors.Is(err, errTooLarge) {
		httpx.WriteError(w, http.StatusBadRequest, "file exceeds 2 MB and cannot be edited")
		return
	}
	if errors.Is(err, errNotRegular) {
		httpx.WriteError(w, http.StatusBadRequest, "not a regular file")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"path":    rel,
		"content": string(data),
		"size":    info.Size(),
	})
}

type mkdirReq struct {
	Path string `json:"path"`
}

func (h *Handlers) Mkdir(w http.ResponseWriter, r *http.Request) {
	home, systemUser, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), messageFromErr(err))
		return
	}
	var req mkdirReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := mkdirAllBeneath(home, req.Path, systemUser); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"ok": true, "path": req.Path})
}

func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	home, _, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), messageFromErr(err))
		return
	}
	rel := r.URL.Query().Get("path")
	if rel == "" || rel == "/" {
		httpx.WriteError(w, http.StatusBadRequest, "the home directory cannot be deleted")
		return
	}
	if err := removeAllBeneath(home, rel); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": rel})
}

func (h *Handlers) Upload(w http.ResponseWriter, r *http.Request) {
	// This endpoint moves a body far larger than the server's own read and write
	// timeouts allow for, so it lifts them for this request alone.
	if err := httpx.ExtendDeadline(w, r, httpx.LargeTransferDeadline); err != nil {
		log.Printf("file upload: could not extend the socket deadline: %v", err)
	}

	home, systemUser, err := h.home(r)
	if err != nil {
		httpx.WriteError(w, statusFromErr(err), messageFromErr(err))
		return
	}
	rel := r.URL.Query().Get("path")
	if rel == "" {
		rel = "/"
	}
	// Concurrent-upload disk-exhaustion guard: reject with 507 when the temp
	// filesystem cannot hold another upload rather than letting parallel uploads
	// fill it and take the whole service down. The reservation is released on
	// every exit path below.
	if !reserveUploadSpace() {
		httpx.WriteError(w, http.StatusInsufficientStorage, "server disk space is temporarily low, please retry the upload later")
		return
	}
	defer releaseUploadSpace()
	if err := parseMultipartUpload(w, r, MaxUploadBytes, maxMultipartMemory); err != nil {
		if errors.Is(err, errUploadTooLarge) {
			httpx.WriteError(w, http.StatusRequestEntityTooLarge, "upload exceeds the 10 GiB limit")
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	// Anything over maxMultipartMemory is spooled to a temp file; without
	// RemoveAll those /tmp/multipart-* files survive the request and slowly fill
	// the disk. Clean them up on every exit path.
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	file, fh, err := r.FormFile("file")
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	defer func() { _ = file.Close() }()
	if fh.Size > MaxUploadBytes {
		httpx.WriteError(w, http.StatusRequestEntityTooLarge, "file is too large (maximum 10 GiB)")
		return
	}
	// The panel writes as root and then chowns to the tenant, which bypasses the
	// kernel EDQUOT check, so the plan disk quota could be exceeded. Check the
	// XFS quota before writing.
	if !uploadQuotaAvailable(systemUser, fh.Size) {
		httpx.WriteError(w, http.StatusInsufficientStorage, "disk quota exceeded — this upload would exceed your plan quota")
		return
	}
	uploadPath := filepath.Join(rel, fh.Filename)
	written, err := copyStreamBeneath(home, uploadPath, file, systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"ok":   true,
		"path": filepath.ToSlash(uploadPath),
		"size": written,
		"name": fh.Filename,
	})
}

func parseMultipartUpload(w http.ResponseWriter, r *http.Request, maxBytes int64, maxMemory int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	// #nosec G120 -- body is bounded by MaxBytesReader above, so parsing cannot exhaust memory.
	if err := r.ParseMultipartForm(maxMemory); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return errUploadTooLarge
		}
		return err
	}
	return nil
}

func statusFromErr(err error) int {
	switch err {
	case os.ErrNotExist:
		return http.StatusNotFound
	case errDemo:
		return http.StatusForbidden
	case errBadUser, errEscape:
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// messageFromErr returns a human-readable error message for filesystem-related
// sentinel errors, or a generic fallback for unknown errors.
func messageFromErr(err error) string {
	switch err {
	case os.ErrNotExist:
		return "not found"
	case errDemo:
		return "not available for demo subscriptions"
	case errBadUser, errEscape:
		return "invalid path"
	}
	return "operation failed"
}

// uploadReserved is the total temp-disk space currently reserved by in-flight
// uploads. Each upload reserves MaxUploadBytes; when free - reserved drops below
// what one more upload needs, the next upload is refused with 507. On a small
// disk this stops parallel uploads from filling the temp filesystem and taking
// every service down (a resource-exhaustion DoS).
var (
	uploadReserveMu sync.Mutex
	uploadReserved  int64
)

// reserveUploadSpace reserves room for one upload when the temp filesystem has
// it (returns true), otherwise false. Pair every true with releaseUploadSpace.
func reserveUploadSpace() bool {
	needed := int64(MaxUploadBytes) + 256*1024*1024 // upload cap + 256 MB safety margin
	uploadReserveMu.Lock()
	defer uploadReserveMu.Unlock()
	var st syscall.Statfs_t
	if err := syscall.Statfs(os.TempDir(), &st); err != nil {
		return true // statfs failed: do not block (keep prior behaviour)
	}
	// #nosec G115 -- Bavail/Bsize come from the OS statfs of a local temp dir, not attacker input; free space fits int64.
	free := int64(st.Bavail) * int64(st.Bsize)
	if free-uploadReserved < needed {
		return false
	}
	uploadReserved += int64(MaxUploadBytes)
	return true
}

func releaseUploadSpace() {
	uploadReserveMu.Lock()
	uploadReserved -= int64(MaxUploadBytes)
	if uploadReserved < 0 {
		uploadReserved = 0
	}
	uploadReserveMu.Unlock()
}

// uploadQuotaAvailable reports whether the tenant's XFS quota has room for
// extraBytes. It reads used/hard (KB) from xfs_quota. When the quota cannot be
// determined (tool missing / parse error) it fails open (true) so uploads are
// not broken. hard=0 means unlimited. This closes the quota bypass on the
// root-writes-then-chowns-to-tenant path.
func uploadQuotaAvailable(systemUser string, extraBytes int64) bool {
	if !strings.HasPrefix(systemUser, "c_") {
		return true
	}
	// The XFS quota lives on the mount: /home when it is a separate mount,
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	// otherwise the rootfs / (rootflags=uquota). Try both; use the first valid row.
	for _, mount := range []string{"/home", "/"} {
		out, err := exec.Command("xfs_quota", "-x", "-c", "quota -u -b -N "+systemUser, mount).CombinedOutput()
		if err != nil {
			continue
		}
		fields := strings.Fields(string(out))
		if len(fields) < 4 {
			continue
		}
		usedKB, e1 := strconv.ParseInt(fields[1], 10, 64)
		hardKB, e2 := strconv.ParseInt(fields[3], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		if hardKB <= 0 {
			return true // unlimited
		}
		return usedKB*1024+extraBytes <= hardKB*1024
	}
	return true // quota could not be determined -> fail open
}
