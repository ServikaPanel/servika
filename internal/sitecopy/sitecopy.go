// Package sitecopy clones site files into timestamped staging copies under the same home directory.
// Copies are stored as public_html snapshots under ~/copies/copy_<ts>/ before changes and exclude databases.
// Security constraints prevent cross-user access, bind mounts, and fuser use. Deletion is restricted
// to /home/c_*/copies/ with both a name regular expression and a path-prefix guard.
package sitecopy

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"servika/internal/diskusage"
	"servika/internal/files"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

type Handlers struct{ DB *sql.DB }

const maxCopyBytes = 3 * 1024 * 1024 * 1024 // Direct sites over 3 GB to the Backups feature.

var copyNamePattern = regexp.MustCompile(`^copy_[0-9]{8}_[0-9]{6}$`)

type Copy struct {
	Name   string `json:"name"`
	SizeMB int64  `json:"size_mb"`
	Date   string `json:"date"`
}

func (h *Handlers) domain(r *http.Request) (id int64, systemUser string, ok bool) {
	id, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).Scan(&systemUser); err != nil {
		return id, "", false
	}
	return id, systemUser, true
}

// GET /domains/{id}/copy
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	_, systemUser, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	dir := "/home/" + systemUser + "/copies"
	out := []Copy{}
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() || !copyNamePattern.MatchString(e.Name()) {
				continue
			}
			copyItem := Copy{Name: e.Name()}
			if fi, err := e.Info(); err == nil {
				copyItem.Date = fi.ModTime().Format("2006-01-02 15:04")
			}
			copyItem.SizeMB = dirSizeMB(r.Context(), filepath.Join(dir, e.Name()))
			out = append(out, copyItem)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name }) // Sort newest first.
	httpx.WriteJSON(w, http.StatusOK, out)
}

// POST /domains/{id}/copy creates a staging copy.
func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	domainID, systemUser, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !strings.HasPrefix(systemUser, "c_") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user")
		return
	}
	// One copy per domain at a time. This runs a root rsync over the whole
	// document root, outside the tenant's cgroup, so without it a customer could
	// start any number of them at once and saturate the host's disk.
	release, claimed := lockDomain(domainID)
	if !claimed {
		httpx.WriteError(w, http.StatusConflict, "a copy is already being created for this domain")
		return
	}
	defer release()
	home := "/home/" + systemUser
	source := home + "/public_html"
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if _, err := os.Stat(source); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "public_html not found")
		return
	}
	if b := dirSizeBytes(r.Context(), source); b > maxCopyBytes {
		httpx.WriteError(w, http.StatusRequestEntityTooLarge, "site exceeds 3 GB; use the Backups tool")
		return
	}
	copyDir := home + "/copies"
	name := "copy_" + time.Now().Format("20060102_150405")
	relTarget := "copies/" + name + "/public_html"
	// The tenant owns this home and can replace any component with a symlink, so
	// the whole chain is created through openat2(RESOLVE_BENEATH|NO_SYMLINKS).
	// os.MkdirAll accepts a symlinked component, and the `chown` that used to
	// follow accepts one too: `chown` dereferences by default, so with
	// ~/copies pointing at /etc this handed the tenant ownership of /etc, and
	// with it /etc/passwd and /etc/cron.d. MkdirAllBeneath chowns each directory
	// it creates through that directory's own fd, so no path chown is needed.
	if err := files.MkdirAllBeneath(home, relTarget, systemUser); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create the copy directory")
		return
	}
	target := home + "/" + relTarget
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	// The trailing slash makes rsync copy directory contents. Omit --delete to keep the operation non-destructive.
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	if _, err := exec.CommandContext(ctx, "rsync", "-a", "--no-owner", "--no-group", source+"/", target+"/").CombinedOutput(); err != nil {
		// Symlink-safe removal: a path-based RemoveAll would follow a component
		// the tenant swapped while rsync was running.
		_ = files.RemoveAllBeneath(home, "copies/"+name)
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	// Assign ownership to the domain user. -h keeps chown on the link itself so a
	// tenant symlink inside the copy cannot retarget it.
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_ = exec.Command("chown", "-Rh", systemUser+":"+systemUser, copyDir+"/"+name).Run()
	files.RestoreconBeneath(home, "copies/"+name)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name, "size_mb": dirSizeMB(r.Context(), copyDir+"/"+name)})
}

// DELETE /domains/{id}/copy/{name}
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	_, systemUser, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !strings.HasPrefix(systemUser, "c_") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user")
		return
	}
	name := chi.URLParam(r, "name")
	if !copyNamePattern.MatchString(name) { // Strict name validation prevents path traversal.
		httpx.WriteError(w, http.StatusBadRequest, "invalid copy name")
		return
	}
	home := "/home/" + systemUser
	rel := "copies/" + name
	// os.Stat and os.RemoveAll resolve by path, so a tenant symlink at ~/copies
	// would have this root-run delete empty a directory elsewhere. Both steps go
	// through openat2(RESOLVE_BENEATH|NO_SYMLINKS) instead; the prefix check
	// above only proves the string is well formed, not where it lands.
	isDir, err := files.IsDirBeneath(home, rel)
	if err != nil || !isDir {
		httpx.WriteError(w, http.StatusNotFound, "copy not found")
		return
	}
	if err := files.RemoveAllBeneath(home, rel); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete record")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// dirSizeBytes measures a directory through internal/diskusage, which bounds the
// scan with a deadline and caches it. Measuring here by hand let a customer turn
// a held-down refresh of the copy list into one root-privileged full-tree scan
// per copy per request, outside their own cgroup I/O limit.
//
// A failed measurement reports 0. Every caller of this helper is display-only or
// compares against a ceiling, so a failure must not fail the request; the 3 GB
// guard in Create still refuses on a real over-size measurement.
func dirSizeBytes(ctx context.Context, p string) int64 {
	size, err := diskusage.Bytes(ctx, p)
	if err != nil {
		return 0
	}
	return size
}

func dirSizeMB(ctx context.Context, p string) int64 {
	return dirSizeBytes(ctx, p) / (1024 * 1024)
}
