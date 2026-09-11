// Package siteimport moves a site onto an EXISTING domain, whatever panel it
// came from.
//
// internal/transfers already ingests a whole cPanel account and a live remote
// host, but both are vendor-shaped and both CREATE a domain. This package is the
// other case, and the common one: somebody has a zip of their site and a .sql
// file and a domain here already. It does three independent steps, any of which
// can be used on its own.
//
//  1. a site archive (zip/tar/tar.gz/tar.bz2/tar.xz/rar) into a directory
//  2. a SQL dump (.sql or .sql.gz) into one of the domain's own databases
//  3. the DB settings inside wp-config.php or .env rewritten to match
//
// Step 3 is the one that decides whether the other two produced a working site.
// The files arrive, the data arrives, and the site still answers "Error
// establishing a database connection" because the configuration still names the
// old server's database.
//
// Two surfaces here are dangerous and neither is guarded by being careful:
//
//   - The panel is root and the tenant owns their home, so any path this package
//     resolves can have a symlink planted at any component. Every read, write,
//     listing and removal goes through internal/files, which pins each component
//     with openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS). Extraction itself drops
//     to the tenant through internal/archivex.
//   - A SQL dump applied on the panel's root MariaDB connection hands over the
//     whole server. internal/sqlimport applies it as an account granted on the
//     one target schema.
package siteimport

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"servika/internal/archivex"
	"servika/internal/files"

	"github.com/go-chi/chi/v5"
)

type Handlers struct{ DB *sql.DB }

const (
	// MaxArchiveBytes caps one uploaded site archive.
	MaxArchiveBytes = int64(10 << 30)
	// MaxDumpBytes caps one uploaded SQL dump, before decompression.
	MaxDumpBytes = int64(4 << 30)
	// maxConfigBytes caps a configuration file the rewriter will touch.
	// wp-config.php and .env are a few kilobytes; anything larger is either not
	// the file we are looking for or is damaged, and is left alone.
	maxConfigBytes = int64(1 << 20)

	// stagingDir holds an uploaded archive between the analyse call and the
	// apply call. It lives in the TENANT's home, so it counts against their own
	// quota and the tenant-side extractor can read it.
	stagingDir = ".servika-import"
	// stagingLifetime is how long an unused upload survives. Abandoned uploads
	// would otherwise fill a tenant's disk with files they cannot see.
	stagingLifetime = 24 * time.Hour
)

var (
	errBadUser = errors.New("the domain has no valid system user")

	managedSystemUser = regexp.MustCompile(`^c_[A-Za-z0-9_]+$`)

	// archiveExtensions is the accepted set, used BOTH when accepting an upload
	// and when validating a staging id, so only these extensions can enter the
	// staging area and only these can be named on the way out.
	archiveExtensions = `(zip|tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|rar)`
	reArchiveSuffix   = regexp.MustCompile(`\.` + archiveExtensions + `$`)
	reStageID         = regexp.MustCompile(`^[0-9a-f]{32}\.` + archiveExtensions + `$`)
)

// markerFiles are the application signatures looked for inside an archive, both
// to tell the user what they uploaded and to offer the matching config rewrite.
var markerFiles = []string{
	"wp-config.php",     // WordPress
	"artisan",           // Laravel
	".env",              // Laravel / Symfony
	"configuration.php", // Joomla
	"settings.php",      // Drupal
	"index.php",
}

// domain resolves the URL's domain id to its home and system user. Ownership is
// already enforced by middleware.CustomerScope on the route.
func (h *Handlers) domain(r *http.Request) (id int64, home, systemUser string, err error) {
	id, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	err = h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).Scan(&systemUser)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", "", os.ErrNotExist
	}
	if err != nil {
		return 0, "", "", err
	}
	if !managedSystemUser.MatchString(systemUser) {
		return 0, "", "", errBadUser
	}
	return id, "/home/" + systemUser, systemUser, nil
}

// statusFor maps an internal failure to a response code without leaking the
// reason for anything unexpected.
func statusFor(err error) int {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return http.StatusNotFound
	case errors.Is(err, errBadUser):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// newStageID builds an opaque staging id carrying the archive's extension. The
// name is generated, never taken from the upload, so a crafted filename cannot
// reach the filesystem at all.
func newStageID(fileName string) (string, error) {
	extension := reArchiveSuffix.FindString(strings.ToLower(fileName))
	if extension == "" {
		return "", errors.New("unsupported format (zip, tar, tar.gz/tgz, tar.bz2, tar.xz, rar)")
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw) + extension, nil
}

// stagedArchive is a staged upload held OPEN, plus the two things a reader needs
// about it.
//
// Pinned is the /proc/self/fd path of the descriptor, so every later read
// resolves to the inode this package proved rather than to whatever the name
// points at by then. Type comes from the staging id, whose extension was taken
// from the upload; a pinned path carries no suffix to derive it from.
type stagedArchive struct {
	file *os.File
	// Pinned addresses the open descriptor and is valid only until Close.
	Pinned string
	// Type is the archive format, decided from the staging id.
	Type archivex.Type
}

// Close releases the descriptor. Pinned is meaningless afterwards.
func (a *stagedArchive) Close() { _ = a.file.Close() }

// openStagedArchive validates a staging id and opens the file it names.
//
// It returns a DESCRIPTOR rather than a path string, which is the whole point.
// The staging directory and the file inside it are created beneath the home and
// chowned to the tenant, so the tenant owns both and can unlink the file and put
// a symlink in its place at any moment. A path string checked once and then
// resolved again by every reader is not a boundary: between the check and the
// tar branch's second os.Open as root lie a mkdir, an optional clear, an
// optional full summary pass and the whole validation scan. Pinning once closes
// that window, because /proc/self/fd resolves to the inode, not the name.
func openStagedArchive(home, stageID string) (*stagedArchive, error) {
	if !reStageID.MatchString(stageID) {
		return nil, errors.New("invalid upload id")
	}
	file, err := files.OpenBeneath(home, path.Join(stagingDir, stageID))
	if err != nil {
		return nil, errors.New("the uploaded archive is gone (it may have expired)")
	}
	// Asserted on the DESCRIPTOR, as OpenBeneath requires: a named pipe or a
	// device node under the home opens successfully, and reading one would hang
	// the request or hand the extractor something that is not an archive.
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("the uploaded archive is gone (it may have expired)")
	}
	return &stagedArchive{
		file:   file,
		Pinned: "/proc/self/fd/" + strconv.Itoa(int(file.Fd())),
		Type:   archivex.DetectType(stageID),
	}, nil
}

// sweepStaging removes uploads older than stagingLifetime. It runs on every
// upload so an abandoned transfer cannot sit in a tenant's quota forever.
func sweepStaging(home string) {
	names, err := files.ListNamesBeneath(home, stagingDir)
	if err != nil {
		return
	}
	for _, name := range names {
		relative := path.Join(stagingDir, name)
		info, statErr := files.StatBeneath(home, relative)
		if statErr != nil || time.Since(info.ModTime()) < stagingLifetime {
			continue
		}
		_ = files.RemoveAllBeneath(home, relative)
	}
}

// targetDirectory reduces a requested destination to a clean home-relative path.
//
// The beneath helpers already refuse to leave the home, so the extra rule here
// is only that the staging area cannot be chosen: extracting an archive over its
// own source is not something a caller can mean.
func targetDirectory(requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		requested = "public_html"
	}
	clean := strings.Trim(path.Clean("/"+strings.ReplaceAll(requested, `\`, "/")), "/")
	if clean == "" || clean == "." {
		return "", errors.New("the destination cannot be the home directory itself")
	}
	if clean == stagingDir || strings.HasPrefix(clean, stagingDir+"/") {
		return "", errors.New("the import work area cannot be the destination")
	}
	return clean, nil
}
