// Package appinstall puts a packaged application into a tenant's document root.
//
// Until now only WordPress could be installed, through wp-cli, and everything
// else meant a customer finding an archive somewhere and uploading it.
//
// Nothing here is a new mechanism. The download goes through a netguard-guarded
// client, the archive is validated and unpacked by internal/archivex as the
// owning user, and the database is created by internal/credentials. What this
// package adds is the catalog, the checksum pin and the order the steps run in.
package appinstall

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
)

// Refusal reason codes. The screen renders twelve languages, so a refusal
// carries a code beside the English message.
const (
	ReasonUnknownApp      = "app_not_in_catalog"
	ReasonAppDisabled     = "app_disabled"
	ReasonNoChecksum      = "app_checksum_missing"
	ReasonChecksum        = "app_checksum_mismatch"
	ReasonBadSubdirectory = "app_subdirectory_invalid"
	ReasonTargetNotEmpty  = "app_target_not_empty"
	ReasonDatabaseExists  = "app_database_exists"
	ReasonDownload        = "app_download_failed"
	ReasonExtract         = "app_extract_failed"
)

// Refusal is an error carrying one of the codes above.
type Refusal struct {
	Code string
	Err  error
}

func (r *Refusal) Error() string {
	if r.Err != nil {
		return r.Code + ": " + r.Err.Error()
	}
	return r.Code
}

func (r *Refusal) Unwrap() error { return r.Err }

func refuse(code string, err error) error { return &Refusal{Code: code, Err: err} }

// ReasonOf returns the code of a refusal, or "" for anything else.
func ReasonOf(err error) string {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}

// Entry is one catalog row.
type Entry struct {
	Code            string `json:"code"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	DownloadURL     string `json:"download_url"`
	SHA256          string `json:"sha256"`
	ArchiveName     string `json:"archive_name"`
	StripComponents int    `json:"strip_components"`
	NeedsDatabase   bool   `json:"needs_database"`
	Enabled         bool   `json:"enabled"`
	UpdatedAt       string `json:"updated_at"`
}

// Install is one recorded installation.
type Install struct {
	ID           int64  `json:"id"`
	DomainID     int64  `json:"domain_id"`
	Code         string `json:"code"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Subdirectory string `json:"subdirectory"`
	SiteURL      string `json:"site_url"`
	DBName       string `json:"db_name"`
	DBUser       string `json:"db_user"`
	CreatedAt    string `json:"created_at"`
}

var (
	// codePattern is what a catalog code may be. It becomes part of a database
	// name and a log line.
	codePattern = regexp.MustCompile(`^[a-z][a-z0-9]{1,31}$`)

	// subdirectoryPattern is ONE path segment. A subdirectory that could carry
	// a slash would put the installation somewhere other than under the
	// document root, and one starting with a dot would hide it.
	subdirectoryPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

	// sha256Pattern is a lowercase hex digest.
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidSubdirectory reports whether a target subdirectory may be used. The
// empty string means the document root itself.
func ValidSubdirectory(subdirectory string) bool {
	return subdirectory == "" || subdirectoryPattern.MatchString(subdirectory)
}

// ValidEntry reports whether a catalog row may be stored, and why not.
//
// The URL must be https. An administrator entering a plain http address would
// be asking the panel to fetch executable code over a channel anybody on the
// path can rewrite, and the checksum would then be verifying whatever the
// attacker sent alongside it.
func ValidEntry(entry Entry) (string, bool) {
	switch {
	case !codePattern.MatchString(entry.Code):
		return "code", false
	case strings.TrimSpace(entry.Name) == "" || len(entry.Name) > 64:
		return "name", false
	case strings.TrimSpace(entry.Version) == "" || len(entry.Version) > 32:
		return "version", false
	case !strings.HasPrefix(entry.DownloadURL, "https://") || len(entry.DownloadURL) > 512:
		return "download_url", false
	case entry.SHA256 != "" && !sha256Pattern.MatchString(entry.SHA256):
		return "sha256", false
	case !validArchiveName(entry.ArchiveName):
		return "archive_name", false
	case entry.StripComponents < 0 || entry.StripComponents > 8:
		return "strip_components", false
	}
	return "", true
}

// validArchiveName reports whether the name carries an extension archivex can
// act on. It is a NAME, never a path: it is joined onto the panel's temporary
// directory, and a slash or a dot segment in it would leave that directory.
func validArchiveName(name string) bool {
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return false
	}
	for _, suffix := range []string{".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar", ".zip"} {
		if strings.HasSuffix(strings.ToLower(name), suffix) {
			return true
		}
	}
	return false
}

const catalogColumns = `code, name, version, download_url, sha256, archive_name,
	strip_components, needs_database, enabled, DATE_FORMAT(updated_at,'%Y-%m-%d %H:%i')`

func scanEntry(rs interface{ Scan(...any) error }) (Entry, error) {
	var entry Entry
	var needsDatabase, enabled int
	err := rs.Scan(&entry.Code, &entry.Name, &entry.Version, &entry.DownloadURL,
		&entry.SHA256, &entry.ArchiveName, &entry.StripComponents,
		&needsDatabase, &enabled, &entry.UpdatedAt)
	entry.NeedsDatabase = needsDatabase != 0
	entry.Enabled = enabled != 0
	return entry, err
}

// Catalog returns every catalog row.
func Catalog(ctx context.Context, db *sql.DB) ([]Entry, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+catalogColumns+` FROM app_catalog ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := make([]Entry, 0)
	for rows.Next() {
		entry, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

// LookupEntry returns one installable catalog row.
//
// A disabled entry and one with no checksum are refused HERE rather than at the
// download, so the refusal names the reason instead of failing later with a
// mismatch against an empty string.
func LookupEntry(ctx context.Context, db *sql.DB, code string) (Entry, error) {
	if !codePattern.MatchString(code) {
		return Entry{}, refuse(ReasonUnknownApp, nil)
	}
	entry, err := scanEntry(db.QueryRowContext(ctx,
		`SELECT `+catalogColumns+` FROM app_catalog WHERE code=?`, code))
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, refuse(ReasonUnknownApp, nil)
	}
	if err != nil {
		return Entry{}, err
	}
	if !entry.Enabled {
		return Entry{}, refuse(ReasonAppDisabled, nil)
	}
	// The pin is not optional. Installing an entry with no checksum would hand
	// a customer bytes the panel cannot vouch for, which is the one thing this
	// catalog exists to prevent.
	if !sha256Pattern.MatchString(entry.SHA256) {
		return Entry{}, refuse(ReasonNoChecksum, nil)
	}
	return entry, nil
}

// SaveEntry writes one catalog row.
func SaveEntry(ctx context.Context, db *sql.DB, entry Entry) error {
	needsDatabase, enabled := 0, 0
	if entry.NeedsDatabase {
		needsDatabase = 1
	}
	if entry.Enabled {
		enabled = 1
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO app_catalog
		   (code, name, version, download_url, sha256, archive_name,
		    strip_components, needs_database, enabled)
		 VALUES (?,?,?,?,?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE
		   name=VALUES(name), version=VALUES(version), download_url=VALUES(download_url),
		   sha256=VALUES(sha256), archive_name=VALUES(archive_name),
		   strip_components=VALUES(strip_components), needs_database=VALUES(needs_database),
		   enabled=VALUES(enabled)`,
		entry.Code, entry.Name, entry.Version, entry.DownloadURL, entry.SHA256,
		entry.ArchiveName, entry.StripComponents, needsDatabase, enabled)
	return err
}

// DeleteEntry removes one catalog row. Recorded installations survive it: they
// carry their own copy of the code and version for exactly this reason.
func DeleteEntry(ctx context.Context, db *sql.DB, code string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM app_catalog WHERE code=?`, code)
	return err
}
