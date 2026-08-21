// Package wpchecksums keeps WordPress core checksum tables on disk so the
// integrity check still has an answer when api.wordpress.org cannot be reached.
//
// `wp core verify-checksums` fetches the table itself on every run and there is
// no way to hand it one, so an unreachable wordpress.org leaves the command with
// nothing to compare against. That is not a defect in the command; the defect is
// reporting the result as a clean core, which internal/wordpress used to do. The
// honest answer is "not measured", and this package is what turns a large part
// of that into a real measurement instead.
//
// It is deliberately NOT a replacement for the command. Two differences are
// intentional and both make this the FALLBACK rather than the engine:
//
//   - wp-cli runs as the tenant (`runuser -u`), while everything here runs as
//     root. Every read of a tenant tree therefore goes through files.OpenBeneath
//     (openat2 with RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS), so a symlink planted
//     where a core file belongs is REFUSED here while wp-cli follows it and
//     hashes the target. The direction is safe but the answer is not identical.
//   - openat2 is Linux only, so on any other platform this reports that it could
//     not measure rather than pretending to.
//
// The comparison below is read from the command's own source rather than
// guessed, because a reproduction that is close is worse than none: it reports
// files as extra or missing on healthy sites. Measured against WP-CLI 2.12.0
// (checksum-command's Checksum_Core_Command and Checksum_Base_Command):
//
//   - Pass one walks the CHECKSUM TABLE. A `wp-content` prefix is skipped, a
//     path that is absent is "File doesn't exist", and an md5 mismatch is "File
//     doesn't verify against checksum". Both count as errors.
//   - Pass two walks the DISK. Anything passing the same file filter that the
//     table does not name is "File should not exist". This does NOT count as an
//     error, which is why an installation whose only problem is an extra file
//     exits 0 (measured).
//   - The filter keeps `wp-admin/` and `wp-includes/` and the root-level `wp-*`
//     files except `wp-config.php`, and nothing else. So `readme.html` is
//     verified by pass one and can never be reported as extra by pass two.
//
// The reproduction was then measured against the command itself on a real
// Turkish WordPress 7.1 tree, 4009 files, with the published tr_TR table:
//
//	clean tree            wp-cli 0 verdicts     this package 0 verdicts
//	one core file edited  both: File doesn't verify against checksum: wp-includes/pluggable.php
//	one core file deleted both: File doesn't exist: wp-admin/about.php
//	one file planted      both: File should not exist: wp-includes/js/jquery/jquery.min.php
//
// The clean result is not vacuous: the same table and the same walk report the
// three defects on the tree that has them.
package wpchecksums

import (
	"context"
	"crypto/md5" // #nosec G501 -- wordpress.org publishes md5, so the comparison has no other choice.
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"servika/internal/config"
	"servika/internal/files"
)

// checksumAPI is wordpress.org's published endpoint. It is a fixed address the
// operator did not name, so it does NOT go through internal/netguard: that guard
// exists for a host a CUSTOMER supplied.
const checksumAPI = "https://api.wordpress.org/core/checksums/1.0/"

// tableCeiling bounds the decoded response. A full core table is roughly 200 KB
// of JSON; the ceiling is enforced while streaming rather than read off
// Content-Length, which the remote server supplies.
const tableCeiling = 8 << 20

// versionFileHead mirrors what wp-cli reads out of version.php: 2048 bytes from
// offset 6. Reading the whole file instead would also work, but matching the
// command means a file whose tail was appended to cannot make the two disagree
// about which version is installed.
const (
	versionFileOffset = 6
	versionFileLength = 2048
)

// Details is what version.php says about the installation.
type Details struct {
	// Version is $wp_version.
	Version string
	// Locale is $wp_local_package, empty on an English installation. The
	// distinction matters: wordpress.org publishes a DIFFERENT version.php for
	// every localized build, so asking for en_US checksums on a Turkish
	// installation reports version.php as modified on a healthy site (measured
	// against a real tr_TR 7.1 install: disk 45ddd1e0…, en_US table c77f737c…,
	// tr_TR table 45ddd1e0…).
	Locale string
}

// Verdict is one line of the report, in the same vocabulary the command uses so
// internal/wordpress can map both through one table.
type Verdict struct {
	// Message is the command's own wording, without the trailing path.
	Message string
	// Rel is relative to the WordPress directory.
	Rel string
}

// The three messages, spelled as the command spells them.
const (
	MessageMissing  = "File doesn't exist"
	MessageModified = "File doesn't verify against checksum"
	MessageExtra    = "File should not exist"
)

// ErrNoTable means the table for this version and locale is neither cached nor
// reachable, so nothing was compared. It is never a clean result.
var ErrNoTable = errors.New("no checksum table for this version and locale")

// ErrUnknownVersion means wordpress.org ANSWERED and publishes nothing for this
// version and locale. It is a different fact from being unable to ask, and the
// difference is the whole point: version.php is both the source of the version
// and one of the files being verified, so editing it to name a version that was
// never released blinds the entire check, and the edited file escapes with it.
//
// Measured against the live endpoint: a made-up version answers HTTP 200 with
// the body {"checksums":false}.
var ErrUnknownVersion = errors.New("wordpress.org publishes no checksums for this version and locale")

// client is the HTTP client used for the fetch. A variable so a test can point
// it at a server it built; the production value is created once.
var client = &http.Client{Timeout: 30 * time.Second}

// endpoint is the base URL, likewise replaceable in a test.
var endpoint = checksumAPI

// negative remembers a version and locale wordpress.org answered nothing for, so
// a site on a version that was never published does not fetch on every check.
// It is memory only: a panel restart is a cheap and obvious way to retry, and a
// negative entry on disk would outlive the reason for it.
var negative sync.Map

// ReadDetails reads the version and the package locale out of version.php.
//
// The read is beneath the tenant home, so a symlink at any component is refused
// rather than followed: this runs as root, and version.php decides which table
// is fetched and therefore which file name is written into the cache directory.
func ReadDetails(home, relDir string) (Details, error) {
	rel := path.Join(relDir, "wp-includes/version.php")
	body, err := files.ReadFileBeneath(home, rel, versionFileOffset+versionFileLength)
	if err != nil {
		return Details{}, err
	}
	if len(body) <= versionFileOffset {
		return Details{}, errors.New("version.php is too short to be a WordPress version file")
	}
	text := string(body[versionFileOffset:])

	version := findVar("wp_version", text)
	if !validVersion(version) {
		return Details{}, fmt.Errorf("version.php does not name a usable WordPress version")
	}
	locale := findVar("wp_local_package", text)
	if !validLocale(locale) {
		// An unreadable locale is dropped rather than refused. Dropping it asks
		// for the en_US table, which is what an installation with no
		// $wp_local_package really is; refusing would take the whole check away
		// over a line nothing else depends on.
		locale = ""
	}
	return Details{Version: version, Locale: locale}, nil
}

// findVar mirrors wp-cli's own reader: find `$name = `, take everything up to
// the next `;`, and trim spaces and single quotes. It is not a PHP parser and
// does not need to be, because it reads a file WordPress generates.
func findVar(name, code string) string {
	_, rest, found := strings.Cut(code, "$"+name+" = ")
	if !found {
		return ""
	}
	value, _, found := strings.Cut(rest, ";")
	if !found {
		return ""
	}
	return strings.Trim(value, " '")
}

// validVersion accepts what a WordPress version can contain and nothing else.
// The value reaches a URL query and a cache file name, so this is a boundary
// rather than a tidiness check.
func validVersion(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}

// validLocale accepts a WordPress locale such as `tr_TR`, `de_DE_formal` or
// `ja`. Empty is valid and means en_US.
func validLocale(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > 16 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		default:
			return false
		}
	}
	return true
}

// tag is the cache key and the cache file's base name. An empty locale and an
// explicit en_US are the same table, so they share one entry rather than
// fetching the same bytes twice under two names.
func tag(d Details) string {
	if d.Locale == "" || d.Locale == "en_US" {
		return d.Version
	}
	return d.Version + "-" + d.Locale
}

// Table returns the checksum table for an installation, from the cache when it
// is there and from wordpress.org otherwise.
//
// A successful fetch is written to the cache before it is returned, which is the
// whole point: the fallback is entered when the network is down, so a table
// fetched only at that moment would never arrive.
func Table(ctx context.Context, d Details) (map[string]string, error) {
	if !validVersion(d.Version) || !validLocale(d.Locale) {
		return nil, ErrNoTable
	}
	key := tag(d)
	if table := readCache(key); table != nil {
		return table, nil
	}
	if _, refused := negative.Load(key); refused {
		return nil, ErrUnknownVersion
	}
	table, err := fetch(ctx, d)
	if err != nil {
		// A transport failure is TEMPORARY and must not be remembered. Caching it
		// would leave that installation unchecked for the life of the process
		// because wordpress.org hiccupped once.
		return nil, err
	}
	if table == nil {
		// wordpress.org answered and does not publish this version and locale.
		// That is definite, so it is remembered, and it is a DIFFERENT fact from
		// being unable to ask.
		negative.Store(key, struct{}{})
		return nil, ErrUnknownVersion
	}
	writeCache(key, table)
	return table, nil
}

// Warm fills the cache for an installation and reports nothing.
//
// It is called on the path that is about to run wp-cli, while the network is by
// definition working, because that is the only moment the cache CAN be filled.
// Its failure is not the caller's problem: the check it protects has its own
// answer either way.
func Warm(ctx context.Context, d Details) {
	_, _ = Table(ctx, d)
}

// fetch asks wordpress.org. A nil table with a nil error means the endpoint
// answered but published nothing for this version and locale, which is a
// different thing from a network failure and is remembered as such.
func fetch(ctx context.Context, d Details) (map[string]string, error) {
	locale := d.Locale
	if locale == "" {
		locale = "en_US"
	}
	// The two values are validated above, so they cannot carry a separator; they
	// are still placed through url.Values rather than concatenated, because a
	// boundary that depends on an earlier check having run is not a boundary.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	query := req.URL.Query()
	query.Set("version", d.Version)
	query.Set("locale", locale)
	req.URL.RawQuery = query.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wordpress.org answered %d", resp.StatusCode)
	}
	// The field is taken raw because wordpress.org answers a version it never
	// published with HTTP 200 and the body {"checksums":false} (measured, not a
	// 404 and not an empty object). Decoding straight into a map turns that into
	// "cannot unmarshal bool into map[string]string", which is a decode error
	// and therefore indistinguishable from a truncated response or a proxy
	// serving something else. It has to be readable as an ANSWER, because it is
	// the only thing that separates a version this installation invented from a
	// wordpress.org nobody can reach.
	var wrapper struct {
		Checksums json.RawMessage `json:"checksums"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, tableCeiling)).Decode(&wrapper); err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(wrapper.Checksums))
	if trimmed == "" || trimmed == "false" || trimmed == "null" {
		return nil, nil
	}
	var table map[string]string
	if err := json.Unmarshal(wrapper.Checksums, &table); err != nil {
		return nil, err
	}
	if len(table) == 0 {
		return nil, nil
	}
	return table, nil
}

// cachePath is the file a table is kept in. The key is validated by construction
// (version and locale are both checked above), and the join is still confined to
// the cache directory, because the key travels through version.php.
func cachePath(key string) (string, bool) {
	root := filepath.Clean(config.WPChecksumDir())
	full := filepath.Clean(filepath.Join(root, key+".json"))
	if filepath.Dir(full) != root {
		return "", false
	}
	return full, true
}

func readCache(key string) map[string]string {
	full, ok := cachePath(key)
	if !ok {
		return nil
	}
	body, err := os.ReadFile(full) // #nosec G304 -- confined to the cache directory on the line above.
	if err != nil {
		return nil
	}
	var table map[string]string
	if json.Unmarshal(body, &table) != nil || len(table) == 0 {
		return nil
	}
	return table
}

// writeCache stores a table. It writes to a temporary name and renames, because
// a half-written file parses as nothing and would send every later check back to
// the network, which is the state this cache exists to survive.
func writeCache(key string, table map[string]string) {
	full, ok := cachePath(key)
	if !ok {
		return
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return
	}
	body, err := json.Marshal(table)
	if err != nil {
		return
	}
	temp, err := os.CreateTemp(filepath.Dir(full), ".table-*")
	if err != nil {
		return
	}
	name := temp.Name()
	if _, err := temp.Write(body); err != nil {
		_ = temp.Close()
		_ = os.Remove(name)
		return
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(name)
		return
	}
	if err := os.Chmod(name, 0o600); err != nil {
		_ = os.Remove(name)
		return
	}
	if err := os.Rename(name, full); err != nil {
		_ = os.Remove(name)
	}
}

// keepInTable reports whether a table entry is compared at all.
//
// wp-cli skips a `wp-content` prefix because those files are the site's own and
// change legitimately. The test is on the raw prefix rather than a path segment,
// exactly as the command does it, so a root-level file literally named
// `wp-contentious.php` would be skipped by both. Matching the command matters
// more here than being right in isolation, because a difference shows up as a
// finding on a healthy site.
func keepInTable(rel string) bool {
	return !strings.HasPrefix(rel, "wp-content")
}

// keepOnDisk is wp-cli's filter_file with include_root false: the two core
// directories, plus the root-level `wp-*` files except wp-config.php.
func keepOnDisk(rel string) bool {
	if strings.HasPrefix(rel, "wp-admin/") || strings.HasPrefix(rel, "wp-includes/") {
		return true
	}
	if strings.Contains(rel, "/") || !strings.HasPrefix(rel, "wp-") {
		return false
	}
	return rel != "wp-config.php"
}

// Verify compares an installation against a table.
//
// The verdicts come back in the command's order: the table pass first, then the
// disk pass, so a caller mapping them onto its own signatures reads one list.
func Verify(home, relDir string, table map[string]string) ([]Verdict, error) {
	if len(table) == 0 {
		return nil, ErrNoTable
	}
	var out []Verdict

	for rel, want := range table {
		if !keepInTable(rel) {
			continue
		}
		got, err := hashBeneath(home, path.Join(relDir, rel))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				out = append(out, Verdict{Message: MessageMissing, Rel: rel})
				continue
			}
			// Anything else (a symlink where a core file belongs, a directory, a
			// device node) is not the file the table names, and reporting it as
			// modified is the honest answer: it is certainly not verified.
			out = append(out, Verdict{Message: MessageModified, Rel: rel})
			continue
		}
		if got != want {
			out = append(out, Verdict{Message: MessageModified, Rel: rel})
		}
	}
	sortVerdicts(out)

	extra, err := extraFiles(home, relDir, table)
	if err != nil {
		return nil, err
	}
	out = append(out, extra...)
	return out, nil
}

// hashBeneath md5s one file beneath the home.
//
// The regular-file test is on the DESCRIPTOR rather than a separate stat of the
// path: this walks a directory a tenant writes to, and the two answers can
// differ between the stat and the open.
func hashBeneath(home, rel string) (string, error) {
	handle, err := files.OpenBeneath(home, rel)
	if err != nil {
		return "", err
	}
	defer func() { _ = handle.Close() }()
	info, err := handle.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	sum := md5.New() // #nosec G401 -- wordpress.org publishes md5; this compares against it.
	if _, err := io.Copy(sum, handle); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// extraFiles is the disk pass: every file the filter keeps that the table does
// not name.
func extraFiles(home, relDir string, table map[string]string) ([]Verdict, error) {
	var out []Verdict
	// The filter keeps only these three places, so the walk visits only them
	// rather than the whole document root. That is the same set filter_file
	// admits, and it keeps the walk off wp-content, which on a real site is
	// almost all of the files.
	for _, dir := range []string{"wp-admin", "wp-includes"} {
		found, err := walkBeneath(home, relDir, dir)
		if err != nil {
			return nil, err
		}
		for _, rel := range found {
			if _, known := table[rel]; !known {
				out = append(out, Verdict{Message: MessageExtra, Rel: rel})
			}
		}
	}
	names, err := files.ListNamesBeneath(home, relDir)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		if !keepOnDisk(name) {
			continue
		}
		info, err := files.StatBeneath(home, path.Join(relDir, name))
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if _, known := table[name]; !known {
			out = append(out, Verdict{Message: MessageExtra, Rel: name})
		}
	}
	sortVerdicts(out)
	return out, nil
}

// walkDepth bounds the descent. WordPress core is four levels deep at its
// deepest; the bound is here because the walk is driven by directory entries a
// tenant can create.
const walkDepth = 16

// walkBeneath lists every regular file under one core directory, relative to the
// installation.
//
// A symlinked directory is not descended and a symlinked file is not listed,
// because ListNamesBeneath and StatBeneath both resolve with RESOLVE_NO_SYMLINKS
// and refuse one. That is the deliberate difference from wp-cli described at the
// top of the file.
func walkBeneath(home, relDir, sub string) ([]string, error) {
	var out []string
	var descend func(rel string, depth int) error
	descend = func(rel string, depth int) error {
		if depth > walkDepth {
			return nil
		}
		names, err := files.ListNamesBeneath(home, path.Join(relDir, rel))
		if err != nil {
			return err
		}
		for _, name := range names {
			child := path.Join(rel, name)
			info, err := files.StatBeneath(home, path.Join(relDir, child))
			if err != nil {
				continue
			}
			switch {
			case info.IsDir():
				if err := descend(child, depth+1); err != nil {
					return err
				}
			case info.Mode().IsRegular():
				out = append(out, child)
			}
		}
		return nil
	}
	exists, err := files.IsDirBeneath(home, path.Join(relDir, sub))
	if err != nil || !exists {
		// A core directory that is not there is reported by the table pass as a
		// long list of missing files, which is the right report. Nothing is
		// added here.
		return nil, nil //nolint:nilerr // absence is the table pass's finding, not this one's.
	}
	if err := descend(sub, 0); err != nil {
		return nil, err
	}
	return out, nil
}

// sortVerdicts puts a list in a stable order. Map iteration is randomised in Go,
// so without this the same installation produces a different list on every run
// and every test asserting on one becomes flaky rather than wrong.
func sortVerdicts(list []Verdict) {
	if len(list) < 2 {
		return
	}
	// A plain insertion sort: these lists are findings on a broken site, so they
	// are short, and the comparison is on two fields.
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && less(list[j], list[j-1]); j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}

func less(a, b Verdict) bool {
	if a.Rel != b.Rel {
		return a.Rel < b.Rel
	}
	return a.Message < b.Message
}
