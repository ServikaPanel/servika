package appinstall

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"servika/internal/archivex"
	"servika/internal/credentials"
	"servika/internal/netguard"
)

const (
	// maxArchiveBytes bounds one download. The largest thing in the seeded
	// catalog is Nextcloud at around 200 MB, so this leaves room for a
	// catalogued application to grow without leaving room for a mistake in the
	// catalog to fill the disk.
	maxArchiveBytes = 512 << 20

	// downloadTimeout is one download's budget.
	downloadTimeout = 15 * time.Minute

	// extractTimeout is the unpacking budget, separate from the download so a
	// slow mirror does not eat the time the unpack needs.
	extractTimeout = 10 * time.Minute

	// maxMembers and maxExpandedBytes bound the unpacked archive. A CMS is tens
	// of thousands of files; past these the archive is not one.
	maxMembers        = 200000
	maxExpandedBytes  = 2 << 30
	stagingNamePrefix = ".servika-install-"
)

// Request is one installation.
type Request struct {
	DomainID     int64
	DomainName   string
	SystemUser   string
	WebRoot      string
	SSL          bool
	Code         string
	Subdirectory string
	// DBSuffix names the database when the application needs one. The panel
	// prepends the tenant's own prefix, so this is the customer's half only.
	DBSuffix string
}

// newClient builds the download client.
//
// The URL comes from the catalog, which an administrator can edit, so the
// target is not a fixed constant. netguard.DialControl runs AFTER resolution
// with the concrete address, which is what stops a catalog entry, or a resolver
// answering one, from turning an installation into a request against the
// panel's own network.
func newClient() *http.Client {
	return &http.Client{
		Timeout: downloadTimeout,
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second, Control: netguard.DialControl}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			Proxy:               http.ProxyFromEnvironment,
		},
	}
}

// download fetches the archive and verifies the pin.
//
// The digest is computed WHILE the bytes are written, so the archive is never
// read twice and a mismatch is known before anything is unpacked. A file that
// fails the check is removed rather than left behind: the next run must not
// find it and the operator must not be able to point anything at it.
func download(ctx context.Context, client *http.Client, entry Entry, into string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, entry.DownloadURL, nil)
	if err != nil {
		return refuse(ReasonDownload, err)
	}
	response, err := client.Do(request)
	if err != nil {
		return refuse(ReasonDownload, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return refuse(ReasonDownload, fmt.Errorf("the download answered %s", response.Status))
	}

	// #nosec G304 G703 -- into is composed by the caller from os.MkdirTemp and a validated archive name (validArchiveName rejects separators and dot segments).
	file, err := os.OpenFile(into, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return refuse(ReasonDownload, err)
	}
	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, digest), io.LimitReader(response.Body, maxArchiveBytes+1))
	closeErr := file.Close()
	switch {
	case copyErr != nil:
		_ = os.Remove(into)
		return refuse(ReasonDownload, copyErr)
	case closeErr != nil:
		_ = os.Remove(into)
		return refuse(ReasonDownload, closeErr)
	case written > maxArchiveBytes:
		_ = os.Remove(into)
		return refuse(ReasonDownload, fmt.Errorf("the archive is over %d bytes", int64(maxArchiveBytes)))
	}

	if got := hex.EncodeToString(digest.Sum(nil)); got != entry.SHA256 {
		_ = os.Remove(into)
		return refuse(ReasonChecksum, fmt.Errorf("the archive hashes to %s, not %s", got, entry.SHA256))
	}
	return nil
}

// targetIsEmpty reports whether the installation target can be written into.
//
// An existing installation is REFUSED rather than unpacked over. Unpacking a
// second application on top of a first leaves a directory that is neither, and
// the files that survive are whichever the second archive did not happen to
// name.
func targetIsEmpty(path string) (bool, error) {
	// #nosec G703 -- path is composed from a validated system user and a validated single-segment subdirectory.
	entries, err := os.ReadDir(path)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), stagingNamePrefix) {
			return false, nil
		}
	}
	return true, nil
}

// tenantCommand runs one command as the tenant.
//
// Every filesystem step after the download runs as the owning user, not as
// root: the extraction already does, and a move performed as root would leave
// root-owned files in a tenant tree that the tenant then cannot update.
func tenantCommand(ctx context.Context, systemUser string, arguments ...string) *exec.Cmd {
	full := append([]string{"-u", systemUser, "--"}, arguments...)
	// #nosec G204 G702 -- fixed binary with separate arguments (no shell); systemUser is validated and every path is composed by this package.
	return exec.CommandContext(ctx, "runuser", full...)
}

// unpack extracts the archive into a staging directory and moves the result
// into place.
//
// It does NOT use archivex.ExtractStrip. That function implements strip for zip
// through bsdtar and refuses when bsdtar is absent, which AlmaLinux 10 does not
// install by default, and three of the seven seeded applications are zips that
// need a strip. Staging works for every format with the tools that are always
// there, and the staging directory sits INSIDE the target so the move is a
// rename on one filesystem rather than a copy of a whole CMS.
func unpack(ctx context.Context, entry Entry, archivePath, target, systemUser string) error {
	limits := archivex.Limits{MaxTotalBytes: maxExpandedBytes, MaxMembers: maxMembers}
	staging := filepath.Join(target, stagingNamePrefix+strconv.FormatInt(time.Now().UnixNano(), 36))

	if err := tenantCommand(ctx, systemUser, "mkdir", "-p", staging).Run(); err != nil {
		return refuse(ReasonExtract, fmt.Errorf("staging directory: %w", err))
	}
	defer func() {
		// Best effort: the installation has either succeeded or already failed,
		// and a leftover staging directory is visible under its own name.
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = tenantCommand(cleanup, systemUser, "rm", "-rf", staging).Run()
	}()

	if _, err := archivex.Extract(ctx, archivePath, staging, systemUser, limits); err != nil {
		return refuse(ReasonExtract, err)
	}

	source := staging
	for range entry.StripComponents {
		// #nosec G703 -- source is the staging directory this function created inside a validated target.
		entries, err := os.ReadDir(source)
		if err != nil {
			return refuse(ReasonExtract, err)
		}
		// A strip is only meaningful when the level really is one wrapper. If
		// the archive changed shape, stripping anyway would move an arbitrary
		// subdirectory into the document root and silently discard the rest.
		if len(entries) != 1 || !entries[0].IsDir() {
			return refuse(ReasonExtract,
				fmt.Errorf("the archive does not wrap its contents in one directory, so strip_components=%d is wrong for it",
					entry.StripComponents))
		}
		source = filepath.Join(source, entries[0].Name())
	}

	// The move is one shell-free command per entry name, run as the tenant.
	// #nosec G703 -- source is under the staging directory this function created.
	moved, err := os.ReadDir(source)
	if err != nil {
		return refuse(ReasonExtract, err)
	}
	for _, entry := range moved {
		arguments := []string{"mv", "-n", filepath.Join(source, entry.Name()), target + string(os.PathSeparator)}
		if output, err := tenantCommand(ctx, systemUser, arguments...).CombinedOutput(); err != nil {
			return refuse(ReasonExtract, fmt.Errorf("moving %s: %s", entry.Name(), strings.TrimSpace(string(output))))
		}
	}
	return nil
}

// databaseFree reports whether a database name is unused.
//
// This is asked EXPLICITLY because credentials.MySQLCreateDBForUser issues
// CREATE DATABASE IF NOT EXISTS, which succeeds silently against an existing
// schema. The installation would then be pointed at somebody's live data and
// the application's own wizard would offer to overwrite it.
func databaseFree(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var found string
	err := db.QueryRowContext(ctx,
		`SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?`, name).Scan(&found)
	if err == sql.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

// Result is what an installation produced.
type Result struct {
	Install
	// NextStep is where the customer finishes. The panel places the files and
	// prepares the database; the application's own web wizard makes the
	// administrator account, so no password of theirs ever reaches an argument
	// list, a log or /proc/<pid>/cmdline.
	NextStep string `json:"next_step"`
}

// siteURLFor composes where the installation will answer.
func siteURLFor(request Request) string {
	scheme := "http://"
	if request.SSL {
		scheme = "https://"
	}
	url := scheme + request.DomainName
	if request.Subdirectory != "" {
		url += "/" + request.Subdirectory
	}
	return url
}

// Begin validates the request and CLAIMS the target, returning the row id.
//
// It is separate from Run because the work takes longer than the panel's
// request timeout: the handler calls this one synchronously, so a refusal is
// answered as a refusal, and then runs the rest detached.
//
// The claim is the INSERT itself. UNIQUE (domain_id, subdirectory) is what stops
// two installations into one target, rather than a check followed by an insert,
// which two concurrent requests can both pass.
func Begin(ctx context.Context, db *sql.DB, request Request) (int64, Entry, error) {
	entry, err := LookupEntry(ctx, db, request.Code)
	if err != nil {
		return 0, Entry{}, err
	}
	if !ValidSubdirectory(request.Subdirectory) {
		return 0, Entry{}, refuse(ReasonBadSubdirectory, nil)
	}

	empty, err := targetIsEmpty(targetOf(request))
	if err != nil {
		return 0, Entry{}, err
	}
	if !empty {
		return 0, Entry{}, refuse(ReasonTargetNotEmpty, nil)
	}

	dbName, dbUser, err := databaseNames(ctx, db, entry, request)
	if err != nil {
		return 0, Entry{}, err
	}

	result, err := db.ExecContext(ctx,
		`INSERT INTO app_installs
		   (domain_id, code, name, version, subdirectory, site_url, db_name, db_user, state)
		 VALUES (?,?,?,?,?,?,?,?, 'installing')`,
		request.DomainID, entry.Code, entry.Name, entry.Version,
		request.Subdirectory, siteURLFor(request), dbName, dbUser)
	if err != nil {
		// The unique key answering here is not a fault: it means somebody is
		// already installing into this target, which is exactly what it is for.
		if strings.Contains(err.Error(), "uq_app_installs_target") {
			return 0, Entry{}, refuse(ReasonTargetNotEmpty, nil)
		}
		return 0, Entry{}, err
	}
	id, err := result.LastInsertId()
	return id, entry, err
}

// targetOf resolves the absolute directory an installation lands in.
func targetOf(request Request) string {
	if request.Subdirectory == "" {
		return request.WebRoot
	}
	return filepath.Join(request.WebRoot, request.Subdirectory)
}

// databaseNames decides the schema and account an installation will use, and
// refuses a name that is taken.
//
// The free check is asked EXPLICITLY because credentials.MySQLCreateDBForUser
// issues CREATE DATABASE IF NOT EXISTS, which succeeds silently against an
// existing schema. The installation would then be pointed at somebody's live
// data and the application's own wizard would offer to overwrite it.
func databaseNames(ctx context.Context, db *sql.DB, entry Entry, request Request) (string, string, error) {
	if !entry.NeedsDatabase {
		return "", "", nil
	}
	suffix := strings.TrimSpace(request.DBSuffix)
	if suffix == "" {
		suffix = entry.Code
	}
	if !credentials.ValidDBSuffix(suffix) {
		return "", "", refuse(ReasonDatabaseExists, fmt.Errorf("database suffix is not usable"))
	}
	dbName := request.SystemUser + "_" + suffix
	dbUser := request.SystemUser + "_db"
	if !credentials.ValidCustomerDBIdentifier(request.SystemUser, dbName) {
		return "", "", refuse(ReasonDatabaseExists, fmt.Errorf("database name is not usable"))
	}
	free, err := databaseFree(ctx, db, dbName)
	if err != nil {
		return "", "", err
	}
	if !free {
		return "", "", refuse(ReasonDatabaseExists, nil)
	}
	return dbName, dbUser, nil
}

// Run performs the work Begin claimed.
//
// The order matters. The archive is fetched and VERIFIED before anything on the
// host is touched, so a mismatched pin costs nothing but a download. The
// database is created before the files, because a failed database leaves an
// empty schema that is trivial to drop while a failure after the files leaves a
// half-written document root.
func Run(ctx context.Context, db *sql.DB, entry Entry, request Request) error {
	// os.MkdirTemp with an empty directory argument honours the TMPDIR the
	// panel pins to persistent disk at startup, so a 200 MB archive does not
	// land in the tmpfs AlmaLinux 10 mounts on /tmp.
	scratch, err := os.MkdirTemp("", "servika-appinstall-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(scratch) }()

	archivePath := filepath.Join(scratch, entry.ArchiveName)
	if err := download(ctx, newClient(), entry, archivePath); err != nil {
		return err
	}

	dbName, dbUser, err := databaseNames(ctx, db, entry, request)
	if err != nil {
		return err
	}
	if entry.NeedsDatabase {
		if err := credentials.MySQLCreateDBForUser(db, request.DomainID, dbName, dbUser); err != nil {
			return err
		}
	}

	target := targetOf(request)
	if err := tenantCommand(ctx, request.SystemUser, "mkdir", "-p", target).Run(); err != nil {
		return refuse(ReasonExtract, err)
	}
	extractCtx, cancel := context.WithTimeout(ctx, extractTimeout)
	defer cancel()
	return unpack(extractCtx, entry, archivePath, target, request.SystemUser)
}

// Finish records the outcome of one installation.
//
// It takes its OWN context: the work's budget may already have expired, and the
// row must still stop saying "installing". A failed installation KEEPS its row,
// because deleting it would leave a half-unpacked document root with nothing in
// the panel saying why.
func Finish(db *sql.DB, id int64, runErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	state, message := "installed", ""
	if runErr != nil {
		state = "failed"
		// The reason CODE goes first, because the screen matches on it and
		// renders the sentence in twelve languages. The detail follows it for
		// an operator reading the row directly.
		message = runErr.Error()
		if code := ReasonOf(runErr); code != "" && !strings.HasPrefix(message, code) {
			message = code + ": " + message
		}
		if len(message) > 512 {
			message = message[:512]
		}
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE app_installs SET state=?, last_error=?, finished_at=NOW() WHERE id=?`,
		state, message, id); err != nil {
		log.Printf("app install %d: could not record the outcome: %v", id, err)
	}
}
