// Backup off-site destinations: FTP/SFTP and S3-compatible remote storage.
package backups

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"servika/internal/netguard"
	"servika/internal/secret"
)

// Destination describes a remote backup upload destination.
type Destination struct {
	ID        int64  `json:"id"`
	DomainID  int64  `json:"domain_id"`
	Type      string `json:"type"` // "ftp" | "sftp"
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password,omitempty"` // write-only: returns empty on GET
	RemoteDir string `json:"remote_dir"`
	// HostKey is the SFTP host key pinned on first use. It never leaves the
	// server: publishing it would let a caller confirm which host a destination
	// points at, and the operator has no use for it in the UI.
	HostKey    string `json:"-"`
	Bucket     string `json:"bucket,omitempty"`
	Region     string `json:"region,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	PathStyle  bool   `json:"path_style"`
	Enabled    bool   `json:"active"`
	LastUpload string `json:"last_upload,omitempty"`
	LastStatus string `json:"last_status,omitempty"`
	LastError  string `json:"last_error,omitempty"`

	// dialHost is the concrete address netguard approved, filled by
	// pinDialTarget for SFTP only. It is not persisted and not serialised: it is
	// valid for one operation, because a name may legitimately resolve elsewhere
	// tomorrow.
	dialHost string
}

func validType(t string) bool {
	return t == "ftp" || t == "sftp" || t == "s3" || t == "b2"
}

func objectStorageType(t string) bool { return t == "s3" || t == "b2" }

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// readDestination: returns a domain destination record (nil, nil if none).
func readDestination(ctx context.Context, db *sql.DB, domainID int64) (*Destination, error) {
	d := &Destination{DomainID: domainID}
	var enabled int
	var lastUpload sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT id, type, host, port, username, password, remote_dir, host_key,
		        bucket, region, endpoint, path_style, enabled,
		        DATE_FORMAT(last_upload,'%Y-%m-%d %H:%i'), last_status, last_error
		 FROM backup_destinations WHERE domain_id=?`, domainID).
		Scan(&d.ID, &d.Type, &d.Host, &d.Port, &d.Username, &d.Password, &d.RemoteDir, &d.HostKey,
			&d.Bucket, &d.Region, &d.Endpoint, &d.PathStyle, &enabled, &lastUpload,
			&d.LastStatus, &d.LastError)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	d.Enabled = enabled == 1
	if lastUpload.Valid {
		d.LastUpload = lastUpload.String
	}
	// Stored password is encrypted at rest; decrypt so runtime consumers
	// (upload, connection test) receive the usable plaintext. Legacy plaintext
	// rows pass through unchanged.
	pw, err := secret.Decrypt(d.Password)
	if err != nil {
		return nil, err
	}
	d.Password = pw
	return d, nil
}

// pinDialTarget vets the destination and, for SFTP, pins the address lftp will
// connect to.
//
// netguard.CheckHost resolves the name and hands the bare name onward, and lftp
// then resolves it a SECOND time. Between the two lookups a low-TTL record under
// the customer's control can answer with a public address for the check and an
// internal one for the connection, so the panel opens a connection to an address
// it never approved.
//
// Only SFTP is pinned. An FTP destination is reached with ssl-force plus
// verify-certificate, and a certificate names a host rather than an address, so
// dialing the IP would mean turning the hostname check off: that trades a blind
// TCP probe for a weaker transport, which is the worse of the two. SFTP has no
// such cost, because the pinned host key is verified under HostKeyAlias.
func pinDialTarget(d *Destination) error {
	if d.Type != "sftp" {
		if err := netguard.CheckHost(d.Host); err != nil {
			return fmt.Errorf("destination host not permitted: %w", err)
		}
		return nil
	}
	address, err := netguard.ResolveAllowed(d.Host)
	if err != nil {
		return fmt.Errorf("destination host not permitted: %w", err)
	}
	d.dialHost = address
	return nil
}

// dialTarget is the address a client should connect to: the pinned one when
// pinDialTarget supplied it, the configured host otherwise. It is BARE, which is
// the form ssh takes.
func dialTarget(d *Destination) string {
	if d.dialHost != "" {
		return d.dialHost
	}
	return d.Host
}

// urlHost renders an address for a URL authority. A bare IPv6 address has to be
// bracketed there, and a hostname or IPv4 address must not be.
func urlHost(address string) string {
	if strings.Contains(address, ":") {
		return "[" + address + "]"
	}
	return address
}

// lftpURL builds an lftp URL from the type, host, and port. It uses the pinned
// address when pinDialTarget supplied one, so the connection goes where netguard
// looked rather than wherever the name resolves a second time.
func lftpURL(d *Destination) string {
	host := urlHost(dialTarget(d))
	if d.Type == "sftp" {
		return fmt.Sprintf("sftp://%s:%d", host, d.Port)
	}
	return fmt.Sprintf("ftp://%s:%d", host, d.Port)
}

// uploadToRemote: uploads the local tar.gz to the remote destination.
// With lftp: connect, cd, put. Auto-confirm host key for SFTP.
func uploadToRemote(ctx context.Context, db *sql.DB, d *Destination, localPath, fileName string) error {
	if !d.Enabled {
		return nil // Skip disabled destinations.
	}
	if objectStorageType(d.Type) {
		return uploadS3Object(ctx, d, localPath, fileName)
	}
	if err := pinDialTarget(d); err != nil {
		return err
	}
	if err := credentialSafe(d.Password); err != nil {
		return err
	}
	hostKey, cleanupHostKey, err := lftpHostKeySettings(ctx, db, d)
	if err != nil {
		return err
	}
	defer cleanupHostKey()
	// The URL is double-quoted in every script below. validHost rejects a host
	// carrying lftp meta-characters on the way in, but rows saved before that check
	// existed are still read back from the database, so the quoting stands on its
	// own rather than depending on the validator.
	// with cmd:fail-exit, lftp exits non-zero if any command fails
	script := fmt.Sprintf(
		`set cmd:fail-exit yes; `+
			`%s`+
			`%s`+
			`set net:max-retries 1; `+
			`set net:timeout 15; `+
			`set net:reconnect-interval-base 2; `+
			`%s; `+
			`mkdir -p -f "%s"; `+
			`cd "%s"; `+
			`put -O . "%s"; `+
			`bye`,
		hostKey, lftpTransportSettings(d), lftpOpen(d),
		lftpEscape(d.RemoteDir), lftpEscape(d.RemoteDir), lftpEscape(localPath))

	out, err := lftpCommand(ctx, d, script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("lftp: %s: %w", strings.TrimSpace(string(out)), err)
	}
	// Treat known error text in otherwise successful output as a failure for defense in depth.
	bad := []string{"Login failed", "Access failed", "Connection refused", "Permission denied",
		"Could not resolve", "Host key verification failed", "No route to host"}
	for _, p := range bad {
		if strings.Contains(string(out), p) {
			return fmt.Errorf("lftp: %s", strings.TrimSpace(string(out)))
		}
	}
	_ = fileName
	return nil
}

// ensureLocalArchive makes sure a backup archive is present on local disk,
// fetching it from the domain's off-site destination when it is not.
//
// A local archive can be gone while the off-site copy is intact: manual
// retention prunes the newest-N on the root disk, and an operator can remove a
// local file by hand. Before this, every read path (restore, contents,
// download) answered "missing on disk" and the off-site copy was unreachable
// from the panel, so a backup the customer could see listed could not be used.
//
// The fetch happens ONLY when the row records a successful upload, so a backup
// that never went off-site still answers "missing" rather than reaching for a
// file that was never written.
func ensureLocalArchive(ctx context.Context, db *sql.DB, domainID, backupID int64, systemUser, file string) error {
	// Both components are read from the panel's own rows, but this function is
	// the one gate every read path (restore, contents, download) passes through,
	// so the check is made here rather than trusted from each caller.
	//
	// filepath.Base(file) != file rejects a separator and any deeper path, but it
	// does NOT reject the exact value ".." or ".", because Base returns those
	// unchanged. Either one resolves the join back to a directory rather than an
	// archive, so they are refused by name.
	if !validSystemUser(systemUser) || file == "" || filepath.Base(file) != file ||
		file == ".." || file == "." {
		return errors.New("invalid backup file")
	}
	abs := filepath.Join(backupRoot(), systemUser, file)
	// The recorded archive size, used to tell a complete local copy from a
	// truncated one. 0 means unknown (a legacy row), which skips the size check.
	expected := expectedBackupSize(ctx, db, backupID, domainID)
	// The digest is read here, once, and applied to whichever destination answers.
	digest := expectedBackupDigest(ctx, db, backupID, domainID)
	// #nosec G703 -- abs derives from backupRoot(), a validSystemUser-checked identifier and a base-name-validated file.
	if fi, err := os.Lstat(abs); err == nil && fi.Mode().IsRegular() {
		// Existing is not enough; it must be COMPLETE. A download killed mid-flight
		// (deploy, crash, OOM) can leave a half file under the final name, and a
		// restore would trust it and run against a truncated archive. A size
		// mismatch deletes the leftover and re-fetches.
		if expected <= 0 || fi.Size() == expected {
			return nil
		}
		// #nosec G706 -- logged values are integer IDs, a validated file name and sizes; no raw tenant string with CR/LF reaches the log.
		log.Printf("backup restore domain=%d: local copy of %s is incomplete (%d/%d bytes), refetching", domainID, file, fi.Size(), expected)
		// #nosec G703 -- abs derives from backupRoot(), a validSystemUser-checked identifier and a base-name-validated file.
		_ = os.Remove(abs)
	}
	dir := filepath.Join(backupRoot(), systemUser)
	// #nosec G703 -- dir derives from backupRoot() and a validSystemUser-checked identifier.
	_ = os.MkdirAll(dir, 0700)
	// First try the domain's OWN destination, when the row records a successful
	// per-domain upload.
	var remoteStatus string
	if err := db.QueryRowContext(ctx,
		`SELECT remote_status FROM backups WHERE id=? AND domain_id=?`, backupID, domainID).
		Scan(&remoteStatus); err == nil && remoteStatus == "successful" {
		if d, e := readDestination(ctx, db, domainID); e == nil && d != nil {
			if downloadFromRemote(ctx, db, d, file, abs) == nil {
				verifyErr := verifyFetched(abs, expected, digest)
				if verifyErr == nil {
					return nil
				}
				// #nosec G706 -- logged values are integer IDs, a validated file name and error text; no raw tenant string with CR/LF reaches the log.
				log.Printf("backup restore domain=%d: the copy of %s from the domain destination was refused: %v", domainID, file, verifyErr)
			}
		}
	}
	// Then the SYSTEM-WIDE destination, which is where a delete-local backup lives.
	s := readBackupSettings(ctx, db)
	if s.RemoteEnabled && strings.TrimSpace(s.RemoteHost) != "" {
		// A credential the panel cannot open is not a missing backup. Saying so
		// here rather than falling through matters most during a recovery, where
		// "backup file is missing on disk" sends the operator looking for an
		// archive that is intact at the destination.
		if err := s.usablePassword(); err != nil {
			return err
		}
		// Do not download onto a disk that is already low.
		if s.MinFreeGB > 0 {
			if free, e := diskFreeGB(backupRoot()); e == nil && free < float64(s.MinFreeGB) {
				return errors.New("the backup is off-site but there is not enough disk to fetch it")
			}
		}
		if err := fetchGlobalRemote(ctx, db, s, file, abs); err == nil {
			verifyErr := verifyFetched(abs, expected, digest)
			if verifyErr == nil {
				return nil
			}
			// #nosec G706 -- logged values are integer IDs, a validated file name and error text; no raw tenant string with CR/LF reaches the log.
			log.Printf("backup restore domain=%d: the off-site copy of %s was refused: %v", domainID, file, verifyErr)
		} else {
			// #nosec G706 -- logged values are integer IDs and error/command output; no raw tenant string with CR/LF reaches the log.
			log.Printf("backup restore domain=%d: off-site fetch failed: %v", domainID, err)
		}
	}
	return errors.New("backup file is missing on disk")
}

// expectedBackupSize returns the recorded archive size for a backup, or 0 when it
// is unknown (a legacy row with no size), which disables the size check.
func expectedBackupSize(ctx context.Context, db *sql.DB, backupID, domainID int64) int64 {
	var b int64
	_ = db.QueryRowContext(ctx, `SELECT size_b FROM backups WHERE id=? AND domain_id=?`, backupID, domainID).Scan(&b)
	return b
}

// expectedBackupDigest returns the recorded sha256 of an archive, or "" when the
// row carries none (written before the column existed), which disables the
// digest check.
func expectedBackupDigest(ctx context.Context, db *sql.DB, backupID, domainID int64) string {
	var digest string
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(sha256,'') FROM backups WHERE id=? AND domain_id=?`, backupID, domainID).Scan(&digest)
	return digest
}

// verifyFetched checks a freshly downloaded archive against everything the panel
// recorded about it: its size first, then its digest.
//
// Size alone answered only "did the transfer finish". It is a weak check on this
// path: the destination is a third-party host the customer or operator
// configured, an FTP destination runs plaintext and unauthenticated on the wire,
// and padding a substituted archive to the recorded byte count is trivial. What
// arrives is then extracted as root, rsynced into the tenant's home and imported
// as SQL, so this is exactly the moment to ask the stronger question the panel
// already holds the answer to.
//
// The digest is read on the FETCH path rather than only by the periodic
// integrity scan, because the fetch is when the bytes come from outside the
// server. A mismatch removes the file and refuses.
func verifyFetched(abs string, expected int64, digest string) error {
	if err := verifyDownloaded(abs, expected); err != nil {
		return err
	}
	if digest == "" {
		return nil
	}
	actual, err := fileSHA256(abs)
	if err != nil {
		// #nosec G703 -- abs derives from backupRoot(), a validSystemUser-checked identifier and a base-name-validated file.
		_ = os.Remove(abs)
		return fmt.Errorf("the fetched archive could not be hashed: %w", err)
	}
	if actual != digest {
		// #nosec G703 -- see above.
		_ = os.Remove(abs)
		return fmt.Errorf("the fetched archive does not match its recorded sha256")
	}
	return nil
}

// verifyDownloaded reports whether a freshly downloaded archive matches its
// recorded size. A transport can report success and still deliver a truncated
// file, so a size mismatch removes the file and returns an error, turning a
// silent partial download into a loud one. An unknown size (0) passes.
//
// It is the cheap FIRST gate; verifyFetched is what callers use, because a
// complete transfer of the wrong bytes passes this one.
func verifyDownloaded(abs string, expected int64) error {
	if expected <= 0 {
		return nil
	}
	// #nosec G703 -- abs derives from backupRoot(), a validSystemUser-checked identifier and a base-name-validated file.
	fi, err := os.Stat(abs)
	if err != nil {
		return err
	}
	if fi.Size() != expected {
		// #nosec G703 -- see above.
		_ = os.Remove(abs)
		return fmt.Errorf("downloaded archive is incomplete: %d/%d bytes", fi.Size(), expected)
	}
	return nil
}

// downloadFromRemote fetches a single backup file from the destination into
// localPath ATOMICALLY: it writes to a ".downloading" temp file and renames it
// into place only after the transfer completes. A killed process (deploy, crash,
// OOM) then leaves a ".downloading" orphan rather than a half file under the final
// name, which a later restore would trust and run against a truncated archive.
func downloadFromRemote(ctx context.Context, db *sql.DB, d *Destination, fileName, localPath string) error {
	tmp := localPath + ".downloading"
	// #nosec G703 -- localPath derives from backupRoot() and a validSystemUser-checked identifier; the suffix is a fixed constant.
	_ = os.Remove(tmp)
	if err := fetchRemoteInto(ctx, db, d, fileName, tmp); err != nil {
		// #nosec G703 -- see above; tmp is the same validated path with a fixed suffix.
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, localPath); err != nil {
		// #nosec G703 -- see above; tmp is the same validated path with a fixed suffix.
		_ = os.Remove(tmp)
		return fmt.Errorf("the downloaded file could not be moved into place: %w", err)
	}
	return nil
}

// fetchRemoteInto downloads a single backup file into target (S3 or lftp).
func fetchRemoteInto(ctx context.Context, db *sql.DB, d *Destination, fileName, target string) error {
	localPath := target
	if objectStorageType(d.Type) {
		return downloadS3Object(ctx, d, fileName, localPath)
	}
	if err := pinDialTarget(d); err != nil {
		return err
	}
	if err := credentialSafe(d.Password); err != nil {
		return err
	}
	hostKey, cleanupHostKey, err := lftpHostKeySettings(ctx, db, d)
	if err != nil {
		return err
	}
	defer cleanupHostKey()
	script := fmt.Sprintf(
		`set cmd:fail-exit yes; %s`+
			`%s`+
			`set net:max-retries 1; set net:timeout 15; `+
			`%s; cd "%s"; get "%s" -o "%s"; bye`,
		hostKey, lftpTransportSettings(d), lftpOpen(d),
		lftpEscape(d.RemoteDir), lftpEscape(fileName), lftpEscape(localPath))
	out, err := lftpCommand(ctx, d, script).CombinedOutput()
	if err != nil {
		_ = os.Remove(localPath)
		return fmt.Errorf("lftp: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// remoteSize returns the uploaded object's size in bytes, or -1 when it cannot
// be read. The caller compares it to the local file's size to catch an upload
// the transport reported complete but that arrived truncated. A -1 means "could
// not verify", never "size mismatch", so a transient read never flags a good
// upload.
func remoteSize(ctx context.Context, db *sql.DB, d *Destination, fileName string) int64 {
	if objectStorageType(d.Type) {
		return headS3Object(ctx, d, fileName)
	}
	if err := pinDialTarget(d); err != nil {
		return -1
	}
	if err := credentialSafe(d.Password); err != nil {
		return -1
	}
	hostKey, cleanupHostKey, err := lftpHostKeySettings(ctx, db, d)
	if err != nil {
		return -1
	}
	defer cleanupHostKey()
	// Use `cls -l "<file>"`, NEVER `ls "<file>"`: on an SFTP target such as a
	// Hetzner Storage Box, `ls` with a single file argument answers "Access failed:
	// Not a directory" and the size reads -1 forever, so the verification gate never
	// passes and delete-local never runs. `cls -l` gives one file's long listing
	// with the byte size (measured). parseRemoteSize reads the largest integer on
	// the line, which is the size in both layouts.
	script := fmt.Sprintf(
		`set cmd:fail-exit yes; %s`+
			`%s`+
			`set net:max-retries 1; set net:timeout 20; `+
			`%s; cd "%s"; cls -l "%s"; bye`,
		hostKey, lftpTransportSettings(d), lftpOpen(d),
		lftpEscape(d.RemoteDir), lftpEscape(fileName))
	out, err := lftpCommand(ctx, d, script).CombinedOutput()
	if err != nil {
		return -1
	}
	return parseRemoteSize(string(out), fileName)
}

// parseRemoteSize reads a byte count out of an lftp `ls` listing. It finds the
// line naming the file and returns the LARGEST positive integer field on it, so
// it does not depend on a fixed column layout across FTP and SFTP servers. The
// largest field, not the first: a long `ls -l` line begins with the hardlink
// count (1), and the size is always the dominant integer for a backup archive,
// which is kilobytes at the smallest. It returns -1 when no such field is found,
// which the caller reads as "could not verify" rather than a size mismatch.
func parseRemoteSize(output, fileName string) int64 {
	best := int64(-1)
	for line := range strings.SplitSeq(output, "\n") {
		if !strings.Contains(line, fileName) {
			continue
		}
		for field := range strings.FieldsSeq(line) {
			if n, err := strconv.ParseInt(field, 10, 64); err == nil && n > best {
				best = n
			}
		}
	}
	return best
}

// deleteFromRemote removes a single backup file from the destination.
//
//nolint:unused // reserved for the remote retention-prune path (not yet wired to a handler); kept alongside uploadToRemote so the destination round-trip stays complete.
func deleteFromRemote(ctx context.Context, db *sql.DB, d *Destination, fileName string) error {
	if objectStorageType(d.Type) {
		return deleteS3Object(ctx, d, fileName)
	}
	if err := pinDialTarget(d); err != nil {
		return err
	}
	if err := credentialSafe(d.Password); err != nil {
		return err
	}
	hostKey, cleanupHostKey, err := lftpHostKeySettings(ctx, db, d)
	if err != nil {
		return err
	}
	defer cleanupHostKey()
	script := fmt.Sprintf(
		`set cmd:fail-exit yes; %s`+
			`%s`+
			`set net:max-retries 1; set net:timeout 15; `+
			`%s; cd "%s"; rm "%s"; bye`,
		hostKey, lftpTransportSettings(d), lftpOpen(d),
		lftpEscape(d.RemoteDir), lftpEscape(fileName))
	out, err := lftpCommand(ctx, d, script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("lftp: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// lftpTransportSettings returns the transport security an lftp script needs for
// this destination.
//
// Every script used to DISABLE the AUTH TLS upgrade and certificate
// verification. lftp offers that upgrade by default, so turning it off sent the
// whole archive (document root, mail and the tenant's SQL dump) and the
// destination's username and password across the public internet in cleartext,
// on every scheduled upload, every restore fetch and every size check.
//
// ssl-force refuses the transfer rather than falling back to plaintext, because
// a destination that cannot do TLS is exactly the one this must not use.
// ssl-protect-data covers the DATA channel: without it the login is encrypted
// and the archive itself still travels in the clear. An operator whose server
// has no TLS, or a certificate that does not verify, is told by the connection
// test rather than backed up in the open.
//
// SFTP gets nothing: it runs over SSH, and its host key is pinned separately by
// lftpHostKeySettings.
func lftpTransportSettings(d *Destination) string {
	if d.Type != "ftp" {
		return ""
	}
	return `set ftp:ssl-allow yes; ` +
		`set ftp:ssl-force yes; ` +
		`set ftp:ssl-protect-data yes; ` +
		`set ssl:verify-certificate yes; `
}

// lftpHostKeySettings pins an SFTP destination to the host key recorded on its
// row and returns the cleanup for the temporary known_hosts file. lftp spawns
// ssh for sftp:// transfers, so the pin is installed through its connect
// program. An FTP destination has no host key and gets nothing.
//
// The previous setting was `sftp:auto-confirm yes`, which accepts whatever key
// answers, on every connection.
func lftpHostKeySettings(ctx context.Context, db *sql.DB, d *Destination) (string, func(), error) {
	if d.Type != "sftp" {
		return "", func() {}, nil
	}
	key, err := ensureHostKey(ctx, db, d)
	if err != nil {
		return "", func() {}, err
	}
	path, cleanup, err := knownHostsFile(key)
	if err != nil {
		return "", func() {}, err
	}
	// HostKeyAlias is what makes the pinned address and the pinned key agree. The
	// URL carries the vetted IP so lftp cannot resolve the name a second time,
	// and ssh-keyscan wrote the pin under the NAME, so without the alias ssh
	// would look the address up in known_hosts, find nothing, and refuse. ssh
	// applies the same [host]:port bracketing ssh-keyscan used, so the bare name
	// is the right value for both default and non-default ports.
	return `set sftp:auto-confirm no; ` +
		`set sftp:connect-program "ssh -a -x` +
		` -o HostKeyAlias=` + lftpEscape(d.Host) +
		` -o StrictHostKeyChecking=yes` +
		` -o UserKnownHostsFile=` + lftpEscape(path) +
		` -o GlobalKnownHostsFile=/dev/null"; `, cleanup, nil
}

// lftpOpen renders the lftp connect command. The password is NOT in it: it
// travels in LFTP_PASSWORD and `--env-password` reads it there. The older
// `open -u user,password` form put it in the `-c` argument, and therefore in
// argv, where every local account could read it.
func lftpOpen(d *Destination) string {
	return `open -u "` + lftpEscape(d.Username) + `" --env-password "` + lftpURL(d) + `"`
}

// lftpCommand runs an lftp script with the destination password in
// LFTP_PASSWORD, which the script's `open --env-password` reads. lftp's own
// manual gives the reason: "it is not secure to specify the password on command
// line". The `-c` argument is world-readable through /proc/<pid>/cmdline, and a
// tenant reaches that window with arbitrary shell from a cron entry, so a
// password embedded in `open -u user,pass` was readable by every local account.
// newRestoreCommand supplies the package's environment allowlist, so the panel's
// own secrets are not inherited alongside it.
func lftpCommand(ctx context.Context, d *Destination, script string) *exec.Cmd {
	command := newRestoreCommand(ctx, "lftp", "-c", script)
	command.Env = append(command.Env, "LFTP_PASSWORD="+d.Password)
	return command
}

// sshpassCommand runs sshpass with the destination password in SSHPASS, which
// its -e flag reads. Same reason as lftpCommand, and the same mechanism
// internal/transfers already uses: -p would place the password in argv.
func sshpassCommand(ctx context.Context, d *Destination, arguments ...string) *exec.Cmd {
	command := newRestoreCommand(ctx, "sshpass", arguments...)
	command.Env = append(command.Env, "SSHPASS="+d.Password)
	return command
}

// curlCredentialConfig renders the one config line curl reads from stdin under
// `--config -`, replacing `--user <user>:<password>` in argv. curl ends the
// value at the closing quote, so a double quote or backslash in either half has
// to be escaped or the credential is silently cut short.
func curlCredentialConfig(username, password string) string {
	quoted := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(username + ":" + password)
	return "user = \"" + quoted + "\"\n"
}

// credentialSafe rejects a stored password that cannot be delivered out of band.
// A line break ends a `curl --config` line and a NUL cannot go into an
// environment value, so either one would authenticate with a silently truncated
// secret. validDestinationInput rejects both on the way in, but rows written
// before that check existed are still read back from the database.
func credentialSafe(password string) error {
	if strings.ContainsAny(password, "\r\n\x00") {
		return errors.New("the stored destination password contains a line break or control character; save the destination again")
	}
	return nil
}

// lftpEscape: escapes values placed inside double quotes on the lftp command line.
func lftpEscape(s string) string {
	// Strip control characters (line-injection). The input layer rejects these
	// too, but sanitize here as defence in depth.
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// validHost returns true when h is a plausible hostname or IP address.
// It rejects values containing shell/lftp meta-characters that could enable
// command injection when the host is embedded in command-line arguments.
var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251})[a-zA-Z0-9]$|^[a-fA-F0-9:\.\[\]]+$`)

func validHost(h string) bool {
	if len(h) > 253 {
		return false
	}
	return hostPattern.MatchString(h)
}

// testConnection verifies the destination credentials.
// sshpass+ssh for SFTP, curl for FTP; both return an auth-specific exit code.
func testConnection(ctx context.Context, db *sql.DB, d *Destination) error {
	if objectStorageType(d.Type) {
		return testS3Connection(ctx, d)
	}
	if err := pinDialTarget(d); err != nil {
		return err
	}
	if err := credentialSafe(d.Password); err != nil {
		return err
	}
	if d.Type == "sftp" {
		// The connection test is the first thing that touches a new destination,
		// so it is where the host key gets pinned.
		key, err := ensureHostKey(ctx, db, d)
		if err != nil {
			return err
		}
		knownHosts, cleanup, err := knownHostsFile(key)
		if err != nil {
			return err
		}
		defer cleanup()
		// Force password authentication through sshpass and disable public-key fallback.
		// This ensures the supplied user password is actually valid.
		// Pass the user with -l and the host after --, so neither can be
		// interpreted as an ssh option (closes ProxyCommand-style arg injection
		// via a username or host beginning with "-").
		// -e reads the password from SSHPASS instead of argv, matching
		// internal/transfers; -p published it to every local account.
		args := []string{
			"-e",
			"ssh",
			"-p", fmt.Sprintf("%d", d.Port),
			"-l", d.Username,
			"-o", "ConnectTimeout=10",
			"-o", "PreferredAuthentications=password",
			"-o", "PubkeyAuthentication=no",
			"-o", "BatchMode=no",
		}
		args = append(args, sshHostKeyOptions(knownHosts, d.Host)...)
		// The vetted address, not the name: ssh would otherwise resolve the name
		// a THIRD time, after netguard and after ssh-keyscan, and the connection
		// test is the path a customer can drive at will.
		args = append(args, "--", dialTarget(d), "true")
		out, err := sshpassCommand(ctx, d, args...).CombinedOutput()
		if err != nil {
			short := strings.TrimSpace(string(out))
			if short == "" {
				short = err.Error()
			}
			return fmt.Errorf("%s", short)
		}
		return nil
	}
	// Use curl to list the FTP root with the supplied credentials. The credentials
	// arrive through `--config -` on stdin rather than `--user`, which put them in
	// argv where every local account could read them.
	url := fmt.Sprintf("ftp://%s:%d/", d.Host, d.Port)
	args := []string{
		"-sS",
		"--connect-timeout", "10",
		"--max-time", "15",
		"--config", "-",
		"--ftp-skip-pasv-ip",
		// The test must exercise the transport the uploads use, or it reports a
		// destination as working and every transfer to it then crosses the internet
		// in cleartext, or fails at 03:00 with nobody watching.
		"--ssl-reqd",
		url,
	}
	cmd := newRestoreCommand(ctx, "curl", args...)
	cmd.Stdin = strings.NewReader(curlCredentialConfig(d.Username, d.Password))
	out, err := cmd.CombinedOutput()
	if err != nil {
		short := strings.TrimSpace(string(out))
		if short == "" {
			short = err.Error()
		}
		return fmt.Errorf("%s", short)
	}
	return nil
}

// pushToDestinationAsync: triggers a background upload after the backup is created successfully.
// Does not block the API response even on error; last_status/last_error are written to the DB.
// removeRemoteCopy deletes a backup's copy from the domain's destination.
//
// Every path that removes a backup has to call it. Retention and the delete
// button removed the local archive and the row and left the remote object in
// place for good, so an S3 bucket or an SFTP directory grew without bound and a
// backup the customer had deleted still existed off the server.
//
// It runs on its OWN context, detached from the caller's: the local file and the
// row are already gone, and a destination that is briefly unreachable must not
// fail the deletion that was asked for. The failure is logged, never returned,
// for the same reason.
//
// remoteStatus gates the call. Only an upload that reported success wrote an
// object, so a failed or never-started upload sends no delete for something that
// was never there.
func removeRemoteCopy(db *sql.DB, domainID int64, fileName, remoteStatus string) {
	if remoteStatus != "successful" || fileName == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	d, err := readDestination(ctx, db, domainID)
	if err != nil || d == nil {
		if err != nil {
			// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
			log.Printf("backup remote delete domain=%d: destination unreadable: %v", domainID, err)
		}
		return
	}
	// A disabled destination still holds what was uploaded while it was on.
	if err := deleteFromRemote(ctx, db, d, fileName); err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("backup remote delete domain=%d file=%s: %v", domainID, fileName, err)
	}
}

// HealRemoteUploads closes any backup left at remote_status='uploading' by a
// panel restart.
//
// The upload runs in a detached goroutine with a 30-minute budget, and the only
// exits from 'uploading' are 'successful' and 'failed'. A restart inside that
// window leaves the row saying "uploading" for ever: nothing resets it, and no
// route re-triggers the push, so the backup screen shows a transfer that will
// never advance for an archive whose off-site copy never landed. This is the
// same correction HealJobsOnStartup makes for backup_jobs.
//
// The local archive is untouched and the next scheduled backup uploads its own
// new one; only the interrupted row's status is corrected.
func (h *Handlers) HealRemoteUploads() {
	res, err := h.DB.Exec(
		`UPDATE backups SET remote_status='failed',
		        remote_error='the panel restarted while this upload was running'
		  WHERE remote_status='uploading'`)
	if err != nil {
		log.Printf("backup destinations: startup heal failed: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("backup destinations: %d interrupted upload(s) marked as failed", n)
	}
}

func pushToDestinationAsync(db *sql.DB, domainID, backupID int64, localPath, fileName string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		d, err := readDestination(ctx, db, domainID)
		if err != nil || d == nil || !d.Enabled {
			return
		}
		_, _ = db.Exec(`UPDATE backups SET remote_status='uploading', remote_error='' WHERE id=?`, backupID)
		if err := uploadToRemote(ctx, db, d, localPath, fileName); err != nil {
			short := err.Error()
			if len(short) > 500 {
				short = short[:500]
			}
			_, _ = db.Exec(`UPDATE backup_destinations
				SET last_status='failed', last_error=?, last_upload=NOW() WHERE domain_id=?`,
				short, domainID)
			_, _ = db.Exec(`UPDATE backups SET remote_status='failed', remote_error=? WHERE id=?`,
				short, backupID)
			// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
			log.Printf("backup destination upload domain=%d: %v", domainID, err)
			notifyUploadFailed(ctx, db, domainID, backupID, short)
			return
		}
		// Verify the object arrived whole. lftp and S3 can report a transfer
		// complete while the stored object is short (a dropped connection, a full
		// remote disk). Only a POSITIVE mismatch is a failure: an unreadable
		// remote size returns -1 and is not treated as corruption, so a transient
		// read never flags a good upload.
		localSize := int64(-1)
		// #nosec G703 -- localPath is an internal backup archive path under BackupRoot derived from a validSystemUser-checked identifier.
		if fi, e := os.Stat(localPath); e == nil {
			localSize = fi.Size()
		}
		if rs := remoteSize(ctx, db, d, fileName); localSize > 0 && rs > 0 && rs != localSize {
			short := fmt.Sprintf("remote size mismatch (local=%d remote=%d): the upload was incomplete", localSize, rs)
			_, _ = db.Exec(`UPDATE backup_destinations
				SET last_status='failed', last_error=?, last_upload=NOW() WHERE domain_id=?`,
				short, domainID)
			_, _ = db.Exec(`UPDATE backups SET remote_status='failed', remote_error=? WHERE id=?`,
				short, backupID)
			// #nosec G706 -- logged values are integer IDs and a template-derived size message; no raw tenant string with CR/LF reaches the log.
			log.Printf("backup destination upload domain=%d: %s", domainID, short)
			notifyUploadFailed(ctx, db, domainID, backupID, short)
			return
		}
		_, _ = db.Exec(`UPDATE backup_destinations
			SET last_status='successful', last_error='', last_upload=NOW() WHERE domain_id=?`,
			domainID)
		remoteKey := strings.Trim(strings.TrimSpace(d.RemoteDir), "/")
		if remoteKey != "" {
			remoteKey += "/"
		}
		remoteKey += fileName
		_, _ = db.Exec(`UPDATE backups
			SET remote_status='successful', remote_key=?, remote_error='' WHERE id=?`,
			remoteKey, backupID)
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("backup destination upload domain=%d successful: %s", domainID, fileName)
	}()
}
