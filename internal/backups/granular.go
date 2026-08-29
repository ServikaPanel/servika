package backups

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"servika/internal/archivex"
	"servika/internal/credentials"
	"servika/internal/files"
	"servika/internal/httpx"
	"servika/internal/sqlimport"

	"github.com/go-chi/chi/v5"
)

// shellQuote single-quotes a value for a bash -c command line (mysql/mysqldump
// file paths and DB names). All embedded single quotes are escaped.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// isSystemDB reports databases that must never be dumped or overwritten.
func isSystemDB(n string) bool {
	switch strings.ToLower(strings.TrimSpace(n)) {
	case "mysql", "information_schema", "performance_schema", "sys", "panel":
		return true
	}
	return false
}

// domainDatabases returns every database name owned by a domain (the primary
// <system_user>_main plus db_accounts rows). Only valid, non-system identifiers
// pass, so this doubles as the restore whitelist.
func domainDatabases(db *sql.DB, domainID int64, systemUser string) []string {
	set := map[string]bool{}
	out := []string{}
	add := func(n string) {
		n = strings.TrimSpace(n)
		if n != "" && credentials.ValidDBIdentifier(n) && !isSystemDB(n) && !set[n] {
			set[n] = true
			out = append(out, n)
		}
	}
	add(systemUser + "_main")
	if rows, err := db.Query(`SELECT db_name FROM db_accounts WHERE domain_id=?`, domainID); err == nil {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				add(n)
			}
		}
	}
	return out
}

// tenantPrimaryDBUser returns the domain's main DB user, for granting a
// newly-created restore-target database.
func tenantPrimaryDBUser(db *sql.DB, domainID int64, systemUser string) string {
	var u string
	_ = db.QueryRow(`SELECT db_user FROM db_accounts WHERE domain_id=? AND db_name=? LIMIT 1`,
		domainID, systemUser+"_main").Scan(&u)
	if u == "" {
		_ = db.QueryRow(`SELECT db_user FROM db_accounts WHERE domain_id=? LIMIT 1`, domainID).Scan(&u)
	}
	if u == "" {
		u = systemUser + "_db"
	}
	return u
}

// archiveManifest is the __db__/manifest.json payload (informational + DB list).
type archiveManifest struct {
	CreatedAt string   `json:"created_at"`
	Home      string   `json:"home"`
	MainDB    string   `json:"main_db"`
	Databases []string `json:"databases"`
	// FailedDatabases lists databases the panel owns whose dump errored or came
	// out truncated, so a restore knows the archive is missing them rather than
	// treating their absence as "the site had no such database".
	FailedDatabases []string `json:"failed_databases,omitempty"`
}

// dumpCompleteMark is the comment mysqldump writes as the last line of a
// successful dump. Its absence means the dump was cut short.
const dumpCompleteMark = "Dump completed"

// dumpComplete reports whether a dump file ends with mysqldump's completion
// marker. It reads only the tail, because a dump can be gigabytes.
func dumpComplete(path string) bool {
	// #nosec G304 G703 -- path is an internal staging file under BackupRoot derived from a validated systemUser and DB name.
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	const tail = 512
	off := int64(0)
	if fi.Size() > tail {
		off = fi.Size() - tail
	}
	buf := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	return strings.Contains(string(buf), dumpCompleteMark)
}

// buildArchive packages /home/<systemUser> plus every domain DB (__db__/<name>.sql)
// plus a manifest into a single .tar.gz. Used by both the manual Create handler
// and the scheduler. Older backups dumped only <systemUser>_main; extra DBs such
// as wp_* are now included. Returns the archive size in bytes.
func buildArchive(ctx context.Context, db *sql.DB, domainID int64, systemUser, dir, file, createdTS string) (int64, error) {
	abs := filepath.Join(dir, file)
	dbDir := filepath.Join(dir, "__db__")
	// #nosec G703 -- staging paths derive from backupRoot()/<validSystemUser-checked systemUser> and ValidDBIdentifier-checked DB names; no raw tenant path input.
	_ = os.RemoveAll(dbDir)
	// #nosec G703 -- staging paths derive from backupRoot()/<validSystemUser-checked systemUser> and ValidDBIdentifier-checked DB names; no raw tenant path input.
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		return 0, fmt.Errorf("db staging: %w", err)
	}
	// #nosec G703 -- staging paths derive from backupRoot()/<validSystemUser-checked systemUser> and ValidDBIdentifier-checked DB names; no raw tenant path input.
	defer func() { _ = os.RemoveAll(dbDir) }()

	// Progress stages are no-ops when no record exists (the scheduler path), so the
	// same buildArchive serves both the interactive and scheduled backups.
	progressStage(domainID, stageDumpingDBs, 0)
	written := []string{}
	failedDBs := []string{}
	for _, dbName := range domainDatabases(db, domainID, systemUser) {
		target := filepath.Join(dbDir, dbName+".sql")
		// --routines --events --triggers keep stored procedures, scheduled events
		// and triggers, which restore would otherwise lose silently; --hex-blob
		// and --default-character-set=utf8mb4 keep binary and multibyte data
		// intact. This matches the site-migration and system-backup dumps.
		// #nosec G204 G702 -- dbName is a credentials.ValidDBIdentifier-checked, non-system name and target is an internal staging path, both shell-quoted; no tenant shell input.
		cmd := newRestoreCommand(ctx, "bash", "-c",
			fmt.Sprintf("mysqldump --single-transaction --skip-lock-tables --routines --events --triggers --default-character-set=utf8mb4 --hex-blob %s > %s 2>/dev/null",
				shellQuote(dbName), shellQuote(target)))
		if err := cmd.Run(); err != nil {
			// The database comes from the panel's own records, so a dump error is a
			// real or transient failure, never "no such database". Record it so the
			// gap is not silently dropped from the manifest.
			// #nosec G703 -- staging paths derive from backupRoot()/<validSystemUser-checked systemUser> and ValidDBIdentifier-checked DB names; no raw tenant path input.
			_ = os.Remove(target)
			failedDBs = append(failedDBs, dbName)
			continue
		}
		// A dump that produced bytes can still be truncated (the client was killed,
		// the disk filled). mysqldump writes its completion marker as the last line,
		// so its absence means the dump is incomplete and must not be trusted.
		// #nosec G703 -- staging paths derive from backupRoot()/<validSystemUser-checked systemUser> and ValidDBIdentifier-checked DB names; no raw tenant path input.
		if fi, e := os.Stat(target); e != nil || fi.Size() == 0 || !dumpComplete(target) {
			// #nosec G703 -- staging paths derive from backupRoot()/<validSystemUser-checked systemUser> and ValidDBIdentifier-checked DB names; no raw tenant path input.
			_ = os.Remove(target)
			failedDBs = append(failedDBs, dbName)
			continue
		}
		written = append(written, dbName)
	}

	// Capture the owning MySQL accounts (with their password hash) and grants.
	// mysqldump does not, because they live in the server's `mysql` schema, so
	// without this line a restore brought the tables back but not the account the
	// site connects as, and the site kept returning 500.
	if n := writeDBUsers(ctx, dbDir, written); n > 0 {
		// #nosec G706 -- logged values are an integer count and a validated systemUser identifier.
		log.Printf("backup %s: %d database user(s) added to the archive", systemUser, n)
	}

	man := archiveManifest{CreatedAt: createdTS, Home: systemUser, MainDB: systemUser + "_main", Databases: written, FailedDatabases: failedDBs}
	if b, err := json.MarshalIndent(man, "", "  "); err == nil {
		// #nosec G306 G703 -- root-owned backup staging file under BackupRoot (0700), path derived from a validated systemUser; carries no secret.
		_ = os.WriteFile(filepath.Join(dbDir, "manifest.json"), b, 0600)
	}

	// Sample the archive file's growth so the customer sees the archiving stage
	// move; the estimate uses the previous backup's size.
	progressStage(domainID, stageArchiving, previousBackupSize(db, domainID))
	progressWatchFile(domainID, abs)
	args := []string{"czf", abs, "-C", "/home", systemUser, "-C", dir, "__db__"}
	// #nosec G204 G702 -- fixed binary (tar) with separate args (no shell); systemUser is validSystemUser-checked and paths are internal.
	if out, err := newRestoreCommand(ctx, "tar", args...).CombinedOutput(); err != nil {
		// tar exit 1 is "file changed as we read it": a live session or cache
		// directory (Laravel sessions, WordPress cache) was written while tar
		// read it. The archive is still COMPLETE and restorable, so discarding it
		// would leave the site with NO backup at all. Keep it and warn. Only a
		// real failure (exit >= 2) discards the archive.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && tarArchiveUsable(exitErr.ExitCode()) {
			// #nosec G706 -- the operand is tar's own output, not client-controlled input.
			log.Printf("backup: tar reported a file changed during read for %s (exit 1); archive kept: %s",
				systemUser, strings.TrimSpace(string(out)))
		} else {
			// #nosec G703 -- staging paths derive from backupRoot()/<validSystemUser-checked systemUser> and ValidDBIdentifier-checked DB names; no raw tenant path input.
			_ = os.Remove(abs)
			return 0, fmt.Errorf("tar: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}
	progressStopFile(domainID)
	var size int64
	// #nosec G703 -- staging paths derive from backupRoot()/<validSystemUser-checked systemUser> and ValidDBIdentifier-checked DB names; no raw tenant path input.
	if st, _ := os.Stat(abs); st != nil {
		size = st.Size()
	}
	return size, nil
}

// tarArchiveUsable reports whether a tar exit code leaves a COMPLETE archive.
// Exit 1 is "file changed as we read it": one file moved mid-read, but every
// member tar decided to include is written, so the archive still restores. Exit
// 2 and above is a real failure whose archive must not be trusted.
func tarArchiveUsable(exitCode int) bool { return exitCode == 1 }

// safeMemberPath validates an archive-relative path (rejects absolute / jail escape).
func safeMemberPath(p string) (string, bool) {
	p = strings.TrimPrefix(strings.TrimSpace(p), "./")
	if p == "" || strings.HasPrefix(p, "/") {
		return "", false
	}
	c := filepath.Clean(p)
	if c == ".." || strings.HasPrefix(c, "../") || strings.Contains(c, "/../") || strings.HasPrefix(c, "/") {
		return "", false
	}
	return c, true
}

// archiveDBFiles maps DB name -> extracted .sql path inside tmp.
// New format: tmp/__db__/<name>.sql. Legacy: tmp/<any>.sql -> <systemUser>_main.
func archiveDBFiles(tmp, systemUser string) map[string]string {
	out := map[string]string{}
	dbDir := filepath.Join(tmp, "__db__")
	if fi, err := os.Stat(dbDir); err == nil && fi.IsDir() {
		ents, _ := os.ReadDir(dbDir)
		for _, e := range ents {
			// users.sql is the account/GRANT dump, not a database dump; treating it
			// as one would try to create a database named "users" and break restore.
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") || e.Name() == dbUsersFileName {
				continue
			}
			out[strings.TrimSuffix(e.Name(), ".sql")] = filepath.Join(dbDir, e.Name())
		}
		if len(out) > 0 {
			return out
		}
	}
	ents, _ := os.ReadDir(tmp)
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		out[systemUser+"_main"] = filepath.Join(tmp, e.Name())
		break
	}
	return out
}

// importDB imports a .sql file into a (whitelisted) database.
//
// It goes through internal/sqlimport rather than the panel's own root MariaDB
// connection. Naming the database on a root `mysql <db>` only sets a DEFAULT
// schema and is not a privilege boundary, so every statement in the file would
// run with full server rights. The whitelist above decides WHICH database the
// panel intends to write; it says nothing about where the file's own statements
// go. sqlimport imports as an account granted on that schema alone, so MariaDB
// enforces the intent.
func importDB(ctx context.Context, dbName, sqlPath string) error {
	// Create the target schema first. sqlimport connects with dbName as the default
	// schema and its dump has the CREATE DATABASE / USE lines stripped, so a database
	// that was deleted (exactly when a restore is most needed) would fail with
	// "Unknown database". The name is a validated, non-system identifier.
	if err := ensureSchema(ctx, dbName); err != nil {
		return err
	}
	// #nosec G304 G703 -- sqlPath is a server-internal staging path under the panel temp dir, produced by extracting the archive; no tenant path input.
	dump, err := os.Open(sqlPath)
	if err != nil {
		return err
	}
	defer func() { _ = dump.Close() }()
	return sqlimport.Import(ctx, dbName, dump)
}

// ensureSchema creates the target database when it does not exist, so a restore
// can rebuild a database that was dropped. The name is validated before it is
// interpolated, and system schemas are refused.
func ensureSchema(ctx context.Context, dbName string) error {
	if !credentials.ValidDBIdentifier(dbName) || isSystemDB(dbName) {
		return fmt.Errorf("invalid database name: %q", dbName)
	}
	return mysqlExec(ctx,
		"CREATE DATABASE IF NOT EXISTS `"+dbName+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
}

// restoreAllDBs imports every domain-owned DB present in the archive (mode full/database).
// When filter != "", only that DB. Non-owned / system DBs are skipped.
func restoreAllDBs(ctx context.Context, db *sql.DB, domainID int64, tmp, systemUser, filter string) []map[string]string {
	files := archiveDBFiles(tmp, systemUser)
	owned := map[string]bool{}
	for _, n := range domainDatabases(db, domainID, systemUser) {
		owned[n] = true
	}
	res := []map[string]string{}
	restored := []string{}
	for name, p := range files {
		if filter != "" && name != filter {
			continue
		}
		if isSystemDB(name) {
			res = append(res, map[string]string{"db": name, "status": "rejected (system database)"})
			continue
		}
		reRegister := false
		if !owned[name] {
			// Recovery path: a database whose panel record was deleted can still be
			// restored. Deleting a database from the panel removes its db_accounts
			// row, which empties the whitelist and made restoring your own database
			// from your own backup impossible (the job reported success with zero
			// databases restored). This archive IS this domain's backup, so a
			// database in it belongs to this domain by definition. The only real
			// risk is the name being registered to ANOTHER domain, which is refused.
			if otherDomainOwns(db, name, domainID) {
				res = append(res, map[string]string{"db": name, "status": "rejected (registered to another domain)"})
				continue
			}
			reRegister = true
		}
		if err := importDB(ctx, name, p); err != nil {
			res = append(res, map[string]string{"db": name, "status": "error: " + err.Error()})
			continue
		}
		status := "restored"
		if reRegister {
			// Re-register in the panel, or this database is never backed up again
			// (domainDatabases reads db_accounts plus <systemUser>_main). db_user and
			// db_pass_plain are NOT NULL with no default, so empty strings are given:
			// the account is recreated from users.sql, or the operator sets it under
			// Databases.
			if _, e := db.Exec(
				`INSERT INTO db_accounts (domain_id, db_name, db_user, db_pass_plain, db_host) VALUES (?,?,'','','localhost')`,
				domainID, name); e == nil {
				status = "restored (panel record recreated — set a database user)"
			} else {
				status = "restored (not registered in the panel — add it under Databases)"
			}
		}
		res = append(res, map[string]string{"db": name, "status": status})
		restored = append(restored, name)
	}

	// Recreate the MySQL accounts and grants for the restored databases from
	// __db__/users.sql. Restoring schema and data does not bring the site up on its
	// own: the account it connects as has to exist too. The allowlist is the set of
	// databases actually restored, so a grant on any other database is refused even
	// if the file carries one.
	if len(restored) > 0 {
		allow := map[string]bool{}
		for _, n := range restored {
			allow[n] = true
		}
		if n, err := applyDBUsers(ctx, filepath.Join(tmp, "__db__"), allow); err == nil && n > 0 {
			// #nosec G706 -- logged values are an integer count and a validated systemUser identifier.
			log.Printf("restore %s: %d user/grant statement(s) applied", systemUser, n)
		}
	}
	return res
}

// otherDomainOwns reports whether a database name is registered to a DIFFERENT
// domain, which is the cross-tenant guard for the recovery path. A read failure
// counts as owned elsewhere (fail closed), so a database hiccup never opens a
// path to import over another tenant's schema.
func otherDomainOwns(db *sql.DB, dbName string, domainID int64) bool {
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM db_accounts WHERE db_name=? AND domain_id<>?`, dbName, domainID).Scan(&n); err != nil {
		return true
	}
	return n > 0
}

// dbSummary turns a restoreAllDBs result into counts and a readable message.
// Without it the caller discarded the result and reported "databases restored"
// even when ZERO were: a failed restore rendered as confidence.
func dbSummary(results []map[string]string) (restored, skipped, failed int, message string) {
	var parts []string
	for _, r := range results {
		switch s := r["status"]; {
		case strings.HasPrefix(s, "restored"):
			restored++
		case strings.HasPrefix(s, "error"):
			failed++
		default:
			skipped++
		}
		parts = append(parts, r["db"]+": "+r["status"])
	}
	return restored, skipped, failed, strings.Join(parts, " | ")
}

// restoreOneDB restores a single DB either over the original (targetDB empty) or
// into a NEW name (mode db). A new target must be tenant-prefixed and non-system.
func restoreOneDB(ctx context.Context, db *sql.DB, domainID int64, tmp, systemUser, srcDB, targetDB string) (string, error) {
	files := archiveDBFiles(tmp, systemUser)
	sqlPath, ok := files[srcDB]
	if !ok {
		return "", fmt.Errorf("database %q is not in the backup", srcDB)
	}
	owned := map[string]bool{}
	for _, n := range domainDatabases(db, domainID, systemUser) {
		owned[n] = true
	}
	if targetDB == "" || targetDB == srcDB {
		if isSystemDB(srcDB) || !owned[srcDB] {
			return "", fmt.Errorf("%q is not owned by this domain", srcDB)
		}
		if err := importDB(ctx, srcDB, sqlPath); err != nil {
			return "", err
		}
		return "restored over " + srcDB, nil
	}
	if !credentials.ValidDBIdentifier(targetDB) || isSystemDB(targetDB) || !strings.HasPrefix(targetDB, systemUser+"_") {
		return "", fmt.Errorf("invalid target name — must start with %q", systemUser+"_")
	}
	if owned[targetDB] {
		return "", fmt.Errorf("%q already exists; leave the target empty to overwrite it", targetDB)
	}
	dbUser := tenantPrimaryDBUser(db, domainID, systemUser)
	if err := credentials.MySQLCreateDBForUser(db, domainID, targetDB, dbUser); err != nil {
		return "", fmt.Errorf("could not create target database: %w", err)
	}
	if err := importDB(ctx, targetDB, sqlPath); err != nil {
		return "", err
	}
	return "restored into new database " + targetDB, nil
}

// pathEscapes reports whether a relative path leaves the archive root after Clean.
func pathEscapes(p string) bool {
	c := filepath.Clean(p)
	return c == ".." || strings.HasPrefix(c, "../")
}

// restoreSelectedFiles copies only the chosen paths out of the archive.
// target != "in_place" -> /home/<systemUser>/restore-<stamp>/ (nothing overwritten).
// target == "in_place" -> original location (only the selected paths; home not wiped).
func restoreSelectedFiles(ctx context.Context, tmp, systemUser string, paths []string, target string) (int, string, error) {
	src := filepath.Join(tmp, systemUser)
	home := "/home/" + systemUser
	subDir := ""
	if target != "in_place" {
		subDir = "restore-" + time.Now().Format("20060102-150405")
		// Symlink-safe: the stamp is predictable, so a tenant can pre-create the name
		// as a symlink; os.MkdirAll would accept it and hand root a path outside home.
		if err := files.MkdirAllBeneath(home, subDir, systemUser); err != nil {
			return 0, "", fmt.Errorf("target directory: %w", err)
		}
	}
	n := 0
	for _, y := range paths {
		if ctx.Err() != nil {
			break
		}
		rel, ok := safeMemberPath(y)
		if !ok {
			continue
		}
		s := filepath.Join(src, rel)
		if s != src && !strings.HasPrefix(s, src+string(os.PathSeparator)) {
			continue
		}
		if _, err := os.Lstat(s); err != nil {
			continue
		}
		// The whole destination path is tenant-controlled, and this runs as root, so
		// the copy goes through openat2 instead of `cp`: `cp` follows a symlink at the
		// destination, and a symlinked parent component would let a tenant redirect the
		// write anywhere on the filesystem.
		if err := files.ImportBeneath(home, filepath.Join(subDir, rel), s, systemUser); err != nil {
			continue
		}
		n++
	}
	// No path-based `chown -R` here: ImportBeneath already chowns every entry it
	// creates through its pinned fd, and a recursive chown by path would follow a
	// tenant symlink and hand an unrelated tree to the tenant.
	files.RestoreconBeneath(home, subDir)
	return n, subDir, nil
}

// restoreHome restores the whole home. clean=false -> no --delete (active files
// absent from the backup are kept; only backed-up files are overwritten).
// clean=true -> rsync --delete (exact backup state; the old, dangerous behavior).
//
// rsync is the only copier used here on purpose. It replaces a destination symlink
// instead of writing through it, and it replaces a symlinked destination directory
// instead of descending into it, so a tenant cannot make this root-level copy land
// outside their own home. `cp` does follow both, so a cp fallback would reopen that
// hole whenever rsync happened to be missing; a failure is reported instead.
func restoreHome(ctx context.Context, tmp, systemUser string, clean bool) error {
	extractedHome := filepath.Join(tmp, systemUser)
	if _, err := os.Stat(extractedHome); err != nil {
		return nil
	}
	args := []string{"-a"}
	if clean {
		args = append(args, "--delete")
	}
	args = append(args, extractedHome+"/", "/home/"+systemUser+"/")
	// #nosec G204 G702 -- fixed binary (rsync) with separate args (no shell); systemUser is validated and paths are internal.
	if _, err := newRestoreCommand(ctx, "rsync", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("home directory copy failed: %w", err)
	}
	// chown -R defaults to -P, so it retags the symlink itself and never the file a
	// tenant link points at; restorecon reads labels with lgetfilecon for the same reason.
	// #nosec G204 G702 -- fixed binaries (chown/restorecon) with separate args (no shell); systemUser is validated.
	_, _ = newRestoreCommand(ctx, "chown", "-R", systemUser+":"+systemUser, "/home/"+systemUser).CombinedOutput()
	_, _ = newRestoreCommand(ctx, "restorecon", "-R", "/home/"+systemUser).CombinedOutput()
	return nil
}

// ContentFile / ContentDB are the archive-listing output types.
type ContentFile struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	IsDir bool   `json:"is_dir"`
}
type ContentDB struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// Contents handles GET /domains/{id}/backups/{bid}/contents.
// It read-only scans a domain's own archive and returns the file tree + DB list
// for the file-level and SQL-level granular restore UI.
func (h *Handlers) Contents(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	bid, _ := strconv.ParseInt(chi.URLParam(r, "bid"), 10, 64)

	var systemUser, file string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT d.system_user, b.file FROM backups b
		 JOIN domains d ON d.id=b.domain_id
		 WHERE b.id=? AND b.domain_id=?`, bid, id).Scan(&systemUser, &file)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "backup not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if !validSystemUser(systemUser) || file == "" || filepath.Base(file) != file {
		httpx.WriteError(w, http.StatusBadRequest, "invalid backup file")
		return
	}
	// Fetch the archive from the off-site destination when the local copy is
	// gone, so the contents of a pruned-but-uploaded backup can still be listed.
	if err := ensureLocalArchive(r.Context(), h.DB, id, bid, systemUser, file); err != nil {
		httpx.WriteError(w, http.StatusNotFound, err.Error())
		return
	}
	abs := filepath.Join(backupRoot(), systemUser, file)

	files, dbs, truncated, err := scanArchiveContents(abs, systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "backup archive could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"files":     files,
		"databases": dbs,
		"truncated": truncated,
	})
}

// scanArchiveContents read-only walks the .tar.gz and splits members into home
// files and DB dumps (capped at 6000 file entries).
func scanArchiveContents(abs, systemUser string) ([]ContentFile, []ContentDB, bool, error) {
	// #nosec G304 -- abs is BackupRoot/<validated systemUser>/<validated base file>, a root-owned server path, not tenant input.
	f, err := os.Open(abs)
	if err != nil {
		return nil, nil, false, err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, false, err
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	const limit = 6000
	files := []ContentFile{}
	dbs := []ContentDB{}
	truncated := false
	for {
		hd, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			break
		}
		name := strings.TrimPrefix(hd.Name, "./")
		if name == "" {
			continue
		}
		if base, ok := strings.CutPrefix(name, "__db__/"); ok {
			if dbName, isSQL := strings.CutSuffix(base, ".sql"); isSQL {
				dbs = append(dbs, ContentDB{Name: dbName, Size: hd.Size})
			}
			continue
		}
		if hd.Typeflag == tar.TypeReg && strings.HasSuffix(name, ".sql") && !strings.Contains(strings.TrimSuffix(name, "/"), "/") {
			dbs = append(dbs, ContentDB{Name: systemUser + "_main", Size: hd.Size})
			continue
		}
		if name == systemUser || name == systemUser+"/" {
			continue
		}
		disp := strings.TrimSuffix(strings.TrimPrefix(name, systemUser+"/"), "/")
		if disp == "" {
			continue
		}
		if len(files) >= limit {
			truncated = true
			continue
		}
		files = append(files, ContentFile{Path: disp, Size: hd.Size, IsDir: hd.Typeflag == tar.TypeDir})
	}
	return files, dbs, truncated, nil
}

// restoreArchiveScan is a restore-specific safety pre-scan. Unlike archivex.Scan
// it ALLOWS internal relative symlinks/hardlinks (npm/composer projects) and only
// rejects jail escapes (absolute or ..-escaping symlink/hardlink targets, absolute
// or ..-escaping member paths) and device/fifo members. Archives are root-produced
// trusted backups; this is defense in depth.
func restoreArchiveScan(abs string) error {
	// #nosec G304 -- abs is BackupRoot/<validated systemUser>/<validated base file>, a root-owned server path, not tenant input.
	f, err := os.Open(abs)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hd, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return fmt.Errorf("archive could not be read: %w", e)
		}
		name := strings.TrimPrefix(hd.Name, "./")
		if filepath.IsAbs(hd.Name) || pathEscapes(name) {
			return fmt.Errorf("security: invalid member path: %s", hd.Name)
		}
		switch hd.Typeflag {
		case tar.TypeSymlink:
			if filepath.IsAbs(hd.Linkname) {
				return fmt.Errorf("security: absolute symlink target rejected: %s -> %s", hd.Name, hd.Linkname)
			}
			// #nosec G305 -- this IS the traversal check: the join resolves the symlink target so pathEscapes can reject it; nothing is extracted here.
			if pathEscapes(filepath.Join(filepath.Dir(name), hd.Linkname)) {
				return fmt.Errorf("security: out-of-archive symlink rejected: %s -> %s", hd.Name, hd.Linkname)
			}
		case tar.TypeLink:
			if filepath.IsAbs(hd.Linkname) || pathEscapes(strings.TrimPrefix(hd.Linkname, "./")) {
				return fmt.Errorf("security: invalid hardlink rejected: %s -> %s", hd.Name, hd.Linkname)
			}
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			return fmt.Errorf("security: device/fifo member rejected: %s", hd.Name)
		}
	}
	return nil
}

// listArchiveMembers returns all member names (read-only).
func listArchiveMembers(abs string) ([]string, error) {
	// #nosec G304 -- abs is BackupRoot/<validated systemUser>/<validated base file>, a root-owned server path, not tenant input.
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	var members []string
	for {
		hd, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return members, nil
		}
		members = append(members, strings.TrimPrefix(hd.Name, "./"))
	}
	return members, nil
}

// membersForMode computes the top-level members to extract for a mode.
func membersForMode(mode, systemUser string, allMembers, paths []string) []string {
	hasHome, hasDBDir := false, false
	legacySQL := []string{}
	for _, m := range allMembers {
		if m == systemUser || strings.HasPrefix(m, systemUser+"/") {
			hasHome = true
		}
		if strings.HasPrefix(m, "__db__/") {
			hasDBDir = true
		}
		if strings.HasSuffix(m, ".sql") && !strings.Contains(strings.TrimSuffix(m, "/"), "/") {
			legacySQL = append(legacySQL, m)
		}
	}
	dbMembers := legacySQL
	if hasDBDir {
		dbMembers = []string{"__db__"}
	}
	switch mode {
	case "files":
		if hasHome {
			return []string{systemUser}
		}
		return nil
	case "database", "db":
		return dbMembers
	case "full":
		r := []string{}
		if hasHome {
			r = append(r, systemUser)
		}
		return append(r, dbMembers...)
	case "file":
		r := []string{}
		for _, y := range paths {
			if rel, ok := safeMemberPath(y); ok {
				r = append(r, systemUser+"/"+rel)
			}
		}
		return r
	}
	return nil
}

// extractMembersRoot extracts ONLY the given members as root into destDir. Quota
// friendly (root uid is unquotaed) so a second copy of the tenant home can be
// staged without hitting the tenant quota. Security: restoreArchiveScan pre-scan
// (jail-escape member rejection) runs first; archives are root-produced trusted
// backups (BackupRoot 0700).
func extractMembersRoot(ctx context.Context, abs, destDir string, members []string) (string, error) {
	if len(members) == 0 {
		return "", fmt.Errorf("no members to extract")
	}
	if archivex.DetectType(abs) == archivex.TypeUnknown {
		return "", fmt.Errorf("unsupported archive")
	}
	if err := restoreArchiveScan(abs); err != nil {
		return "", err
	}
	args := append([]string{"-xz", "-f", abs, "-C", destDir}, members...)
	// #nosec G204 G702 -- fixed binary (tar) with separate args (no shell); abs/destDir are root-owned server paths, members are pre-scanned by restoreArchiveScan.
	out, err := newRestoreCommand(ctx, "tar", args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("member extraction: %w", err)
	}
	return string(out), nil
}
