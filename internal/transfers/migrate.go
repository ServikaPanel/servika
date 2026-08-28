package transfers

import (
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"servika/internal/credentials"
	"servika/internal/dns"
	"servika/internal/domainblock"
	"servika/internal/phpversion"
	"servika/internal/provisioner"
	"servika/internal/resourcelimit"
	"servika/internal/sqlimport"
)

// MigrationResult reports what one account migration produced.
type MigrationResult struct {
	DomainID  int64
	FileBytes int64
	DBCount   int
	DNSCount  int
	Warnings  []string
}

// MigrateAccount migrates ONE account or domain end to end.
//
// Order: target check -> provision -> domains row -> FTP -> files -> databases
// (+ configuration rewrite) -> DNS -> SSL.
//
// Data-safety rules:
//   - When writing over an existing domain (overwrite), rsync NEVER DELETES;
//     existing files stay and source files are written over them.
//   - The database password is generated ONCE per domain; an existing database
//     user keeps its password (changing it kills the live site).
//   - When the database step fails, the item is NOT counted as successful.
func (h *Handlers) MigrateAccount(ctx context.Context, source *RemoteSource, account RemoteAccount,
	settings MigrationSettings, logf func(string, ...any)) (*MigrationResult, error) {

	ctx, cancel := context.WithTimeout(ctx, accountTimeout)
	defer cancel()

	result := &MigrationResult{}
	domainName := strings.ToLower(strings.TrimSpace(account.DomainName))
	if !reRemoteDomain.MatchString(domainName) || !strings.Contains(domainName, ".") {
		return nil, fmt.Errorf("invalid domain name")
	}
	// The live migration is the one creation path with no HTTP response of its
	// own, so it asks the same question directly. A read failure refuses here
	// too: the migration needs this database in the next statement anyway.
	switch blocked, _, err := domainblock.Blocked(ctx, h.DB, domainName); {
	case err != nil:
		return nil, fmt.Errorf("banned domain list: %w", err)
	case blocked:
		return nil, fmt.Errorf("'%s' may not be added to this server", domainName)
	}

	// --- 1. Target check ---------------------------------------------------
	var existingID int64
	var existingUser, existingRoot string
	err := h.DB.QueryRowContext(ctx,
		`SELECT id, system_user, COALESCE(web_root,'') FROM domains WHERE domain_name=?`,
		domainName).Scan(&existingID, &existingUser, &existingRoot)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("target check: %w", err)
	}
	created := false
	var systemUser, webRoot string
	php := settings.TargetPHP
	if php == "" {
		php = account.PHPVersion
	}
	if php == "" {
		php = "8.3"
	}

	if existingID > 0 {
		if !settings.Overwrite {
			return nil, fmt.Errorf("'%s' already exists on this server (overwrite is off)", domainName)
		}
		result.DomainID, systemUser = existingID, existingUser
		// The document root can be a sub-directory (for example a Laravel
		// .../public_html/public). Writing to public_html would publish nothing.
		webRoot = existingRoot
		if webRoot == "" {
			webRoot = filepath.Join("/home", systemUser, "public_html")
		}
		logf("found an existing domain on this server, writing over it (id=%d, root=%s)", existingID, webRoot)
	} else {
		requested := php
		php = installedPHPOrClosest(php)
		if php != requested {
			logf("warning: source PHP %s is not installed here, using %s instead", requested, php)
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("PHP %s is not installed, provisioned with %s", requested, php))
		}
		if err := h.validateMigrationOwner(ctx, settings.CustomerID); err != nil {
			return nil, err
		}
		logf("creating the system account (php %s)...", php)
		pr, err := provisioner.Provision(domainName, php)
		if err != nil {
			return nil, fmt.Errorf("provisioning: %w", err)
		}
		systemUser = pr.SystemUser
		webRoot = pr.WebRoot
		created = true

		dbUser, dbName := systemUser+"_db", systemUser+"_main"
		ipv4 := migrationSourceIPv4(h.DB)
		// status='passive': when the process dies half way (panel restart) a
		// half-migrated domain must not look active. Success flips it to 'active'.
		res, err := h.DB.ExecContext(ctx,
			`INSERT INTO domains(domain_name, system_user, php_version, ssl_enabled, status, ipv4,
			   ftp_host, ftp_user, db_host, db_user, db_name, web_root, web_backend,
			   plan_id, customer_id, is_demo)
			 VALUES(?,?,?,0,'passive',?,?,?, 'localhost',?,?,?, 'php-fpm', NULLIF(?,0), NULLIF(?,0), 0)`,
			domainName, systemUser, php, ipv4, ipv4, systemUser, dbUser, dbName, pr.WebRoot,
			settings.PlanID, settings.CustomerID)
		if err != nil {
			_ = provisioner.Deprovision(domainName, systemUser)
			return nil, fmt.Errorf("domain record: %w", err)
		}
		result.DomainID, _ = res.LastInsertId()

		limitCtx, limitCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		if err := resourcelimit.ApplyAll(limitCtx, h.DB, result.DomainID); err != nil {
			logf("warning: resource limits could not be applied: %v", err)
			result.Warnings = append(result.Warnings, "resource limits could not be applied")
		}
		limitCancel()

		if uid, gid, err := lookupUIDGID(systemUser); err == nil {
			if err := credentials.FTPCreate(h.DB, result.DomainID, systemUser,
				credentials.RandomPassword(16), uid, gid); err != nil {
				logf("warning: the FTP account could not be created: %v", err)
			}
		}
	}

	succeeded := false
	defer func() {
		if succeeded || !created {
			return
		}
		logf("an error occurred — rolling back the created account...")
		_, _ = h.DB.Exec(`DELETE FROM domains WHERE id=?`, result.DomainID)
		_ = provisioner.Deprovision(domainName, systemUser)
	}()

	// --- 2. Files ----------------------------------------------------------
	if settings.Files {
		remote := strings.TrimSpace(account.WebRoot)
		if !validRemotePath(remote) {
			return nil, fmt.Errorf("the source web root is invalid")
		}
		if err := os.MkdirAll(webRoot, 0o750); err != nil {
			return nil, fmt.Errorf("target directory: %w", err)
		}
		logf("copying files: %s -> %s", remote, webRoot)
		if _, err := source.RsyncPull(ctx, remote+"/", webRoot+"/",
			"--exclude=.git/", "--exclude=*.sock", "--exclude=.cpanel/"); err != nil {
			return nil, fmt.Errorf("file transfer: %w", err)
		}
		if size, err := directorySize(webRoot); err == nil {
			result.FileBytes = size
		}
		_ = newTransferCommand(ctx, "chown", "-R", systemUser+":"+systemUser, webRoot).Run()
		_ = newTransferCommand(ctx, "restorecon", "-RF", webRoot).Run()
		logf("files done (%.1f MB)", float64(result.FileBytes)/(1024*1024))
	}

	// --- 3. Databases ------------------------------------------------------
	// Backup discovery: the source enumeration assigns an account's databases to
	// the MAIN domain only (see discovery.go), and a Plesk query can come back
	// empty, so an addon or subdomain reaches here with no database at all. The
	// real name is written in the COPIED configuration and is the same on the
	// source, so read it from there and dump it. Without this the item is marked
	// done with the SQL silently missing.
	if settings.Databases && settings.Files && len(account.Databases) == 0 {
		if found := configDBNames(webRoot); len(found) > 0 {
			logf("discovery found no database; %d name(s) read from configuration: %v", len(found), found)
			account.Databases = found
		}
	}
	switch {
	case settings.Databases && len(account.Databases) > 0:
		mapping, dbPass, dbErr := h.migrateDatabases(ctx, source, account, systemUser, result, logf)
		if dbErr != nil {
			// A silent success here would publish the customer's site with an
			// EMPTY database, so the whole item must fail.
			return nil, dbErr
		}
		if n := rewriteSiteConfigs(webRoot, mapping, dbPass, logf); n > 0 {
			logf("%d configuration file(s) updated (database connection)", n)
		}
	case settings.Databases:
		// A database was requested but none was found, even in the config. Say
		// so, or the item reads as a success with the SQL silently missing.
		logf("warning: no database was found on the source for this site; SQL was not migrated")
		result.Warnings = append(result.Warnings,
			"no database migrated: the source has no database for this site (an addon/subdomain's database migrates with the main domain, or discovery could not see it)")
	}

	// --- 4. DNS ------------------------------------------------------------
	if settings.DNS {
		n, err := h.migrateDNS(ctx, source, result.DomainID, domainName, logf)
		if err != nil {
			logf("warning: DNS could not be migrated (default template used): %v", err)
			result.Warnings = append(result.Warnings, "DNS was created from the default template")
		}
		result.DNSCount = n
	}

	// --- 5. SSL ------------------------------------------------------------
	if settings.SSL {
		logf("requesting an SSL certificate...")
		certPath, keyPath, sslOutcome, sslErr := provisioner.EnableLetsEncrypt(
			domainName, systemUser, installedPHPOrClosest(php), "php-fpm")
		if certPath != "" {
			sourceName := "self-signed"
			if sslOutcome.Real {
				sourceName = "letsencrypt"
			}
			_, _ = h.DB.ExecContext(ctx,
				`UPDATE domains SET ssl_enabled=1, ssl_source=?, cert_path=?, key_path=? WHERE id=?`,
				sourceName, certPath, keyPath, result.DomainID)
			logf("SSL: %s", sourceName)
			if !sslOutcome.Real {
				warning := "SSL is self-signed, renew it once DNS points at this server"
				if sslOutcome.Reason != "" {
					warning += " (" + sslOutcome.Reason + ")"
				}
				result.Warnings = append(result.Warnings, warning)
			}
		} else {
			logf("warning: SSL could not be obtained: %v", sslErr)
			result.Warnings = append(result.Warnings, "SSL could not be obtained")
		}
	}

	if created {
		_, _ = h.DB.ExecContext(ctx, `UPDATE domains SET status='active' WHERE id=?`, result.DomainID)
	}
	succeeded = true
	return result, nil
}

// validateMigrationOwner checks that the customer the migrated site is assigned
// to really exists. An invalid target must not fall back to the main account
// silently.
func (h *Handlers) validateMigrationOwner(ctx context.Context, customerID int64) error {
	if customerID <= 0 {
		return nil
	}
	var n int
	if err := h.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM customers WHERE id=?`, customerID).Scan(&n); err != nil || n == 0 {
		return fmt.Errorf("invalid customer")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Database migration
// ---------------------------------------------------------------------------

type dbTarget struct{ Name, User string }

// migrateDatabases moves every source database.
//
// The password is generated ONCE and only assigned when the user does not exist
// yet. <systemUser>_db is unique to this domain, so setting it to a known new
// value is safe and REQUIRED: otherwise there is no password to write into
// wp-config and the site answers "Access denied".
func (h *Handlers) migrateDatabases(ctx context.Context, source *RemoteSource, account RemoteAccount,
	systemUser string, result *MigrationResult, logf func(string, ...any)) (map[string]dbTarget, string, error) {

	targetUser := systemUser + "_db"
	dbPass := credentials.RandomPassword(24)

	mapping := map[string]dbTarget{}
	userCreated := false
	var failed []string

	for _, sourceDB := range account.Databases {
		if !reRemoteDBName.MatchString(sourceDB) {
			continue
		}
		targetName, err := h.uniqueTargetDB(ctx, systemUser, sourceDB, account.SourceAccount)
		if err != nil {
			logf("warning: could not build a target name for %s: %v", sourceDB, err)
			failed = append(failed, sourceDB)
			continue
		}
		logf("database: %s -> %s", sourceDB, targetName)

		if !userCreated {
			if err := credentials.MySQLCreateDB(h.DB, result.DomainID, targetName, targetUser, dbPass); err != nil {
				logf("warning: %s could not be created: %v", targetName, err)
				failed = append(failed, sourceDB)
				continue
			}
			userCreated = true
		} else if err := credentials.MySQLCreateDBForUser(h.DB, result.DomainID, targetName, targetUser); err != nil {
			logf("warning: %s could not be created: %v", targetName, err)
			failed = append(failed, sourceDB)
			continue
		}

		if err := h.copyDatabase(ctx, source, sourceDB, targetName); err != nil {
			logf("ERROR: %s could not be copied: %v", sourceDB, err)
			failed = append(failed, sourceDB)
			continue
		}
		result.DBCount++
		mapping[sourceDB] = dbTarget{Name: targetName, User: targetUser}
	}

	if len(failed) > 0 {
		return mapping, dbPass, fmt.Errorf("database migration failed: %s", strings.Join(failed, ", "))
	}
	return mapping, dbPass, nil
}

// uniqueTargetDB maps "olduser_wp" to "<systemUser>_wp". Instead of TRUNCATING
// at the 64-character limit it checks for a collision and adds a counter;
// truncation collapsed two different source databases onto one target and
// dropped one of them silently.
func (h *Handlers) uniqueTargetDB(ctx context.Context, systemUser, sourceDB, sourceAccount string) (string, error) {
	suffix := sourceDB
	if sourceAccount != "" && strings.HasPrefix(sourceDB, sourceAccount+"_") {
		suffix = strings.TrimPrefix(sourceDB, sourceAccount+"_")
	}
	suffix = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			return r
		}
		return '_'
	}, suffix)
	if suffix == "" {
		suffix = "db"
	}
	base := systemUser + "_" + suffix
	for i := range 50 {
		candidate := base
		if i > 0 {
			candidate = fmt.Sprintf("%s_%d", base, i+1)
		}
		if len(candidate) > 64 {
			cut := 64 - len(candidate) + len(base)
			if cut < 1 {
				return "", fmt.Errorf("name too long")
			}
			candidate = base[:cut]
			if i > 0 {
				candidate = fmt.Sprintf("%s_%d", base[:cut-2], i+1)
			}
		}
		// Uniqueness must be checked against BOTH the real schema AND the panel
		// record (db_accounts): MySQLCreateDB hits the db_accounts.db_name UNIQUE
		// key, so looking only at information_schema returns 1062 Duplicate on a
		// repeated migration.
		var n int
		_ = h.DB.QueryRowContext(ctx,
			`SELECT (SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name=?)
			      + (SELECT COUNT(*) FROM db_accounts WHERE db_name=?)`, candidate, candidate).Scan(&n)
		if n == 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("could not build a unique database name")
}

const (
	maxDumpBytes         int64 = 8 << 30
	maxDumpExpandedBytes int64 = 64 << 30
	dumpCompleteMark           = "Dump completed"
)

// copyDatabase downloads the remote dump and imports it with a RESTRICTED MySQL
// user.
//
// Two traps:
//  1. In a "mysqldump | gzip" pipeline the shell returns the exit code of the
//     LAST command by default, so a crashed mysqldump still exits 0 and the
//     result looks successful while the database is EMPTY. pipefail is therefore
//     mandatory and the end-of-dump marker is verified.
//  2. Importing as root would let a hostile dump write outside the target
//     database.
func (h *Handlers) copyDatabase(ctx context.Context, source *RemoteSource, sourceDB, targetDB string) error {
	if !reRemoteDBName.MatchString(sourceDB) || !reRemoteDBName.MatchString(targetDB) {
		return fmt.Errorf("invalid database name")
	}
	tmp, err := os.CreateTemp("", "servika_migration_*.sql.gz")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	// The source MySQL admin client needs credentials on Plesk/DirectAdmin; a
	// credential-less mysqldump is refused there with 1045 (mysqlAdminAuth).
	dumpEnv, dumpUser := source.mysqlAdminAuth()
	inner := dumpEnv + "mysqldump " + dumpUser + "--single-transaction --quick --routines --triggers " +
		"--no-tablespaces --default-character-set=utf8mb4 " + shellQuote(sourceDB) + " | gzip -c"
	// bash is forced for pipefail; without it the command falls back to sh and
	// the end-of-dump marker is the only remaining guard.
	remote := "if command -v bash >/dev/null 2>&1; then bash -o pipefail -c " + shellQuote(inner) +
		"; else " + inner + "; fi"

	keyFile, cleanup, err := source.writeKeyFile()
	if err != nil {
		_ = tmp.Close()
		return err
	}
	defer cleanup()

	cmd := source.sshCommand(ctx, keyFile, remote)
	var stderr strings.Builder
	limited := &limitedWriter{file: tmp, remaining: maxDumpBytes}
	cmd.Stdout = limited
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	_ = tmp.Close()
	if limited.exceeded {
		return fmt.Errorf("the dump exceeded the size limit (%d GB)", maxDumpBytes>>30)
	}
	if runErr != nil {
		return fmt.Errorf("dump: %s", truncate(sanitizeRemoteError(stderr.String(), source.Password), 200))
	}
	st, err := os.Stat(tmpName)
	if err != nil || st.Size() == 0 {
		return fmt.Errorf("the dump came back empty")
	}

	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	f, err := os.Open(tmpName)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("the dump could not be read (gzip): %w", err)
	}
	defer func() { _ = gz.Close() }()

	// The dump came off the remote host and is hostile input. sqlimport owns the
	// scoped-account, option-file and DEFINER handling this function used to
	// carry itself; the local copy also passed the account password on
	// `mysql -e "CREATE USER ... IDENTIFIED BY '<pass>'"`, which publishes it
	// through /proc/<pid>/cmdline for the life of that client.
	filter := &dumpFilter{}
	if err := sqlimport.Import(ctx, targetDB,
		filter.Wrap(io.LimitReader(gz, maxDumpExpandedBytes))); err != nil {
		return fmt.Errorf("import: %s", truncate(sanitizeRemoteError(err.Error()), 200))
	}
	// mysqldump ends its output with "-- Dump completed". A missing marker means
	// the dump was cut short (remote error, dropped connection, locked table).
	if !filter.Complete {
		return fmt.Errorf("the dump is incomplete (mysqldump failed on the source server)")
	}
	return nil
}

type limitedWriter struct {
	file      *os.File
	remaining int64
	exceeded  bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.exceeded {
		return 0, fmt.Errorf("size limit exceeded")
	}
	if int64(len(p)) > w.remaining {
		w.exceeded = true
		return 0, fmt.Errorf("size limit exceeded")
	}
	n, err := w.file.Write(p)
	w.remaining -= int64(n)
	return n, err
}

// dumpFilter watches the stream for mysqldump's completion marker so a dump cut
// short by the remote host is not mistaken for a finished one. Rewriting the
// dump is sqlimport's job, not this one's.
type dumpFilter struct{ Complete bool }

func (d *dumpFilter) Wrap(r io.Reader) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		defer func() { _ = pw.Close() }()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 1<<20), 32<<20)
		for sc.Scan() {
			line := sc.Text()
			if strings.Contains(line, dumpCompleteMark) {
				d.Complete = true
			}
			if _, err := pw.Write([]byte(line + "\n")); err != nil {
				return
			}
		}
		if err := sc.Err(); err != nil {
			_ = pw.CloseWithError(err)
		}
	}()
	return pr
}

// ---------------------------------------------------------------------------
// Configuration file rewriting
// ---------------------------------------------------------------------------

// Configuration keys whose value is a DATABASE NAME.
var dbNameKeys = []string{"DB_NAME", "DB_DATABASE", "DATABASE", "dbname", "database", "db"}

// Configuration keys whose value is a DATABASE USER.
var dbUserKeys = []string{"DB_USER", "DB_USERNAME", "DATABASE_USER"}

// Configuration keys whose value is a DATABASE PASSWORD.
var dbPassKeys = []string{"DB_PASSWORD", "DB_PASS", "DATABASE_PASSWORD"}

var configCandidates = []string{
	"wp-config.php", ".env", "configuration.php", "config.php",
	"app/etc/env.php", "sites/default/settings.php", "config/db.php",
	"application/config/database.php", "includes/config.php",
}

// rewriteSiteConfigs updates the database connection details inside the site
// configuration.
//
// Only the value of a KNOWN KEY is replaced. Replacing every occurrence of
// "<account>_" in the text overwrote the database name with the user name and
// broke the syntax of PHP files that contain an apostrophe.
func rewriteSiteConfigs(webRoot string, mapping map[string]dbTarget, newPass string, logf func(string, ...any)) int {
	if len(mapping) == 0 {
		return 0
	}
	var targetUser string
	nameMap := map[string]string{}
	for old, target := range mapping {
		nameMap[old] = target.Name
		targetUser = target.User
	}

	count := 0
	for _, rel := range configCandidates {
		path := filepath.Join(webRoot, rel)
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() || st.Size() > 4<<20 {
			continue
		}
		// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		updated := string(raw)
		for _, key := range dbNameKeys {
			updated = replaceKeyValueFromMap(updated, key, nameMap)
		}
		if targetUser != "" {
			for _, key := range dbUserKeys {
				updated = replaceKeyValue(updated, key, targetUser)
			}
		}
		if newPass != "" {
			for _, key := range dbPassKeys {
				updated = replaceKeyValue(updated, key, newPass)
			}
		}
		if updated == string(raw) {
			continue
		}
		if err := writeConfigBackup(webRoot, rel, raw); err != nil {
			logf("warning: %s could not be backed up, the file was left unchanged: %v", rel, err)
			continue
		}
		if err := writeFileAtomically(path, []byte(updated), st); err == nil {
			count++
			logf("configuration updated: %s", rel)
		}
	}
	return count
}

// writeFileAtomically writes a temporary file in the same directory and renames
// it, so a crash half way cannot leave a truncated wp-config.php. Ownership and
// permissions are preserved.
func writeFileAtomically(path string, data []byte, st os.FileInfo) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".servika_cfg_*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	_ = tmp.Close()
	// #nosec G302 -- the mode is copied from the original file so the site keeps working.
	_ = os.Chmod(name, st.Mode().Perm())
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(name, int(sys.Uid), int(sys.Gid))
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

var reConfigKeyLine = regexp.MustCompile(`^(\s*)(?:define\s*\(\s*)?['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?\s*(?:,|=>|=|:)\s*(.*)$`)

// replaceKeyValue swaps the value on a "<key> = <value>" line. The quote style
// is preserved.
func replaceKeyValue(text, key, newValue string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		m := reConfigKeyLine.FindStringSubmatch(line)
		if m == nil || !strings.EqualFold(m[2], key) {
			continue
		}
		oldValue, quote := extractConfigValue(m[3])
		if oldValue == "" {
			continue
		}
		lines[i] = strings.Replace(line, quote+oldValue+quote, quote+newValue+quote, 1)
	}
	return strings.Join(lines, "\n")
}

// replaceKeyValueFromMap swaps keys whose current value appears in the mapping.
func replaceKeyValueFromMap(text, key string, mapping map[string]string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		m := reConfigKeyLine.FindStringSubmatch(line)
		if m == nil || !strings.EqualFold(m[2], key) {
			continue
		}
		oldValue, quote := extractConfigValue(m[3])
		newValue, ok := mapping[oldValue]
		if !ok || oldValue == "" {
			continue
		}
		lines[i] = strings.Replace(line, quote+oldValue+quote, quote+newValue+quote, 1)
	}
	return strings.Join(lines, "\n")
}

// extractConfigValue turns "'abc' );" into ("abc","'") and "abc" into ("abc","").
func extractConfigValue(rest string) (string, string) {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", ""
	}
	if rest[0] == '\'' || rest[0] == '"' {
		quote := string(rest[0])
		end := strings.Index(rest[1:], quote)
		if end < 0 {
			return "", ""
		}
		return rest[1 : 1+end], quote
	}
	// Unquoted: up to the end of the line or the next separator.
	if end := strings.IndexAny(rest, " \t;,)#"); end >= 0 {
		rest = rest[:end]
	}
	return strings.TrimSpace(rest), ""
}

// configDBNames reads database NAMES out of a copied site's configuration.
//
// It is the backup path for the empty-discovery case: the real database name is
// written in wp-config.php/.env and is the same on the source, so it can be
// dumped from there. Only a value that matches the remote-database name shape
// and is not a system database is returned, because the name becomes a
// mysqldump argument.
func configDBNames(webRoot string) []string {
	seen := map[string]bool{}
	var out []string
	for _, rel := range configCandidates {
		path := filepath.Join(webRoot, rel)
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() || st.Size() > 4<<20 {
			continue
		}
		// #nosec G304 -- path is a fixed configuration path joined onto the migration's own web root; tenant file reads go through safeio (openat2), not this call.
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(raw), "\n") {
			m := reConfigKeyLine.FindStringSubmatch(line)
			if m == nil || !isDBNameKey(m[2]) {
				continue
			}
			value, _ := extractConfigValue(m[3])
			value = strings.TrimSpace(value)
			if value == "" || seen[value] || !reRemoteDBName.MatchString(value) ||
				remoteSystemDBs[strings.ToLower(value)] {
				continue
			}
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

// isDBNameKey reports whether a configuration key holds a database name.
func isDBNameKey(key string) bool {
	for _, k := range dbNameKeys {
		if strings.EqualFold(key, k) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// DNS migration
// ---------------------------------------------------------------------------

// sourceWinsTypes lists record types where the SOURCE value must OVERRIDE the
// panel default. MX and TXT (SPF, DKIM, DMARC) carry the customer's mail flow;
// replacing them with defaults stops all mail the moment the site migrates.
var sourceWinsTypes = map[string]bool{"MX": true, "TXT": true, "CNAME": true, "SRV": true, "CAA": true}

func (h *Handlers) migrateDNS(ctx context.Context, source *RemoteSource, domainID int64,
	domainName string, logf func(string, ...any)) (int, error) {

	serverIP := migrationSourceIPv4(h.DB)
	if _, err := dns.SeedDefaults(ctx, h.DB, domainID, domainName, serverIP); err != nil {
		logf("warning: the DNS defaults could not be written: %v", err)
	}

	quoted := shellQuote(domainName)
	var records []zoneRecord

	// Plesk keeps DNS in its own store rather than a zone file, so it is read
	// with `plesk bin dns --info`. cPanel and DirectAdmin expose a raw BIND zone
	// file.
	if source.Type == "plesk" {
		if raw, err := source.Run(ctx, "plesk bin dns --info "+quoted+" 2>/dev/null"); err == nil {
			records = parsePleskDNS(raw, domainName)
		}
	}
	if len(records) == 0 {
		command := "cat /var/named/" + quoted + ".db 2>/dev/null || " +
			"cat /var/named/run-root/var/named/" + quoted + ".db 2>/dev/null || " +
			"cat /var/lib/named/var/named/" + quoted + ".db 2>/dev/null || " +
			"cat /etc/bind/db." + quoted + " 2>/dev/null || " +
			"cat /var/named/data/" + quoted + ".db 2>/dev/null"
		if raw, err := source.Run(ctx, command); err == nil && strings.TrimSpace(raw) != "" {
			records = parseZoneFile(raw, domainName)
		}
	}
	if len(records) == 0 {
		if err := dns.WriteZone(ctx, h.DB, domainID); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("the source DNS records could not be read")
	}

	oldIP := ""
	for _, rec := range records {
		if rec.Type == "A" && rec.Name == "@" {
			oldIP = rec.Value
			break
		}
	}
	if oldIP == "" && net.ParseIP(source.Host) != nil {
		oldIP = source.Host
	}

	added := 0
	cleared := map[string]bool{}
	for _, rec := range records {
		if rec.Type == "AAAA" || rec.Type == "NS" {
			continue // the old IPv6 is invalid and NS must be the panel's own servers
		}
		value := rec.Value
		if rec.Type == "A" && (value == oldIP || rec.Name == "@" || rec.Name == "www") {
			value = serverIP
		}
		key := rec.Name + "|" + rec.Type
		switch {
		case rec.Type == "CNAME":
			// A CNAME must be the ONLY record for a name (RFC 1034): no A or TXT
			// may share it. Records such as the seeded "www A" are removed too,
			// otherwise named-checkzone REJECTS the zone with "CNAME and other data".
			if !cleared[rec.Name+"|*"] {
				_, _ = h.DB.ExecContext(ctx,
					`DELETE FROM dns_records WHERE domain_id=? AND name=?`, domainID, rec.Name)
				cleared[rec.Name+"|*"] = true
			}
		case sourceWinsTypes[rec.Type]:
			// When the source supplies records for this (name, type), clear the
			// panel default once and then add ALL of the source records.
			if !cleared[key] {
				_, _ = h.DB.ExecContext(ctx,
					`DELETE FROM dns_records WHERE domain_id=? AND name=? AND type=?`,
					domainID, rec.Name, rec.Type)
				cleared[key] = true
			}
		default:
			// Do not add another record to a name that already holds a CNAME.
			var cname int
			_ = h.DB.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM dns_records WHERE domain_id=? AND name=? AND type='CNAME'`,
				domainID, rec.Name).Scan(&cname)
			if cname > 0 {
				continue
			}
			var existing int
			_ = h.DB.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM dns_records WHERE domain_id=? AND name=? AND type=?`,
				domainID, rec.Name, rec.Type).Scan(&existing)
			if existing > 0 {
				continue
			}
		}
		var duplicate int
		_ = h.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM dns_records WHERE domain_id=? AND name=? AND type=? AND value=?`,
			domainID, rec.Name, rec.Type, value).Scan(&duplicate)
		if duplicate > 0 {
			continue
		}
		if _, err := h.DB.ExecContext(ctx,
			`INSERT INTO dns_records(domain_id, name, type, value, ttl, priority, enabled)
			 VALUES(?,?,?,?,?,?,1)`,
			domainID, rec.Name, rec.Type, value, rec.TTL, rec.Priority); err == nil {
			added++
		}
	}
	if err := dns.WriteZone(ctx, h.DB, domainID); err != nil {
		return added, fmt.Errorf("the zone could not be written: %w", err)
	}
	logf("DNS: %d record(s) migrated", added)
	return added, nil
}

type zoneRecord struct {
	Name, Type, Value string
	TTL, Priority     int
}

var migratableRecordTypes = map[string]bool{
	"A": true, "CNAME": true, "MX": true, "TXT": true, "SRV": true, "CAA": true,
}

// parsePleskDNS converts `plesk bin dns --info <domain>` output into records.
// One line per record: "<fqdn>. <TYPE> [<pri> [<weight> <port>]] <value>".
func parsePleskDNS(raw, domainName string) []zoneRecord {
	var out []zoneRecord
	for line := range strings.SplitSeq(raw, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		recordType := strings.ToUpper(fields[1])
		if !migratableRecordTypes[recordType] {
			continue
		}
		name := strings.TrimSuffix(fields[0], ".")
		name = strings.TrimSuffix(name, "."+domainName)
		if name == domainName || name == "" {
			name = "@"
		}
		priority := 0
		var value string
		switch recordType {
		case "MX":
			if len(fields) < 4 {
				continue
			}
			priority, _ = strconv.Atoi(fields[2])
			value = strings.TrimSuffix(fields[3], ".")
		case "SRV":
			if len(fields) < 6 {
				continue
			}
			priority, _ = strconv.Atoi(fields[2])
			value = fields[3] + " " + fields[4] + " " + strings.TrimSuffix(fields[5], ".")
		case "CNAME":
			value = strings.TrimSuffix(fields[2], ".")
		default: // A, TXT, CAA
			value = strings.Join(fields[2:], " ")
		}
		if value == "" || len(value) > 2048 || len(name) > 100 {
			continue
		}
		out = append(out, zoneRecord{Name: name, Type: recordType, Value: value, TTL: 3600, Priority: priority})
	}
	return out
}

// parseZoneFile converts BIND zone text into records.
//
// Comment stripping must be QUOTE AWARE: ';' is DATA inside DMARC, DKIM and SPF
// values. Cutting at the first ';' left only "v=DMARC1". Split quoted strings
// ("v=DKIM1;" "p=MIG...") are joined back together.
func parseZoneFile(raw, domainName string) []zoneRecord {
	var out []zoneRecord
	lastName := "@"
	parenDepth := 0

	for rawLine := range strings.SplitSeq(raw, "\n") {
		line := stripZoneComment(rawLine)
		if parenDepth > 0 {
			parenDepth += strings.Count(line, "(") - strings.Count(line, ")")
			continue // body of a multi-line block such as SOA
		}
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "$") {
			continue
		}
		if strings.Contains(strings.ToUpper(line), "SOA") {
			parenDepth += strings.Count(line, "(") - strings.Count(line, ")")
			continue
		}
		if open := strings.Count(line, "(") - strings.Count(line, ")"); open > 0 {
			parenDepth += open
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		name := lastName
		i := 0
		if !strings.HasPrefix(rawLine, " ") && !strings.HasPrefix(rawLine, "\t") {
			name = fields[0]
			i = 1
		}
		ttl := 3600
		for ; i < len(fields); i++ {
			if strings.EqualFold(fields[i], "IN") {
				continue
			}
			if n, err := strconv.Atoi(fields[i]); err == nil {
				ttl = n
				continue
			}
			break
		}
		if i >= len(fields) {
			continue
		}
		recordType := strings.ToUpper(fields[i])

		// The name must be normalised even for an unsupported type, otherwise the
		// next indented line is attributed to the WRONG owner.
		normalized := strings.TrimSuffix(name, ".")
		normalized = strings.TrimSuffix(normalized, "."+domainName)
		if normalized == domainName || normalized == "" {
			normalized = "@"
		}
		lastName = normalized

		if !migratableRecordTypes[recordType] {
			continue
		}
		rest := fields[i+1:]
		if len(rest) == 0 {
			continue
		}
		priority := 0
		if recordType == "MX" || recordType == "SRV" {
			if n, err := strconv.Atoi(rest[0]); err == nil {
				priority = n
				rest = rest[1:]
			}
		}
		if len(rest) == 0 {
			continue
		}
		// Parenthesised rdata that completes on one line: ( "v=DKIM1;" "p=MIG..." )
		value := joinQuotedParts(stripOuterParens(strings.Join(rest, " ")))
		if value == "" || len(value) > 500 || len(normalized) > 100 {
			continue
		}
		out = append(out, zoneRecord{Name: normalized, Type: recordType, Value: value, TTL: ttl, Priority: priority})
	}
	return out
}

// stripZoneComment drops everything from the first ';' that is outside quotes.
func stripZoneComment(s string) string {
	inQuotes := false
	for i := range len(s) {
		switch s[i] {
		case '"':
			inQuotes = !inQuotes
		case ';':
			if !inQuotes {
				return s[:i]
			}
		}
	}
	return s
}

// joinQuotedParts turns `"v=DKIM1; k=rsa" "p=MIG..."` into `v=DKIM1; k=rsa p=MIG...`.
// BIND splits TXT values over the 255-byte limit; without joining them DKIM breaks.
func joinQuotedParts(s string) string {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "\"") {
		return s
	}
	var b strings.Builder
	inQuotes := false
	for i := range len(s) {
		c := s[i]
		if c == '"' {
			inQuotes = !inQuotes
			continue
		}
		if !inQuotes && c == ' ' {
			continue // whitespace between quoted chunks
		}
		b.WriteByte(c)
	}
	return strings.TrimSpace(b.String())
}

// stripOuterParens removes the wrapping parentheses of an rdata block that
// completes on a single line. BIND wraps long or multi-line TXT records in
// parentheses; leaving them in stores the value as "(v=DKIM1; k=rsa; p=MIG...)"
// and DKIM validation FAILS.
func stripOuterParens(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, "(") {
		s = strings.TrimSpace(s[1:])
	}
	for strings.HasSuffix(s, ")") {
		s = strings.TrimSpace(s[:len(s)-1])
	}
	return strings.TrimSpace(s)
}

// ---------------------------------------------------------------------------
// PHP version
// ---------------------------------------------------------------------------

// installedPHPOrClosest falls back to the best installed version when the source
// version is missing here. Inside the same MAJOR release it looks UPWARDS first:
// downgrading a request for "8" or "8.1" to 7.4 would break PHP 8 code.
func installedPHPOrClosest(requested string) string {
	var installed []string
	for _, v := range phpversion.AllVersions() {
		if v.Loaded {
			installed = append(installed, v.Version)
		}
	}
	if len(installed) == 0 || requested == "" {
		return requested
	}
	if slices.Contains(installed, requested) {
		return requested
	}
	wantMajor, wantMinor := splitPHPVersion(requested)
	// 1) Same major release — first >= requested, otherwise the highest one below.
	var sameUp, sameDown string
	for _, v := range installed {
		major, minor := splitPHPVersion(v)
		if major != wantMajor {
			continue
		}
		if minor >= wantMinor {
			if sameUp == "" {
				sameUp = v
			} else if _, upMinor := splitPHPVersion(sameUp); minor < upMinor {
				sameUp = v
			}
		} else if sameDown == "" {
			sameDown = v
		} else if _, downMinor := splitPHPVersion(sameDown); minor > downMinor {
			sameDown = v
		}
	}
	if sameUp != "" {
		return sameUp
	}
	if sameDown != "" {
		return sameDown
	}
	// 2) Different major release — the closest higher one, otherwise the closest lower.
	var higher, lower string
	for _, v := range installed {
		major, minor := splitPHPVersion(v)
		if major > wantMajor || (major == wantMajor && minor > wantMinor) {
			if higher == "" {
				higher = v
			} else if hMajor, hMinor := splitPHPVersion(higher); major < hMajor || (major == hMajor && minor < hMinor) {
				higher = v
			}
		} else if lower == "" {
			lower = v
		} else if lMajor, lMinor := splitPHPVersion(lower); major > lMajor || (major == lMajor && minor > lMinor) {
			lower = v
		}
	}
	if higher != "" {
		return higher
	}
	if lower != "" {
		return lower
	}
	return requested
}

func splitPHPVersion(s string) (int, int) {
	var major, minor int
	_, _ = fmt.Sscanf(s, "%d.%d", &major, &minor)
	return major, minor
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const migrationBackupRoot = "/var/lib/servika/migration-backup"

func writeConfigBackup(webRoot, rel string, raw []byte) error {
	// filepath.Base alone is not enough: Base("/home/x/..") is "..", which would
	// climb one level out of the backup root. Pin the bucket name to a plain
	// component and fall back to a fixed name when it is not one.
	bucket := filepath.Base(filepath.Dir(webRoot))
	if bucket == "." || bucket == ".." || bucket == string(filepath.Separator) || bucket == "" {
		bucket = "unknown"
	}
	dir := filepath.Join(migrationBackupRoot, bucket)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// rel comes from the fixed configCandidates list and every separator is
	// folded into '_', so the file name is a single component.
	name := strings.ReplaceAll(rel, "/", "_")
	// #nosec G703 -- bucket is a single validated path component and name has no separator, so the write stays inside migrationBackupRoot.
	return os.WriteFile(filepath.Join(dir, name), raw, 0o600)
}

func lookupUIDGID(systemUser string) (int, int, error) {
	u, err := user.Lookup(systemUser)
	if err != nil {
		return 0, 0, err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid, nil
}

func directorySize(path string) (int64, error) {
	var total int64
	err := filepath.Walk(path, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && fi != nil && fi.Mode().IsRegular() {
			total += fi.Size()
		}
		return nil
	})
	return total, err
}
