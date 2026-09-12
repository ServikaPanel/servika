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
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"servika/internal/config"
	"servika/internal/credentials"
)

// MigrationResult reports what one account migration produced.
type MigrationResult struct {
	DomainID  int64
	FileBytes int64
	DBCount   int
	DNSCount  int
	MailCount int
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

	m := &accountMigration{h: h, source: source, account: account, settings: settings,
		result: &MigrationResult{}, logf: logf,
		domainName: strings.ToLower(strings.TrimSpace(account.DomainName))}
	if err := m.checkDomain(ctx); err != nil {
		return nil, err
	}
	if err := m.prepareTarget(ctx); err != nil {
		return nil, err
	}

	succeeded := false
	defer func() {
		if succeeded || !m.created {
			return
		}
		logf("an error occurred — rolling back the created account...")
		_, _ = h.DB.Exec(`DELETE FROM domains WHERE id=?`, m.result.DomainID)
		_ = deprovisionAccount(m.domainName, m.systemUser)
	}()

	if err := m.migrateData(ctx); err != nil {
		return nil, err
	}

	if m.created {
		_, _ = h.DB.ExecContext(ctx, `UPDATE domains SET status='active' WHERE id=?`, m.result.DomainID)
	}
	succeeded = true
	return m.result, nil
}

// accountMigration carries one account migration: its inputs, the target account
// the steps write into, and the result the steps build up.
type accountMigration struct {
	h        *Handlers
	source   *RemoteSource
	account  RemoteAccount
	settings MigrationSettings
	result   *MigrationResult
	logf     func(string, ...any)

	domainName string
	systemUser string
	webRoot    string
	php        string
	// created is set once this migration provisions the account, so a failure
	// after that point removes the account again.
	created bool
}

// checkDomain refuses a domain name that is invalid or on the banned list.
func (m *accountMigration) checkDomain(ctx context.Context) error {
	if !reRemoteDomain.MatchString(m.domainName) || !strings.Contains(m.domainName, ".") {
		return fmt.Errorf("invalid domain name")
	}
	// The live migration is the one creation path with no HTTP response of its
	// own, so it asks the same question directly. A read failure refuses here
	// too: the migration needs this database in the next statement anyway.
	switch blocked, _, err := blockedDomain(ctx, m.h.DB, m.domainName); {
	case err != nil:
		return fmt.Errorf("banned domain list: %w", err)
	case blocked:
		return fmt.Errorf("'%s' may not be added to this server", m.domainName)
	}
	return nil
}

// prepareTarget finds the existing domain to write over, or provisions a new
// account when this server does not have the domain.
func (m *accountMigration) prepareTarget(ctx context.Context) error {
	// --- 1. Target check ---------------------------------------------------
	var existingID int64
	var existingUser, existingRoot string
	err := m.h.DB.QueryRowContext(ctx,
		`SELECT id, system_user, COALESCE(web_root,'') FROM domains WHERE domain_name=?`,
		m.domainName).Scan(&existingID, &existingUser, &existingRoot)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("target check: %w", err)
	}
	m.php = m.settings.TargetPHP
	if m.php == "" {
		m.php = m.account.PHPVersion
	}
	if m.php == "" {
		m.php = "8.3"
	}

	if existingID <= 0 {
		return m.provisionNewAccount(ctx)
	}
	if !m.settings.Overwrite {
		return fmt.Errorf("'%s' already exists on this server (overwrite is off)", m.domainName)
	}
	m.result.DomainID, m.systemUser = existingID, existingUser
	// The document root can be a sub-directory (for example a Laravel
	// .../public_html/public). Writing to public_html would publish nothing.
	m.webRoot = existingRoot
	if m.webRoot == "" {
		m.webRoot = filepath.Join("/home", m.systemUser, "public_html")
	}
	m.logf("found an existing domain on this server, writing over it (id=%d, root=%s)", existingID, m.webRoot)
	return nil
}

// provisionNewAccount creates the system account and the passive domain row,
// then applies the resource limits and creates the FTP account.
func (m *accountMigration) provisionNewAccount(ctx context.Context) error {
	requested := m.php
	m.php = installedPHPOrClosest(m.php)
	if m.php != requested {
		m.logf("warning: source PHP %s is not installed here, using %s instead", requested, m.php)
		m.result.Warnings = append(m.result.Warnings,
			fmt.Sprintf("PHP %s is not installed, provisioned with %s", requested, m.php))
	}
	if err := m.h.validateMigrationOwner(ctx, m.settings.CustomerID); err != nil {
		return err
	}
	m.logf("creating the system account (php %s)...", m.php)
	pr, err := provisionAccount(m.domainName, m.php)
	if err != nil {
		return fmt.Errorf("provisioning: %w", err)
	}
	m.systemUser = pr.SystemUser
	m.webRoot = pr.WebRoot
	m.created = true

	dbUser, dbName := m.systemUser+"_db", m.systemUser+"_main"
	ipv4 := migrationSourceIPv4(m.h.DB)
	// status='passive': when the process dies half way (panel restart) a
	// half-migrated domain must not look active. Success flips it to 'active'.
	res, err := m.h.DB.ExecContext(ctx,
		`INSERT INTO domains(domain_name, system_user, php_version, ssl_enabled, status, ipv4,
			   ftp_host, ftp_user, db_host, db_user, db_name, web_root, web_backend,
			   plan_id, customer_id)
			 VALUES(?,?,?,0,'passive',?,?,?, 'localhost',?,?,?, 'php-fpm', NULLIF(?,0), NULLIF(?,0))`,
		m.domainName, m.systemUser, m.php, ipv4, ipv4, m.systemUser, dbUser, dbName, pr.WebRoot,
		m.settings.PlanID, m.settings.CustomerID)
	if err != nil {
		_ = deprovisionAccount(m.domainName, m.systemUser)
		return fmt.Errorf("domain record: %w", err)
	}
	m.result.DomainID, _ = res.LastInsertId()

	m.applyLimits()
	m.createFTP()
	return nil
}

// applyLimits applies the resource limits to the new domain; a failure is a
// warning.
func (m *accountMigration) applyLimits() {
	limitCtx, limitCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer limitCancel()
	if err := applyResourceLimits(limitCtx, m.h.DB, m.result.DomainID); err != nil {
		m.logf("warning: resource limits could not be applied: %v", err)
		m.result.Warnings = append(m.result.Warnings, "resource limits could not be applied")
	}
}

// createFTP creates the new system user's FTP account. A user that cannot be
// looked up gets none, and a failure is logged.
func (m *accountMigration) createFTP() {
	uid, gid, err := lookupUIDGID(m.systemUser)
	if err != nil {
		return
	}
	if err := createFTPAccount(m.h.DB, m.result.DomainID, m.systemUser,
		credentials.RandomPassword(16), uid, gid); err != nil {
		m.logf("warning: the FTP account could not be created: %v", err)
	}
}

// migrateData runs the files, databases, DNS, SSL and mail steps in that order.
// A files or database failure stops the migration; the later steps only add
// warnings.
func (m *accountMigration) migrateData(ctx context.Context) error {
	if err := m.files(ctx); err != nil {
		return err
	}
	if err := m.databases(ctx); err != nil {
		return err
	}
	if m.settings.DNS {
		m.dns(ctx)
	}
	if m.settings.SSL {
		m.ssl(ctx)
	}
	if m.settings.Mail {
		m.mail(ctx)
	}
	return nil
}

// files copies the source web root into the target web root.
func (m *accountMigration) files(ctx context.Context) error {
	// --- 2. Files ----------------------------------------------------------
	// A hosting-less domain (a redirect-only subdomain) has no web root of its own.
	// Discovery leaves it empty rather than falling back to the main domain's
	// document root, so skip the files step with a visible warning here instead of
	// pulling the wrong tree or aborting the whole account.
	if !m.settings.Files {
		return nil
	}
	remote := strings.TrimSpace(m.account.WebRoot)
	if remote == "" {
		m.logf("no web root for this domain (redirect or hosting-less); files not migrated")
		m.result.Warnings = append(m.result.Warnings,
			"files were not migrated: this domain has no web root of its own (it may be a redirect subdomain)")
		return nil
	}
	if !validRemotePath(remote) {
		return fmt.Errorf("the source web root is invalid")
	}
	if err := os.MkdirAll(m.webRoot, 0o750); err != nil {
		return fmt.Errorf("target directory: %w", err)
	}
	m.logf("copying files: %s -> %s", remote, m.webRoot)
	if _, err := m.source.RsyncPull(ctx, remote+"/", m.webRoot+"/",
		"--exclude=.git/", "--exclude=*.sock", "--exclude=.cpanel/"); err != nil {
		return fmt.Errorf("file transfer: %w", err)
	}
	if size, err := directorySize(m.webRoot); err == nil {
		m.result.FileBytes = size
	}
	_ = newTransferCommand(ctx, "chown", "-R", m.systemUser+":"+m.systemUser, m.webRoot).Run()
	_ = newTransferCommand(ctx, "restorecon", "-RF", m.webRoot).Run()
	m.logf("files done (%.1f MB)", float64(m.result.FileBytes)/(1024*1024))
	return nil
}

// databases moves the site's databases and points its configuration at them.
func (m *accountMigration) databases(ctx context.Context) error {
	// --- 3. Databases ------------------------------------------------------
	m.account.Databases = m.databaseNames()
	switch {
	case m.settings.Databases && len(m.account.Databases) > 0:
		mapping, dbPass, keptOriginal, dbErr := m.h.migrateDatabases(ctx, m.source, m.account, m.systemUser, m.webRoot, m.result, m.logf)
		if dbErr != nil {
			// A silent success here would publish the customer's site with an
			// EMPTY database, so the whole item must fail.
			return dbErr
		}
		// Nothing to rewrite when the databases kept their own name, user and
		// password: the configuration already describes the connection that now
		// exists, and rewriting it would only risk breaking a file that is correct.
		if !keptOriginal {
			if n := rewriteSiteConfigs(m.webRoot, mapping, dbPass, m.logf); n > 0 {
				m.logf("%d configuration file(s) updated (database connection)", n)
			}
		}
	case m.settings.Databases:
		// A database was requested but none was found, even in the config. Say
		// so, or the item reads as a success with the SQL silently missing.
		m.logf("warning: no database was found on the source for this site; SQL was not migrated")
		m.result.Warnings = append(m.result.Warnings,
			"no database migrated: the source has no database for this site (an addon/subdomain's database migrates with the main domain, or discovery could not see it)")
	}
	return nil
}

// databaseNames returns the databases to move: discovery's list, or the names
// read from the copied configuration when discovery found none.
func (m *accountMigration) databaseNames() []string {
	// Backup discovery: the source enumeration assigns an account's databases to
	// the MAIN domain only (see discovery.go), and a Plesk query can come back
	// empty, so an addon or subdomain reaches here with no database at all. The
	// real name is written in the COPIED configuration and is the same on the
	// source, so read it from there and dump it. Without this the item is marked
	// done with the SQL silently missing.
	if m.settings.Databases && m.settings.Files && len(m.account.Databases) == 0 {
		if found := configDBNames(m.webRoot); len(found) > 0 {
			m.logf("discovery found no database; %d name(s) read from configuration: %v", len(found), found)
			return found
		}
	}
	return m.account.Databases
}

// dns merges the source zone into the domain's zone; a failure leaves the
// default template in place with a warning.
func (m *accountMigration) dns(ctx context.Context) {
	// --- 4. DNS ------------------------------------------------------------
	n, err := m.h.migrateDNS(ctx, m.source, m.result.DomainID, m.domainName, m.logf)
	if err != nil {
		m.logf("warning: DNS could not be migrated (default template used): %v", err)
		m.result.Warnings = append(m.result.Warnings, "DNS was created from the default template")
	}
	m.result.DNSCount = n
}

// ssl imports the source certificate, or else requests one from Let's Encrypt.
func (m *accountMigration) ssl(ctx context.Context) {
	// --- 5. SSL ------------------------------------------------------------
	if m.h.importSourceSSL(ctx, m.source, m.account, m.result.DomainID, m.domainName, m.logf, m.result) {
		// The source's own certificate was copied; HTTPS is ready without waiting
		// for the DNS cutover. importSourceSSL logged the outcome and any warning.
		return
	}
	m.logf("requesting an SSL certificate...")
	certPath, keyPath, sslOutcome, sslErr := enableLetsEncrypt(
		m.domainName, m.systemUser, installedPHPOrClosest(m.php), "php-fpm")
	if certPath == "" {
		m.logf("warning: SSL could not be obtained: %v", sslErr)
		m.result.Warnings = append(m.result.Warnings, "SSL could not be obtained")
		return
	}
	sourceName := "self-signed"
	if sslOutcome.Real {
		sourceName = "letsencrypt"
	}
	_, _ = m.h.DB.ExecContext(ctx,
		`UPDATE domains SET ssl_enabled=1, ssl_source=?, cert_path=?, key_path=? WHERE id=?`,
		sourceName, certPath, keyPath, m.result.DomainID)
	m.logf("SSL: %s", sourceName)
	if !sslOutcome.Real {
		warning := "SSL is self-signed, renew it once DNS points at this server"
		if sslOutcome.Reason != "" {
			warning += " (" + sslOutcome.Reason + ")"
		}
		m.result.Warnings = append(m.result.Warnings, warning)
	}
}

// mail moves the mailboxes and their messages; a mail failure is a warning.
func (m *accountMigration) mail(ctx context.Context) {
	// --- 6. Mail (mailboxes + Maildir data) --------------------------------
	// After web, database, DNS and SSL so a mail failure does not roll back a
	// working site: the domain is already provisioned, and a lost mailbox is a
	// warning, not a reason to undo the whole migration.
	m.logf("Mail: discovering source mailboxes...")
	n, creds, warns, mailErr := m.h.migrateMail(ctx, m.source, m.account, m.result.DomainID, m.systemUser, m.logf)
	m.result.Warnings = append(m.result.Warnings, warns...)
	if mailErr != nil {
		m.logf("warning: mail could not be migrated: %v", mailErr)
		m.result.Warnings = append(m.result.Warnings, "mail could not be migrated")
		return
	}
	m.result.MailCount = n
	if n > 0 {
		m.logf("Mail: %d mailbox(es) migrated", n)
	}
	// Fresh passwords for the operator to hand out; the source password is
	// never reused. The migration log is admin-only.
	for _, c := range creds {
		m.logf("Mail: new credential %s / %s", c.Email, c.Password)
	}
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
	systemUser, webRoot string, result *MigrationResult, logf func(string, ...any)) (map[string]dbTarget, string, bool, error) {

	targetUser := systemUser + "_db"
	dbPass := credentials.RandomPassword(24)

	// When the source site's own name, user and password can all be kept, the
	// configuration never has to be rewritten and the database keeps the name its
	// owner knows. The decision is taken for the whole migration rather than per
	// database, because rewriteSiteConfigs writes ONE user and ONE password
	// across every configuration file it finds.
	keepOriginal := false
	if user, password, ok := h.keepOriginalIdentity(ctx, account, webRoot); ok {
		targetUser, dbPass, keepOriginal = user, password, true
		logf("keeping the source database name, user and password; the site configuration is left untouched")
	}

	mapping := map[string]dbTarget{}
	userCreated := false
	var failed []string

	for _, sourceDB := range account.Databases {
		if !reRemoteDBName.MatchString(sourceDB) {
			continue
		}
		targetName := sourceDB
		if !keepOriginal {
			var err error
			targetName, err = h.uniqueTargetDB(ctx, systemUser, sourceDB, account.SourceAccount)
			if err != nil {
				logf("warning: could not build a target name for %s: %v", sourceDB, err)
				failed = append(failed, sourceDB)
				continue
			}
		}
		logf("database: %s -> %s", sourceDB, targetName)

		if err := h.createTargetDB(result.DomainID, targetName, targetUser, dbPass, userCreated); err != nil {
			logf("warning: %s could not be created: %v", targetName, err)
			failed = append(failed, sourceDB)
			continue
		}
		userCreated = true

		if err := h.copyDatabase(ctx, source, sourceDB, targetName); err != nil {
			logf("ERROR: %s could not be copied: %v", sourceDB, err)
			failed = append(failed, sourceDB)
			continue
		}
		result.DBCount++
		mapping[sourceDB] = dbTarget{Name: targetName, User: targetUser}
	}

	if len(failed) > 0 {
		return mapping, dbPass, keepOriginal, fmt.Errorf("database migration failed: %s", strings.Join(failed, ", "))
	}
	return mapping, dbPass, keepOriginal, nil
}

// createTargetDB creates one target database. The first one also creates the
// database user with its password; each later one is attached to that user.
func (h *Handlers) createTargetDB(domainID int64, name, user, password string, userCreated bool) error {
	if !userCreated {
		return createMySQLDB(h.DB, domainID, name, user, password)
	}
	return createMySQLDBForUser(h.DB, domainID, name, user)
}

// keepOriginalIdentity reports the source site's own database user and password
// when the whole migration can run under them, so no configuration file has to
// be touched. Every condition must hold; anything in the way returns false and
// the caller takes the unique-name path it has always taken.
//
// The value read here is the password of a LIVE account on the source, so it is
// used only to create the same account on this server and is never logged.
func (h *Handlers) keepOriginalIdentity(ctx context.Context, account RemoteAccount, webRoot string) (string, string, bool) {
	user, password := configDBIdentity(webRoot)
	// Without both halves there is nothing to keep: creating the account with a
	// password the site does not use would leave it unable to connect, which is
	// worse than renaming the database.
	if user == "" || password == "" {
		return "", "", false
	}
	// The user reaches CREATE USER through credentials, which accepts only
	// [A-Za-z0-9_]. reRemoteDBName is wider (it also allows $ and -), so the
	// narrower rule is the one that decides here.
	if !credentials.ValidDBIdentifier(user) || remoteSystemDBs[strings.ToLower(user)] {
		return "", "", false
	}
	// An account that already exists belongs to somebody else on this server, and
	// taking it over would hand this site their grants.
	if h.dbUserExists(ctx, user) {
		return "", "", false
	}
	if !h.databasesKeepTheirNames(ctx, account.Databases) {
		return "", "", false
	}
	return user, password, true
}

// databasesKeepTheirNames reports whether every source database can be created
// here under its own name: there is at least one, and each is a valid identifier
// that is neither a system database nor a schema this server already holds.
func (h *Handlers) databasesKeepTheirNames(ctx context.Context, databases []string) bool {
	if len(databases) == 0 {
		return false
	}
	for _, name := range databases {
		if !reRemoteDBName.MatchString(name) || !credentials.ValidDBIdentifier(name) ||
			remoteSystemDBs[strings.ToLower(name)] {
			return false
		}
		if !h.dbNameAvailable(ctx, name) {
			return false
		}
	}
	return true
}

// dbUserExists reports whether a local MySQL account of this name is already
// there. It FAILS CLOSED in both directions that matter: a name the allowlist
// refuses, and a query that could not be answered, are both reported as
// existing, so the caller declines to keep the original identity and falls back
// to the unique-name path rather than acting on an unknown.
//
// The name is concatenated into the statement because the mysql CLI takes no
// placeholders, and the panel's own connection cannot read mysql.user (it is
// granted on panel.* alone), which is why this goes over the root socket at all.
// The allowlist is therefore the whole boundary and is checked first.
func (h *Handlers) dbUserExists(ctx context.Context, user string) bool {
	if !credentials.ValidDBIdentifier(user) {
		return true
	}
	out, err := newTransferCommand(ctx, "mysql", "-N", "-B", "-e",
		"SELECT COUNT(*) FROM mysql.user WHERE User='"+user+"' AND Host='localhost'").Output()
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(out)) != "0"
}

// dbNameAvailable reports whether the target server has no schema of this name.
// It fails closed the same way: an unanswerable query reads as taken.
func (h *Handlers) dbNameAvailable(ctx context.Context, name string) bool {
	if !credentials.ValidDBIdentifier(name) {
		return false
	}
	out, err := newTransferCommand(ctx, "mysql", "-N", "-B", "-e",
		"SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+name+"'").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "0"
}

// configDBIdentity reads the database user and password out of the site's own
// configuration, which the file step has already copied onto this server. It
// reuses the same key sets and value reader configDBNames uses, so it covers
// every configuration shape that function already understands.
func configDBIdentity(webRoot string) (string, string) {
	var user, password string
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
		u, p := configDBIdentityFrom(string(raw))
		if u != "" && p != "" {
			return u, p
		}
		// A file may carry only one of the two; keep the first of each seen.
		if user == "" {
			user = u
		}
		if password == "" {
			password = p
		}
	}
	return user, password
}

// configDBIdentityFrom pulls the user and password out of one configuration
// file's text.
func configDBIdentityFrom(body string) (string, string) {
	var user, password string
	for line := range strings.SplitSeq(body, "\n") {
		m := reConfigKeyLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		value, _ := extractConfigValue(m[3])
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		switch {
		case user == "" && matchesKey(m[2], dbUserKeys):
			user = value
		case password == "" && matchesKey(m[2], dbPassKeys):
			password = value
		}
	}
	return user, password
}

// matchesKey reports whether a configuration key is one of the given names.
func matchesKey(key string, names []string) bool {
	for _, n := range names {
		if strings.EqualFold(key, n) {
			return true
		}
	}
	return false
}

// uniqueTargetDB maps "olduser_wp" to "<systemUser>_wp". Instead of TRUNCATING
// at the 64-character limit it checks for a collision and adds a counter;
// truncation collapsed two different source databases onto one target and
// dropped one of them silently.
func (h *Handlers) uniqueTargetDB(ctx context.Context, systemUser, sourceDB, sourceAccount string) (string, error) {
	base := systemUser + "_" + targetDBSuffix(sourceDB, sourceAccount)
	for i := range 50 {
		candidate, err := targetDBCandidate(base, i)
		if err != nil {
			return "", err
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

// targetDBSuffix is the source database name without the source account prefix,
// with every character outside [A-Za-z0-9_] folded into an underscore.
func targetDBSuffix(sourceDB, sourceAccount string) string {
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
	return suffix
}

// targetDBCandidate returns the i-th name to try: the base, then the base with a
// counter, cut to fit the 64-character identifier limit.
func targetDBCandidate(base string, i int) (string, error) {
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
	return candidate, nil
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

	if err := downloadDump(ctx, source, sourceDB, tmp); err != nil {
		return err
	}
	st, err := os.Stat(tmpName)
	if err != nil || st.Size() == 0 {
		return fmt.Errorf("the dump came back empty")
	}
	return importDownloadedDump(ctx, tmpName, targetDB)
}

// downloadDump writes the source database's gzip dump into tmp over SSH and
// closes tmp on every path.
func downloadDump(ctx context.Context, source *RemoteSource, sourceDB string, tmp *os.File) error {
	// The source MySQL admin client needs credentials on Plesk/DirectAdmin; a
	// credential-less mysqldump is refused there with 1045 (mysqlAdminAuth).
	dumpEnv, dumpUser := source.mysqlAdminAuth()
	inner := dumpEnv + "mysqldump " + dumpUser + "--single-transaction --quick --routines --triggers " +
		"--no-tablespaces --default-character-set=utf8mb4 " + config.ShellQuote(sourceDB) + " | gzip -c"
	// bash is forced for pipefail; without it the command falls back to sh and
	// the end-of-dump marker is the only remaining guard.
	remote := "if command -v bash >/dev/null 2>&1; then bash -o pipefail -c " + config.ShellQuote(inner) +
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
	return nil
}

// importDownloadedDump imports the downloaded gzip dump into targetDB and
// requires the completion marker mysqldump writes at its end.
func importDownloadedDump(ctx context.Context, dumpPath, targetDB string) error {
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	f, err := os.Open(dumpPath)
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
	if err := importSQLDump(ctx, targetDB,
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
		path, raw, st, ok := readSiteConfig(webRoot, rel)
		if !ok {
			continue
		}
		updated := rewriteConfigText(string(raw), nameMap, targetUser, newPass)
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

// rewriteConfigText replaces the database name, user and password values in one
// configuration's text; an empty user or password leaves that value as it is.
func rewriteConfigText(text string, nameMap map[string]string, targetUser, newPass string) string {
	updated := text
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
	return updated
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
		_, raw, _, ok := readSiteConfig(webRoot, rel)
		if !ok {
			continue
		}
		for line := range strings.SplitSeq(string(raw), "\n") {
			value := configDBNameValue(line)
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

// readSiteConfig reads one candidate configuration under the web root and
// returns its path, its content and its file information. A path that is
// missing, not a regular file, over 4 MiB or unreadable is skipped.
func readSiteConfig(webRoot, rel string) (string, []byte, os.FileInfo, bool) {
	path := filepath.Join(webRoot, rel)
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 4<<20 {
		return "", nil, nil, false
	}
	// #nosec G304 -- path is a fixed configuration path joined onto the migration's own web root; tenant file reads go through safeio (openat2), not this call.
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", nil, nil, false
	}
	return path, raw, st, true
}

// configDBNameValue returns the database name a configuration line assigns, or
// an empty string when the line names none that may become a mysqldump argument.
func configDBNameValue(line string) string {
	m := reConfigKeyLine.FindStringSubmatch(line)
	if m == nil || !isDBNameKey(m[2]) {
		return ""
	}
	value, _ := extractConfigValue(m[3])
	value = strings.TrimSpace(value)
	if !reRemoteDBName.MatchString(value) || remoteSystemDBs[strings.ToLower(value)] {
		return ""
	}
	return value
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
	if _, err := seedDNSDefaults(ctx, h.DB, domainID, domainName, serverIP); err != nil {
		logf("warning: the DNS defaults could not be written: %v", err)
	}

	records := readSourceRecords(ctx, source, domainName)
	if len(records) == 0 {
		if err := writeDNSZone(ctx, h.DB, domainID); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("the source DNS records could not be read")
	}

	merge := &dnsMerge{h: h, domainID: domainID, serverIP: serverIP,
		oldIP: sourceZoneIPv4(records, source.Host), cleared: map[string]bool{}}
	added := 0
	for _, rec := range records {
		if merge.add(ctx, rec) {
			added++
		}
	}
	if err := writeDNSZone(ctx, h.DB, domainID); err != nil {
		return added, fmt.Errorf("the zone could not be written: %w", err)
	}
	logf("DNS: %d record(s) migrated", added)
	return added, nil
}

// readSourceRecords reads the domain's records from the source server.
func readSourceRecords(ctx context.Context, source *RemoteSource, domainName string) []zoneRecord {
	quoted := config.ShellQuote(domainName)
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
	return records
}

// sourceZoneIPv4 is the address the source zone served at its apex, or the
// source host when no apex record names one and the host is an IP address.
func sourceZoneIPv4(records []zoneRecord, sourceHost string) string {
	for _, rec := range records {
		if rec.Type == "A" && rec.Name == "@" {
			return rec.Value
		}
	}
	if net.ParseIP(sourceHost) != nil {
		return sourceHost
	}
	return ""
}

// dnsMerge adds source records to a seeded zone and remembers which defaults it
// has already cleared.
type dnsMerge struct {
	h               *Handlers
	domainID        int64
	serverIP, oldIP string
	cleared         map[string]bool
}

// add merges one source record and reports whether it was inserted.
func (m *dnsMerge) add(ctx context.Context, rec zoneRecord) bool {
	if rec.Type == "AAAA" || rec.Type == "NS" {
		return false // the old IPv6 is invalid and NS must be the panel's own servers
	}
	value := rec.Value
	if rec.Type == "A" && (value == m.oldIP || rec.Name == "@" || rec.Name == "www") {
		value = m.serverIP
	}
	if !m.makeRoom(ctx, rec) {
		return false
	}
	var duplicate int
	_ = m.h.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM dns_records WHERE domain_id=? AND name=? AND type=? AND value=?`,
		m.domainID, rec.Name, rec.Type, value).Scan(&duplicate)
	if duplicate > 0 {
		return false
	}
	_, err := m.h.DB.ExecContext(ctx,
		`INSERT INTO dns_records(domain_id, name, type, value, ttl, priority, enabled)
			 VALUES(?,?,?,?,?,?,1)`,
		m.domainID, rec.Name, rec.Type, value, rec.TTL, rec.Priority)
	return err == nil
}

// makeRoom prepares the zone for one source record: a CNAME clears its name once
// and a source-wins type clears the default once. It returns false for any
// other record whose name cannot take it.
func (m *dnsMerge) makeRoom(ctx context.Context, rec zoneRecord) bool {
	key := rec.Name + "|" + rec.Type
	switch {
	case rec.Type == "CNAME":
		// A CNAME must be the ONLY record for a name (RFC 1034): no A or TXT
		// may share it. Records such as the seeded "www A" are removed too,
		// otherwise named-checkzone REJECTS the zone with "CNAME and other data".
		if !m.cleared[rec.Name+"|*"] {
			_, _ = m.h.DB.ExecContext(ctx,
				`DELETE FROM dns_records WHERE domain_id=? AND name=?`, m.domainID, rec.Name)
			m.cleared[rec.Name+"|*"] = true
		}
	case sourceWinsTypes[rec.Type]:
		// When the source supplies records for this (name, type), clear the
		// panel default once and then add ALL of the source records.
		if !m.cleared[key] {
			_, _ = m.h.DB.ExecContext(ctx,
				`DELETE FROM dns_records WHERE domain_id=? AND name=? AND type=?`,
				m.domainID, rec.Name, rec.Type)
			m.cleared[key] = true
		}
	default:
		return m.nameIsFree(ctx, rec)
	}
	return true
}

// nameIsFree reports whether a record may join its name: the name holds no CNAME
// and no record of the same type yet.
func (m *dnsMerge) nameIsFree(ctx context.Context, rec zoneRecord) bool {
	// Do not add another record to a name that already holds a CNAME.
	var cname int
	_ = m.h.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM dns_records WHERE domain_id=? AND name=? AND type='CNAME'`,
		m.domainID, rec.Name).Scan(&cname)
	if cname > 0 {
		return false
	}
	var existing int
	_ = m.h.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM dns_records WHERE domain_id=? AND name=? AND type=?`,
		m.domainID, rec.Name, rec.Type).Scan(&existing)
	return existing == 0
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
		name := relativeRecordName(fields[0], domainName)
		priority, value, ok := pleskRecordValue(recordType, fields)
		if !ok {
			continue
		}
		if value == "" || len(value) > 2048 || len(name) > 100 {
			continue
		}
		out = append(out, zoneRecord{Name: name, Type: recordType, Value: value, TTL: 3600, Priority: priority})
	}
	return out
}

// relativeRecordName turns an owner name into the form the panel stores: the
// zone's own domain becomes "@", and a name inside it loses the domain suffix.
func relativeRecordName(name, domainName string) string {
	name = strings.TrimSuffix(name, ".")
	name = strings.TrimSuffix(name, "."+domainName)
	if name == domainName || name == "" {
		name = "@"
	}
	return name
}

// pleskRecordValue reads the priority and the value of one Plesk record, or
// false when a record of this type is too short to carry them.
func pleskRecordValue(recordType string, fields []string) (int, string, bool) {
	switch recordType {
	case "MX":
		if len(fields) < 4 {
			return 0, "", false
		}
		priority, _ := strconv.Atoi(fields[2])
		return priority, strings.TrimSuffix(fields[3], "."), true
	case "SRV":
		if len(fields) < 6 {
			return 0, "", false
		}
		priority, _ := strconv.Atoi(fields[2])
		return priority, fields[3] + " " + fields[4] + " " + strings.TrimSuffix(fields[5], "."), true
	case "CNAME":
		return 0, strings.TrimSuffix(fields[2], "."), true
	default: // A, TXT, CAA
		return 0, strings.Join(fields[2:], " "), true
	}
}

// parseZoneFile converts BIND zone text into records.
//
// Comment stripping must be QUOTE AWARE: ';' is DATA inside DMARC, DKIM and SPF
// values. Cutting at the first ';' left only "v=DMARC1". Split quoted strings
// ("v=DKIM1;" "p=MIG...") are joined back together.
func parseZoneFile(raw, domainName string) []zoneRecord {
	var out []zoneRecord
	p := &zoneParser{domainName: domainName, lastName: "@"}
	for rawLine := range strings.SplitSeq(raw, "\n") {
		if rec, ok := p.line(rawLine); ok {
			out = append(out, rec)
		}
	}
	return out
}

// zoneParser carries what one zone line leaves for the next: the owner an
// indented line inherits and the depth of an open parenthesised block.
type zoneParser struct {
	domainName string
	lastName   string
	parenDepth int
}

// line reads one zone line and returns its record, or false for a line that
// holds no migratable record.
func (p *zoneParser) line(rawLine string) (zoneRecord, bool) {
	line := stripZoneComment(rawLine)
	if p.skipsBlock(line) {
		return zoneRecord{}, false
	}
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return zoneRecord{}, false
	}
	name, ttl, i := p.owner(rawLine, fields)
	if i >= len(fields) {
		return zoneRecord{}, false
	}
	recordType := strings.ToUpper(fields[i])

	// The name must be normalised even for an unsupported type, otherwise the
	// next indented line is attributed to the WRONG owner.
	normalized := relativeRecordName(name, p.domainName)
	p.lastName = normalized

	if !migratableRecordTypes[recordType] {
		return zoneRecord{}, false
	}
	priority, value, ok := zoneRecordValue(recordType, fields[i+1:])
	if !ok || value == "" || len(value) > 500 || len(normalized) > 100 {
		return zoneRecord{}, false
	}
	return zoneRecord{Name: normalized, Type: recordType, Value: value, TTL: ttl, Priority: priority}, true
}

// skipsBlock reports whether a line is consumed without a record: the body of a
// multi-line block, a blank or $ directive line, or a line that opens a block.
func (p *zoneParser) skipsBlock(line string) bool {
	if p.parenDepth > 0 {
		p.parenDepth += strings.Count(line, "(") - strings.Count(line, ")")
		return true // body of a multi-line block such as SOA
	}
	if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "$") {
		return true
	}
	if strings.Contains(strings.ToUpper(line), "SOA") {
		p.parenDepth += strings.Count(line, "(") - strings.Count(line, ")")
		return true
	}
	if open := strings.Count(line, "(") - strings.Count(line, ")"); open > 0 {
		p.parenDepth += open
		return true
	}
	return false
}

// owner returns a line's owner name, its TTL and the index of its type field.
// An indented line inherits the previous owner.
func (p *zoneParser) owner(rawLine string, fields []string) (string, int, int) {
	name := p.lastName
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
	return name, ttl, i
}

// zoneRecordValue reads the priority of an MX or SRV record and the value of any
// record from the fields after its type, or false when no value remains.
func zoneRecordValue(recordType string, rest []string) (int, string, bool) {
	if len(rest) == 0 {
		return 0, "", false
	}
	priority := 0
	if recordType == "MX" || recordType == "SRV" {
		if n, err := strconv.Atoi(rest[0]); err == nil {
			priority = n
			rest = rest[1:]
		}
	}
	if len(rest) == 0 {
		return 0, "", false
	}
	// Parenthesised rdata that completes on one line: ( "v=DKIM1;" "p=MIG..." )
	return priority, joinQuotedParts(stripOuterParens(strings.Join(rest, " "))), true
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
	installed := loadedPHPVersions()
	if len(installed) == 0 || requested == "" {
		return requested
	}
	if slices.Contains(installed, requested) {
		return requested
	}
	wantMajor, wantMinor := splitPHPVersion(requested)
	// 1) Same major release — first >= requested, otherwise the highest one below.
	sameMajor := func(major, _ int) bool { return major == wantMajor }
	atOrAboveMinor := func(_, minor int) bool { return minor >= wantMinor }
	if v := nearestPHP(installed, sameMajor, atOrAboveMinor); v != "" {
		return v
	}
	// 2) Different major release — the closest higher one, otherwise the closest lower.
	anyMajor := func(int, int) bool { return true }
	aboveWanted := func(major, minor int) bool { return phpVersionAbove(major, minor, wantMajor, wantMinor) }
	if v := nearestPHP(installed, anyMajor, aboveWanted); v != "" {
		return v
	}
	return requested
}

// loadedPHPVersions lists the PHP versions installed and loaded on this server.
func loadedPHPVersions() []string {
	var installed []string
	for _, v := range phpVersions() {
		if v.Loaded {
			installed = append(installed, v.Version)
		}
	}
	return installed
}

// nearestPHP returns the lowest installed version on the upper side of the
// wanted one, otherwise the highest on the lower side, or an empty string when
// no version passes keep. above decides the side; of two equal versions the
// first listed wins.
func nearestPHP(installed []string, keep, above func(major, minor int) bool) string {
	var up, down string
	var upMajor, upMinor, downMajor, downMinor int
	for _, v := range installed {
		major, minor := splitPHPVersion(v)
		if !keep(major, minor) {
			continue
		}
		if above(major, minor) {
			if up == "" || phpVersionAbove(upMajor, upMinor, major, minor) {
				up, upMajor, upMinor = v, major, minor
			}
		} else if down == "" || phpVersionAbove(major, minor, downMajor, downMinor) {
			down, downMajor, downMinor = v, major, minor
		}
	}
	if up != "" {
		return up
	}
	return down
}

// phpVersionAbove reports whether major.minor is above otherMajor.otherMinor.
func phpVersionAbove(major, minor, otherMajor, otherMinor int) bool {
	return major > otherMajor || (major == otherMajor && minor > otherMinor)
}

func splitPHPVersion(s string) (int, int) {
	var major, minor int
	_, _ = fmt.Sscanf(s, "%d.%d", &major, &minor)
	return major, minor
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// migrationBackupRoot is where a rewritten configuration's original is kept. It
// is a variable so a test can point the backup at a temporary directory.
var migrationBackupRoot = "/var/lib/servika/migration-backup"

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
	u, err := lookupSystemUser(systemUser)
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
