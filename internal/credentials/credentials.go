// Package credentials manages FTP and MySQL database accounts.
package credentials

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"servika/internal/secret"
)

// PasswordAlphabet is the character set every generated password is drawn from.
// It omits the pairs a reader confuses when a password is read aloud or copied
// off a screen: I, O, l, o, 0 and 1.
const PasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"

// RandomPassword returns a URL-safe alphanumeric password, using 20 characters
// by default.
//
// The byte is drawn by REJECTION SAMPLING rather than reduced with a modulo.
// 256 is not a multiple of the 56-character alphabet (256 % 56 = 32), so
// `byte % 56` gives the first 32 characters five chances out of 256 and the
// remaining 24 only four, a measured 1.2500 bias. Bytes at or above the largest
// exact multiple are drawn again instead.
//
// crypto/rand.Read is documented never to return an error and to always fill
// its buffer, crashing the program irrecoverably if the operating system fails
// it, so there is no partially filled buffer to guard against here.
func RandomPassword(length int) string {
	if length <= 0 {
		length = 20
	}
	n := len(PasswordAlphabet)
	// 224 for a 56-character alphabet. Kept as an int: an alphabet that divides
	// 256 exactly gives 256 here, which as a byte would wrap to 0 and reject
	// every draw for good.
	limit := 256 - (256 % n)
	out := make([]byte, 0, length)
	buf := make([]byte, length)
	for len(out) < length {
		_, _ = rand.Read(buf)
		for _, c := range buf {
			if int(c) >= limit {
				continue // Would land in the short tail and skew the result.
			}
			out = append(out, PasswordAlphabet[int(c)%n])
			if len(out) == length {
				break
			}
		}
	}
	return string(out)
}

// ValidPassword reports whether a password is safe for line-oriented system commands.
func ValidPassword(password string) bool {
	return !strings.ContainsAny(password, "\r\n\x00")
}

// encryptDBPass seals a database password for at-rest storage in
// db_accounts.db_pass_plain. The database user is bound as AEAD associated data
// so a stored ciphertext cannot be copied into another account's row and
// decrypted under a different user (which would leak that user's password
// through the reveal/phpMyAdmin paths). The column keeps its historical name;
// its content is now ciphertext for freshly written rows.
func encryptDBPass(dbUser, plaintext string) (string, error) {
	return secret.EncryptWith(plaintext, dbUser)
}

// DecryptDBPass reverses encryptDBPass, binding the same database-user AAD.
// A legacy plaintext value (no encryption prefix) is returned unchanged, so
// rows written before encryption keep working until their next write/backfill.
func DecryptDBPass(dbUser, stored string) (string, error) {
	return secret.DecryptWith(stored, dbUser)
}

// EncryptDBPass seals a database password bound to its db_user, for a caller
// outside this package that writes its own db_accounts row (the create-user path
// for a database that has none). It mirrors DecryptDBPass, which is already
// exported, so a row written here reads back through the same reveal path.
func EncryptDBPass(dbUser, plaintext string) (string, error) {
	return encryptDBPass(dbUser, plaintext)
}

// IsEncryptedValue reports whether stored already looks like ciphertext. Used to
// reject user-supplied passwords that carry the encryption prefix, closing the
// decryption-oracle path.
func IsEncryptedValue(stored string) bool {
	return secret.IsEncrypted(stored)
}

// IsHashed reports whether a stored value is already a SHA-512-crypt ($6$) hash
// rather than legacy cleartext. Used to keep hashing and backfill idempotent.
func IsHashed(stored string) bool { return strings.HasPrefix(stored, "$6$") }

// HashPassword produces a SHA-512-crypt ($6$) hash with a random salt via
// `openssl passwd -6`. The password is fed on stdin (never as an argv element,
// which would leak through /proc and `ps`). Pure-FTPd verifies these hashes
// natively in MYSQLCrypt=crypt mode, and VerifyPassword checks them in Go, so
// the ftp_accounts.password_md5 column no longer holds reusable cleartext.
func HashPassword(password string) (string, error) {
	cmd := exec.Command("openssl", "passwd", "-6", "-stdin")
	cmd.Stdin = strings.NewReader(password + "\n")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	h := strings.TrimSpace(string(out))
	if !IsHashed(h) {
		return "", errors.New("hash password: unexpected openssl output")
	}
	return h, nil
}

// VerifyPassword reports whether password matches a SHA-512-crypt ($6$) stored
// hash. It re-hashes the input with the stored salt and compares in constant
// time. Stored values that are not $6$ hashes (legacy cleartext that has not yet
// been backfilled) never verify, so a cleartext row cannot authenticate.
func VerifyPassword(stored, password string) bool {
	if !IsHashed(stored) {
		return false
	}
	// $6$<salt>$<digest> — extract the salt segment (index 2).
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[2] == "" {
		return false
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	cmd := exec.Command("openssl", "passwd", "-6", "-salt", parts[2], "-stdin")
	cmd.Stdin = strings.NewReader(password + "\n")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	computed := strings.TrimSpace(string(out))
	return subtle.ConstantTimeCompare([]byte(computed), []byte(stored)) == 1
}

// BackfillCleartextPasswords migrates any ftp_accounts row whose password_md5 is
// still legacy cleartext (not a $6$ hash). While the cleartext is still readable
// it writes BOTH the SHA-512-crypt ($6$) hash into password_md5 and the
// AES-256-GCM encrypted copy into ftp_password_enc — the one chance to preserve
// the reversible value before the cleartext is overwritten by the hash. Runs at
// startup after migrations so the switch to MYSQLCrypt=crypt does not lock out
// existing FTP users. Idempotent: already-hashed rows are skipped. Returns the
// number of rows migrated.
func BackfillCleartextPasswords(db *sql.DB) (int, error) {
	rows, err := db.Query(`SELECT id, password_md5 FROM ftp_accounts`)
	if err != nil {
		return 0, err
	}
	type row struct {
		id       int64
		password string
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.password); err != nil {
			_ = rows.Close() // read-only cursor; Close error is not actionable here
			return 0, err
		}
		if !IsHashed(r.password) {
			pending = append(pending, r)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close() // read-only cursor; Close error is not actionable here
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range pending {
		h, err := HashPassword(r.password)
		if err != nil {
			return n, err
		}
		enc, err := secret.Encrypt(r.password)
		if err != nil {
			return n, err
		}
		if _, err := db.Exec(`UPDATE ftp_accounts SET password_md5=?, ftp_password_enc=? WHERE id=?`, h, enc, r.id); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// BackfillDBPasswords encrypts any db_accounts.db_pass_plain rows still stored
// as legacy cleartext (no encryption prefix), binding each to its db_user as
// AEAD associated data. Idempotent: already-encrypted rows are skipped, so it is
// safe to run on every startup.
func BackfillDBPasswords(db *sql.DB) (int, error) {
	rows, err := db.Query(`SELECT id, db_user, db_pass_plain FROM db_accounts`)
	if err != nil {
		return 0, err
	}
	type row struct {
		id       int64
		dbUser   string
		password string
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.dbUser, &r.password); err != nil {
			_ = rows.Close() // read-only cursor; Close error is not actionable here
			return 0, err
		}
		if !secret.IsEncrypted(r.password) {
			pending = append(pending, r)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close() // read-only cursor; Close error is not actionable here
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range pending {
		enc, err := encryptDBPass(r.dbUser, r.password)
		if err != nil {
			return n, err
		}
		if _, err := db.Exec(`UPDATE db_accounts SET db_pass_plain=? WHERE id=?`, enc, r.id); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// FTPCreate inserts an FTP account. password_md5 stores a SHA-512-crypt ($6$)
// hash that Pure-FTPd (MYSQLCrypt=crypt) and customer login verify against, so it
// never holds reusable cleartext. ftp_password_enc stores an AES-256-GCM encrypted
// copy of the password for the reveal endpoint and the SSH password sync.
func FTPCreate(db *sql.DB, domainID int64, systemUser, password string, uidN, gidN int) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	enc, err := secret.Encrypt(password)
	if err != nil {
		return err
	}
	home := "/home/" + systemUser
	_, err = db.Exec(
		`INSERT INTO ftp_accounts(domain_id, username, password_md5, ftp_password_enc, home_dir, uid_n, gid_n, status)
		 VALUES(?,?,?,?,?,?,?, 'active')
		 ON DUPLICATE KEY UPDATE password_md5=VALUES(password_md5), ftp_password_enc=VALUES(ftp_password_enc), home_dir=VALUES(home_dir), uid_n=VALUES(uid_n), gid_n=VALUES(gid_n), status='active'`,
		domainID, systemUser, hash, enc, home, uidN, gidN)
	return err
}

// FTPUpdatePassword updates an existing FTP account password, writing both the
// SHA-512-crypt ($6$) hash and the AES-256-GCM encrypted copy. Bumping
// token_version revokes any customer JWT that was issued with the old password.
func FTPUpdatePassword(db *sql.DB, systemUser, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	enc, err := secret.Encrypt(password)
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`UPDATE ftp_accounts SET password_md5=?, ftp_password_enc=?, token_version=token_version+1 WHERE username=?`,
		hash, enc, systemUser)
	return err
}

// FTPPlainPassword returns the decrypted cleartext FTP password for a system
// user, read from ftp_password_enc. Used by the reveal endpoint and SSH sync.
// Returns "" (no error) when the account exists but has no stored encrypted copy.
func FTPPlainPassword(db *sql.DB, systemUser string) (string, error) {
	var enc sql.NullString
	err := db.QueryRow(
		`SELECT ftp_password_enc FROM ftp_accounts WHERE username=? AND status='active'`,
		systemUser).Scan(&enc)
	if err != nil {
		return "", err
	}
	if !enc.Valid || enc.String == "" {
		return "", nil
	}
	return secret.Decrypt(enc.String)
}

// FTPDelete explicitly removes an FTP account even though domain deletion cascades.
func FTPDelete(db *sql.DB, systemUser string) error {
	_, err := db.Exec(`DELETE FROM ftp_accounts WHERE username=?`, systemUser)
	return err
}

var (
	mysqlIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	mysqlPasswordPattern   = regexp.MustCompile(`^[ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789]{1,255}$`)
	mysqlSuffixPattern     = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
)

// ValidCustomerDBIdentifier reports whether a database identifier is safe and namespaced to a domain user.
func ValidCustomerDBIdentifier(systemUser, identifier string) bool {
	return mysqlIdentifierPattern.MatchString(systemUser) &&
		mysqlIdentifierPattern.MatchString(identifier) &&
		strings.HasPrefix(identifier, systemUser+"_")
}

// ValidDBSuffix reports whether a customer-provided database/user suffix is safe before the panel
// prepends the `<system_user>_` prefix. Only lowercase letters, digits, and underscore, 1-32 chars.
// The combined length (prefix + suffix) is additionally validated with mysqlIdentifierPattern.
func ValidDBSuffix(suffix string) bool {
	return mysqlSuffixPattern.MatchString(suffix)
}

// ValidDBIdentifier reports whether a database name or user is a valid MySQL identifier
// (alphanumeric + underscore, 1-64 chars). Used as a security gate before DROP operations.
func ValidDBIdentifier(name string) bool {
	return mysqlIdentifierPattern.MatchString(name)
}

// StrongPassword reports whether a customer-chosen database password is strong enough: at least
// 12 characters and a mix of letters and digits. The returned reason is English for API display.
func StrongPassword(password string) (bool, string) {
	if !ValidPassword(password) {
		return false, "password contains invalid characters (line breaks or control chars)"
	}
	if len([]rune(password)) < 12 {
		return false, "password must be at least 12 characters"
	}
	var hasLetter, hasDigit bool
	for _, r := range password {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return false, "password must contain both letters and digits"
	}
	return true, ""
}

func escapeSQLString(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `'`, `\'`)
}

// rootSQLTimeout bounds one privileged MariaDB client run. Without it a client
// waiting on a wedged server never returns: the chi Timeout middleware cancels
// the request context but leaves the subprocess running, so every database
// create, drop, or password change would pin a goroutine and a process for the
// life of the panel. It is generous because DROP DATABASE on a multi-gigabyte
// InnoDB schema legitimately takes minutes, and cutting that short would leave
// the schema half removed.
const rootSQLTimeout = 5 * time.Minute

// rootSQLCommand builds the privileged MariaDB client invocation. root@localhost
// authenticates through the unix_socket plugin, so the client needs no argument
// at all: it inherits the panel's own root identity from the socket peer.
// A variable so a test can substitute a stub and inspect what the process
// actually receives.
//
// The deadline is deliberately detached from the request context. These calls
// destroy and rebuild state (create the user, then record it; drop the schema,
// then delete the row), so a client that hangs up mid-flight must not truncate
// the run and strand a MySQL account with no panel record.
var rootSQLCommand = func() (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), rootSQLTimeout)
	// #nosec G204 G702 -- fixed binary with no arguments and no shell; the statements travel on stdin.
	return exec.CommandContext(ctx, "mysql"), cancel
}

// runRootSQL executes statements against MariaDB as the OS root user.
//
// The statements travel on stdin and must never be handed over as `mysql -e
// <sql>`: argv is world-readable through /proc/<pid>/cmdline, so a
// `CREATE USER ... IDENTIFIED BY '<password>'` line publishes the new database
// password to every local account for as long as the client runs. Tenants get
// arbitrary shell commands through cron, so that window is reachable, and the
// password works from any local process because MariaDB listens on 127.0.0.1.
// HashPassword feeds openssl on stdin for the same reason.
func runRootSQL(statements ...string) error {
	cmd, cancel := rootSQLCommand()
	defer cancel()
	cmd.Stdin = strings.NewReader(strings.Join(statements, "\n"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mysql: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// rootQueryCommand builds the privileged MariaDB client for a SELECT whose
// tab-separated output is read back (-N drops column names, -B is batch mode).
// root@localhost authenticates through the unix_socket plugin, exactly as
// rootSQLCommand. A variable so a test can substitute a stub. The request
// context bounds it: this is a read-only query, so cancelling it strands nothing.
var rootQueryCommand = func(ctx context.Context) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary, no shell; the query travels on stdin, not argv.
	return exec.CommandContext(ctx, "mysql", "-N", "-B")
}

// SchemaSizes returns the on-disk size (data_length+index_length, in bytes) of
// each named schema, keyed by schema name; a schema absent from the result has
// size 0.
//
// Only root over the unix socket can read information_schema.tables for a tenant
// schema. The panel connection ('panel'@'127.0.0.1', GRANT ALL on panel.* alone)
// sees none of them, so this cannot go through *sql.DB. The client's text output
// is parsed here, which internal/antivirus/dbscan deliberately refuses for a
// content scan, but the values here are schema NAMES (already validated to the
// c_<system_user>_ namespace) and integers, never tenant content. Every name is
// re-validated before it is interpolated, because information_schema takes no
// placeholder where a schema name goes.
func SchemaSizes(ctx context.Context, names []string) (map[string]int64, error) {
	quoted := make([]string, 0, len(names))
	for _, n := range names {
		if ValidDBIdentifier(n) {
			quoted = append(quoted, "'"+n+"'")
		}
	}
	if len(quoted) == 0 {
		return map[string]int64{}, nil
	}
	query := "SELECT table_schema, COALESCE(SUM(data_length+index_length),0) " +
		"FROM information_schema.tables WHERE table_schema IN (" +
		strings.Join(quoted, ",") + ") GROUP BY table_schema;"
	cmd := rootQueryCommand(ctx)
	cmd.Stdin = strings.NewReader(query)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("schema sizes: %w", err)
	}
	sizes := map[string]int64{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseInt(f[len(f)-1], 10, 64)
		sizes[f[0]] = v
	}
	return sizes, nil
}

// RunRootSQL executes statements against MariaDB as the OS root user.
//
// It is the single exported entry point for privileged SQL, so no other package
// grows a second `mysql -e ...` habit: argv is world-readable through
// /proc/<pid>/cmdline and a tenant reaches it through cron, while this runner
// feeds everything on stdin. Callers outside this package are responsible for
// validating whatever they interpolate; the runner cannot see the difference.
func RunRootSQL(statements ...string) error { return runRootSQL(statements...) }

// ErrInvalidMySQLCredentials indicates that a database name, user, or password is unsafe for SQL construction.
var ErrInvalidMySQLCredentials = errors.New("invalid MySQL credentials")

// MySQLCreateScopedUser creates an account privileged on exactly one schema.
//
// It exists so an untrusted SQL dump can be imported without touching the
// panel's own root connection. `mysql <db>` as root only selects a DEFAULT
// schema; it imposes no privilege boundary whatsoever, so statements inside the
// dump run with full server rights and a planted
//
//	USE mysql; CREATE USER ...; GRANT ALL PRIVILEGES ON *.* TO ...;
//
// hands over the whole database server. Filtering the dump text is not a
// substitute for the account, because the server accepts spellings a line
// filter does not recognize (`/*!50000 USE mysql */` among them). Let MariaDB
// enforce the boundary instead of trying to out-parse it.
//
// The grant is schema-scoped, so it also carries no GRANT OPTION and no FILE
// privilege: the dump cannot widen its own rights or reach the filesystem
// through `INTO OUTFILE`.
func MySQLCreateScopedUser(dbUser, dbPass, dbName string) error {
	if err := validateMySQLCredentials(dbName, dbUser, dbPass); err != nil {
		return err
	}
	return runRootSQL(
		fmt.Sprintf("CREATE USER '%s'@'localhost' IDENTIFIED BY '%s';", dbUser, escapeSQLString(dbPass)),
		fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost';", dbName, dbUser),
		"FLUSH PRIVILEGES;",
	)
}

// MySQLAddUser creates a MySQL account for an EXISTING database and grants it
// access, WITHOUT recording a db_accounts row (the caller updates its own row).
//
// It is used for a database that has a schema but no user, which happens when a
// database is deleted from the panel and restored from a backup: the archive
// carries schema and data, and a fresh account has to be attached so the site can
// connect. MySQLCreateDB cannot be reused because it INSERTs a db_accounts row,
// which for an already-registered database violates the unique key.
func MySQLAddUser(dbName, dbUser, dbPass string) error {
	if err := validateMySQLCredentials(dbName, dbUser, dbPass); err != nil {
		return err
	}
	return runRootSQL(
		fmt.Sprintf("CREATE USER IF NOT EXISTS '%s'@'localhost' IDENTIFIED BY '%s';", dbUser, escapeSQLString(dbPass)),
		fmt.Sprintf("ALTER USER '%s'@'localhost' IDENTIFIED BY '%s';", dbUser, escapeSQLString(dbPass)),
		fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost';", dbName, dbUser),
		"FLUSH PRIVILEGES;",
	)
}

// MySQLDropUser removes an account. It is idempotent so a caller can defer it
// without having to know whether creation got that far.
func MySQLDropUser(dbUser string) error {
	if !mysqlIdentifierPattern.MatchString(dbUser) {
		return fmt.Errorf("%w: database user", ErrInvalidMySQLCredentials)
	}
	return runRootSQL(fmt.Sprintf("DROP USER IF EXISTS '%s'@'localhost';", dbUser))
}

func validateMySQLCredentials(dbName, dbUser, dbPass string) error {
	if !mysqlIdentifierPattern.MatchString(dbName) {
		return fmt.Errorf("%w: database name", ErrInvalidMySQLCredentials)
	}
	if !mysqlIdentifierPattern.MatchString(dbUser) {
		return fmt.Errorf("%w: database user", ErrInvalidMySQLCredentials)
	}
	if !mysqlPasswordPattern.MatchString(dbPass) {
		return fmt.Errorf("%w: database password", ErrInvalidMySQLCredentials)
	}
	return nil
}

// MySQLCreateDB creates a MariaDB database and user, grants access, and records the account.
func MySQLCreateDB(db *sql.DB, domainID int64, dbName, dbUser, dbPass string) error {
	if err := validateMySQLCredentials(dbName, dbUser, dbPass); err != nil {
		return err
	}
	// Create the MariaDB database and user through root socket authentication.
	if err := runRootSQL(
		fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;", dbName),
		fmt.Sprintf("CREATE USER IF NOT EXISTS '%s'@'localhost' IDENTIFIED BY '%s';", dbUser, escapeSQLString(dbPass)),
		fmt.Sprintf("ALTER USER '%s'@'localhost' IDENTIFIED BY '%s';", dbUser, escapeSQLString(dbPass)),
		fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost';", dbName, dbUser),
		"FLUSH PRIVILEGES;",
	); err != nil {
		return err
	}

	// Record the account in the panel database. The password is encrypted at
	// rest (bound to the database user) so a leaked panel dump does not expose it.
	encPass, err := encryptDBPass(dbUser, dbPass)
	if err != nil {
		return fmt.Errorf("encrypt db password: %w", err)
	}
	_, err = db.Exec(
		`INSERT INTO db_accounts(domain_id, db_name, db_user, db_pass_plain, db_host)
		 VALUES(?,?,?,?, 'localhost')`,
		domainID, dbName, dbUser, encPass)
	return err
}

// MySQLCreateDBForUser creates a database and grants access to an EXISTING database user without
// touching that user's password (so other databases sharing the user are not broken). A new
// db_accounts row is inserted for this domain+database using the existing user's stored password
// (needed for phpMyAdmin single sign-on). The caller MUST first verify that dbUser belongs to this
// domain (ownership + prefix check).
func MySQLCreateDBForUser(db *sql.DB, domainID int64, dbName, dbUser string) error {
	if !mysqlIdentifierPattern.MatchString(dbName) || !mysqlIdentifierPattern.MatchString(dbUser) {
		return fmt.Errorf("%w: database name or user", ErrInvalidMySQLCredentials)
	}
	var stored string
	if err := db.QueryRow(
		`SELECT db_pass_plain FROM db_accounts WHERE db_user=? LIMIT 1`, dbUser).Scan(&stored); err != nil {
		return fmt.Errorf("existing user password not found: %w", err)
	}
	// Stored value may be ciphertext (bound to this same db_user) or legacy
	// plaintext; decrypt so the new row can be re-sealed consistently.
	pass, err := DecryptDBPass(dbUser, stored)
	if err != nil {
		return fmt.Errorf("decrypt existing db password: %w", err)
	}
	// Create the database and grant the existing user access. No CREATE/ALTER USER statement, so
	// the user's password is preserved.
	//
	// The grant goes to every host this user answers on, not only localhost.
	// A remote account is a separate account with separate grants, so skipping it
	// would let the customer connect from outside and then not see the database
	// they just created.
	statements := []string{
		fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;", dbName),
		fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost';", dbName, dbUser),
	}
	remote, err := remoteHostStatements(db, dbUser, func(host string) []string {
		return []string{fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%s';", dbName, dbUser, host)}
	})
	if err != nil {
		return fmt.Errorf("remote hosts: %w", err)
	}
	statements = append(statements, remote...)
	statements = append(statements, "FLUSH PRIVILEGES;")
	if err := runRootSQL(statements...); err != nil {
		return err
	}
	encPass, err := encryptDBPass(dbUser, pass)
	if err != nil {
		return fmt.Errorf("encrypt db password: %w", err)
	}
	_, err = db.Exec(
		`INSERT INTO db_accounts(domain_id, db_name, db_user, db_pass_plain, db_host)
		 VALUES(?,?,?,?, 'localhost')`,
		domainID, dbName, dbUser, encPass)
	return err
}

// MySQLDropDB removes a database and user, then deletes the account metadata.
func MySQLDropDB(db *sql.DB, dbName, dbUser string) error {
	if !mysqlIdentifierPattern.MatchString(dbName) {
		return fmt.Errorf("%w: database name", ErrInvalidMySQLCredentials)
	}
	if !mysqlIdentifierPattern.MatchString(dbUser) {
		return fmt.Errorf("%w: database user", ErrInvalidMySQLCredentials)
	}
	// The user goes away entirely here, so every host it answers on has to go
	// too. The db_remote_hosts row would be removed by the domain's cascade, but
	// a cascade cannot drop a MariaDB account: without this the credential
	// outlives the panel's record of it and still authenticates.
	statements := []string{
		fmt.Sprintf("DROP DATABASE IF EXISTS `%s`;", dbName),
		fmt.Sprintf("DROP USER IF EXISTS '%s'@'localhost';", dbUser),
	}
	remote, err := remoteHostStatements(db, dbUser, func(host string) []string {
		return []string{fmt.Sprintf("DROP USER IF EXISTS '%s'@'%s';", dbUser, host)}
	})
	if err != nil {
		return fmt.Errorf("remote hosts: %w", err)
	}
	statements = append(statements, remote...)
	statements = append(statements, "FLUSH PRIVILEGES;")
	if err := runRootSQL(statements...); err != nil {
		return err
	}
	if _, err := db.Exec(`DELETE FROM db_remote_hosts WHERE db_user=?`, dbUser); err != nil {
		return fmt.Errorf("remote host rows: %w", err)
	}
	_, err = db.Exec(`DELETE FROM db_accounts WHERE db_name=?`, dbName)
	return err
}

// MySQLDropDBKeepUser drops only the database and its metadata row, leaving the user intact. Use
// this for single-database deletion when the user is shared across other databases (existing-user
// mode), so the sharing databases keep their access.
func MySQLDropDBKeepUser(db *sql.DB, dbName string) error {
	if !mysqlIdentifierPattern.MatchString(dbName) {
		return fmt.Errorf("%w: database name", ErrInvalidMySQLCredentials)
	}
	if err := runRootSQL(fmt.Sprintf("DROP DATABASE IF EXISTS `%s`;", dbName)); err != nil {
		return err
	}
	_, err := db.Exec(`DELETE FROM db_accounts WHERE db_name=?`, dbName)
	return err
}

// MySQLDropAllForDomain removes every database account belonging to a deleted domain.
func MySQLDropAllForDomain(db *sql.DB, domainID int64) error {
	rows, err := db.Query(`SELECT db_name, db_user FROM db_accounts WHERE domain_id=?`, domainID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	// Continue past a single failure so remaining accounts are still dropped, but
	// accumulate errors: a swallowed drop leaves a live MySQL user/GRANT after the
	// domain is gone (credential not revoked), so the caller must be able to react.
	var errs []error
	for rows.Next() {
		var dbName, dbUser string
		if err := rows.Scan(&dbName, &dbUser); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := MySQLDropDB(db, dbName, dbUser); err != nil {
			errs = append(errs, fmt.Errorf("drop %s/%s: %w", dbName, dbUser, err))
		}
	}
	if err := rows.Err(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// SyncSSHPassword synchronizes the system account password with the FTP password.
// The plaintext is read from the AES-256-GCM encrypted ftp_password_enc column
// (password_md5 holds only a one-way hash and cannot be used for chpasswd).
func SyncSSHPassword(db *sql.DB, systemUser string) error {
	if !strings.HasPrefix(systemUser, "c_") {
		return fmt.Errorf("security: system user must have the c_ prefix")
	}
	password, err := FTPPlainPassword(db, systemUser)
	if err != nil {
		return fmt.Errorf("read FTP password: %w", err)
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("FTP password is empty")
	}
	if !ValidPassword(password) {
		return fmt.Errorf("security: FTP password contains invalid characters")
	}
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(systemUser + ":" + password)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chpasswd: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// LockSSHPassword locks the system password when SSH is disabled.
func LockSSHPassword(systemUser string) error {
	if !strings.HasPrefix(systemUser, "c_") {
		return fmt.Errorf("security: system user must have the c_ prefix")
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	out, err := exec.Command("passwd", "-l", systemUser).CombinedOutput()
	if err != nil {
		return fmt.Errorf("passwd -l: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}
