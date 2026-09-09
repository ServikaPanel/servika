// Identity recovery for a database that was restored without its account.
//
// A restore rebuilds a schema and its data. It does not rebuild the MySQL
// account the site connects with, and there are two ways that account can be
// missing. The archive may predate __db__/users.sql, or the database may have
// been deleted from the panel, which drops its db_accounts row: the restore path
// re-registers such a database with an EMPTY db_user and db_pass_plain, so the
// data is back and the site still answers "Access denied".
//
// This file closes that gap from the two sources that already know the answer.
// MySQL itself is asked first, because applying users.sql recreates the account
// and the panel record is then the only thing out of date. Only when MySQL has
// no account for the database is the site's own configuration read, which is the
// one remaining place the original user and password exist.
package backups

import (
	"context"
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"servika/internal/credentials"
	"servika/internal/files"
)

const (
	// configReadLimit bounds one configuration file. A wp-config.php is a few
	// kilobytes; the limit exists because the file belongs to the tenant and its
	// size is theirs to choose.
	configReadLimit = 512 * 1024
	// configScanDirs bounds how many subdirectories under the document root are
	// looked at, so the cost of a restore does not follow the size of the tree.
	configScanDirs = 40
)

// completeIdentity gives a just-restored database a usable account and panel
// record. It returns extra text for the restore result, empty when it could not
// add anything, and never fails the restore: the data is already back and a
// missing user is something the operator can still set by hand.
func completeIdentity(ctx context.Context, db *sql.DB, domainID int64, systemUser, dbName string) string {
	// The name can come from a member name inside the archive, and an archive can
	// arrive from outside the panel through a site migration. Everything below
	// interpolates it into SQL through credentials, which validates again, but an
	// invalid name means there is nothing to recover rather than something to try.
	if !credentials.ValidDBIdentifier(dbName) {
		log.Printf("backups: identity recovery refused an invalid database name: %.60q", dbName)
		return ""
	}

	// users.sql may already have recreated the account. Then only the panel record
	// is behind, and the password is not recoverable from MySQL (it stores a hash),
	// so the record is completed with the user alone.
	if accounts := accountsForDB(ctx, dbName); len(accounts) > 0 {
		user := accounts[0].User
		updatePanelRecord(db, domainID, dbName, user, "")
		return "user " + user + " restored"
	}

	user, password, source := appIdentity(systemUser, dbName)
	if user == "" {
		return ""
	}
	// MySQLAddUser validates the triple again and is the only place this package
	// creates an account, so no CREATE USER statement is built here.
	if err := credentials.MySQLAddUser(dbName, user, password); err != nil {
		log.Printf("backups: identity recovery for %q failed: %v", dbName, err)
		return ""
	}
	updatePanelRecord(db, domainID, dbName, user, password)
	log.Printf("backups: recovered the account for %q from the site's own configuration", dbName)
	return "user " + user + " recovered from the site configuration (" + source + ")"
}

// updatePanelRecord completes the db_accounts row. With a password it writes
// both fields; without one it writes the user and only while the row still has
// none, so a record an operator already fixed is left alone.
func updatePanelRecord(db *sql.DB, domainID int64, dbName, user, password string) {
	if password == "" {
		if _, err := db.Exec(
			`UPDATE db_accounts SET db_user=? WHERE domain_id=? AND db_name=? AND (db_user='' OR db_user IS NULL)`,
			user, domainID, dbName); err != nil {
			log.Printf("backups: could not record the recovered user for %q: %v", dbName, err)
		}
		return
	}
	sealed, err := credentials.EncryptDBPass(user, password)
	if err != nil {
		log.Printf("backups: could not seal the recovered password for %q: %v", dbName, err)
		return
	}
	if _, err := db.Exec(
		`UPDATE db_accounts SET db_user=?, db_pass_plain=? WHERE domain_id=? AND db_name=?`,
		user, sealed, domainID, dbName); err != nil {
		log.Printf("backups: could not record the recovered account for %q: %v", dbName, err)
	}
}

// appIdentity looks for a configuration under the tenant's home that names this
// database, and returns the credentials it carries. The empty user means nothing
// usable was found.
//
// The files belong to the TENANT, who can replace any of them with a symlink at
// /etc/shadow and have the panel read it as root. Every read therefore goes
// through files.ReadFileBeneath, which resolves the whole path with openat2 under
// RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS, refuses anything that is not a regular
// file, and stops at the byte limit. On a platform without openat2 the read
// fails and recovery simply reports nothing, which is what it did before.
func appIdentity(systemUser, dbName string) (user, password, source string) {
	home := filepath.Join("/home", systemUser)
	for _, rel := range candidateConfigs(home) {
		raw, err := files.ReadFileBeneath(home, rel, configReadLimit)
		if err != nil {
			continue
		}
		var name, u, p string
		if strings.HasSuffix(rel, ".env") {
			name, u, p = parseDotEnv(string(raw))
		} else {
			name, u, p = parseWPConfig(string(raw))
		}
		// The configuration has to name THIS database, or it belongs to another
		// site under the same home and its account has no grant here.
		if name != dbName || u == "" {
			continue
		}
		if !credentials.ValidDBIdentifier(u) || systemDBUser(u) {
			continue
		}
		return u, p, rel
	}
	return "", "", ""
}

// candidateConfigs lists the relative paths worth opening: the document root and
// one level below it. There is no deep walk, because the cost of a restore must
// not follow the size of the tenant's tree.
func candidateConfigs(home string) []string {
	const base = "public_html"
	names := []string{"wp-config.php", ".env"}
	out := make([]string, 0, len(names)*(configScanDirs+1))
	for _, n := range names {
		out = append(out, base+"/"+n)
	}
	// #nosec G703 -- home is /home/<validated system user>; the entry names are only used to build a relative path that ReadFileBeneath resolves under that home.
	entries, err := os.ReadDir(filepath.Join(home, base))
	if err != nil {
		return out
	}
	seen := 0
	for _, e := range entries {
		// A symlinked directory is skipped here as well, even though
		// ReadFileBeneath would refuse to follow it, so the listing cost stays on
		// real directories.
		if !e.IsDir() || e.Type()&os.ModeSymlink != 0 || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if seen++; seen > configScanDirs {
			break
		}
		for _, n := range names {
			out = append(out, base+"/"+e.Name()+"/"+n)
		}
	}
	return out
}

// wpConfigPattern matches a WordPress define() for the three values that matter.
//
// The value alternatives are separate on purpose. RE2 has no backreference, so a
// single ['"] class would let a quote INSIDE the value close it: a password of
// p@ss"word read back as p@ss, and the account would be created with a password
// the site does not use. Matching the opening quote against its own closing one
// keeps the value whole.
var wpConfigPattern = regexp.MustCompile(
	`(?i)define\(\s*['"]DB_(NAME|USER|PASSWORD)['"]\s*,\s*` +
		`(?:'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)")`)

// dotEnvPattern matches the Laravel-style keys for the same three values.
var dotEnvPattern = regexp.MustCompile(`(?m)^\s*DB_(DATABASE|USERNAME|PASSWORD)\s*=\s*(.*)$`)

// phpUnescape undoes the escapes PHP allows in a single- or double-quoted
// string. A password carrying a quote or a backslash is written escaped, and
// creating the account with the escaped form would not match the running site.
var phpUnescape = strings.NewReplacer(`\'`, `'`, `\"`, `"`, `\\`, `\`)

// parseWPConfig reads DB_NAME, DB_USER and DB_PASSWORD out of a wp-config.php.
func parseWPConfig(s string) (name, user, password string) {
	for _, m := range wpConfigPattern.FindAllStringSubmatch(s, -1) {
		// Exactly one of the two value groups matched; the other is empty.
		v := phpUnescape.Replace(m[2] + m[3])
		switch strings.ToUpper(m[1]) {
		case "NAME":
			name = v
		case "USER":
			user = v
		case "PASSWORD":
			password = v
		}
	}
	return name, user, password
}

// parseDotEnv reads DB_DATABASE, DB_USERNAME and DB_PASSWORD out of a .env.
func parseDotEnv(s string) (name, user, password string) {
	clean := func(v string) string {
		v = strings.TrimSpace(v)
		// A trailing comment is only a comment when a space precedes the #, so a
		// password containing # is not cut short.
		if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		return v
	}
	for _, m := range dotEnvPattern.FindAllStringSubmatch(s, -1) {
		switch strings.ToUpper(m[1]) {
		case "DATABASE":
			name = clean(m[2])
		case "USERNAME":
			user = clean(m[2])
		case "PASSWORD":
			password = clean(m[2])
		}
	}
	return name, user, password
}
