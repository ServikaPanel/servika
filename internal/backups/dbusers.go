// Database USER and GRANT capture for a domain archive.
//
// mysqldump takes SCHEMA and DATA only. CREATE USER and GRANT statements live in
// the server's own `mysql` schema and never entered a tenant archive, so a
// database dropped and restored from backup came back with its tables but WITHOUT
// the account the site connects as: the restore was technically successful while
// the site kept returning 500. This file closes that gap by writing the owning
// accounts (with their password hash) into __db__/users.sql and applying them on
// restore, so a new archive brings the site back up with no file edit.
//
// Old archives predate the file. Their identity is recovered by the operator
// through the panel's "Create User" path, not by reading the tenant's own
// configuration.
package backups

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"servika/internal/credentials"
)

// dbUsersFileName is the archive member holding the user/GRANT dump.
const dbUsersFileName = "users.sql"

// dbAccount is a MySQL account (User@Host) with a grant on a database.
type dbAccount struct{ User, Host string }

// systemDBUser reports accounts that must never enter or leave a tenant archive.
func systemDBUser(u string) bool {
	l := strings.ToLower(strings.TrimSpace(u))
	if strings.HasPrefix(l, "mysql.") || strings.HasPrefix(l, "mariadb.") {
		return true
	}
	switch l {
	case "root", "debian-sys-maint", "", "panel":
		return true
	}
	return false
}

// mysqlQuery runs a root-socket query and returns its non-empty, trimmed lines.
// It goes through newRestoreCommand so the panel's own secret-bearing environment
// is never inherited by the subprocess.
func mysqlQuery(ctx context.Context, query string) ([]string, error) {
	out, err := newRestoreCommand(ctx, "mysql", "-N", "-B", "-e", query).Output()
	if err != nil {
		return nil, err
	}
	var lines []string
	for l := range strings.SplitSeq(string(out), "\n") {
		if l = strings.TrimRight(l, "\r"); strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

// mysqlExec runs one statement through the root socket (no shell).
func mysqlExec(ctx context.Context, statement string) error {
	if out, err := newRestoreCommand(ctx, "mysql", "-e", statement).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// sqlSingleQuoteEscape escapes a value for a single-quoted SQL string.
func sqlSingleQuoteEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `'`, `\'`)
}

// oneLine collapses line breaks so the file's "one statement per line" contract
// holds; a multi-line value would otherwise break the line-based apply.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSuffix(strings.TrimSpace(s), ";")
}

// accountsForDB returns the accounts holding a grant on a database. The mysql.db
// Db column may store the underscore escaped (name\_x) depending on how the grant
// was written, so both spellings are matched. The dbName is a validated
// identifier, so interpolating it into the query is safe.
func accountsForDB(ctx context.Context, dbName string) []dbAccount {
	if !credentials.ValidDBIdentifier(dbName) {
		return nil
	}
	query := fmt.Sprintf(
		"SELECT User,Host FROM mysql.db WHERE Db='%s' OR REPLACE(Db,'\\\\_','_')='%s'",
		dbName, dbName)
	lines, err := mysqlQuery(ctx, query)
	if err != nil {
		return nil
	}
	var out []dbAccount
	for _, l := range lines {
		p := strings.Split(l, "\t")
		if len(p) != 2 || systemDBUser(p[0]) || !credentials.ValidDBIdentifier(p[0]) {
			continue
		}
		out = append(out, dbAccount{User: p[0], Host: p[1]})
	}
	return out
}

// grantAllowed reports whether a SHOW GRANTS line may enter the archive OR be
// applied from it.
//
// Security: an archive can arrive from outside (a site migration), so a GRANT it
// carries must never widen privilege. `ON *.*` is accepted only as bare USAGE,
// which is how MariaDB carries the account's password on that line; every other
// *.* grant and every database outside the allowlist is refused. Otherwise a
// crafted archive could grant SUPER or GRANT OPTION.
func grantAllowed(line string, allow map[string]bool) bool {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, "GRANT ") {
		return false
	}
	i := strings.Index(s, " ON ")
	if i < 0 {
		return false
	}
	privileges := strings.TrimSpace(s[len("GRANT "):i])
	target := strings.TrimSpace(s[i+len(" ON "):])
	if strings.HasPrefix(target, "*.*") {
		return strings.EqualFold(privileges, "USAGE")
	}
	if !strings.HasPrefix(target, "`") {
		return false
	}
	end := strings.Index(target[1:], "`")
	if end < 0 {
		return false
	}
	name := strings.ReplaceAll(target[1:1+end], `\_`, "_")
	return allow[name]
}

// accountStatements builds one account's CREATE USER + filtered GRANT lines.
func accountStatements(ctx context.Context, a dbAccount, allow map[string]bool) []string {
	target := fmt.Sprintf("'%s'@'%s'", a.User, sqlSingleQuoteEscape(a.Host))
	var out []string
	if lines, err := mysqlQuery(ctx, "SHOW CREATE USER "+target); err == nil && len(lines) > 0 {
		c := strings.TrimSpace(lines[0])
		if rest, ok := strings.CutPrefix(c, "CREATE USER "); ok {
			out = append(out, oneLine("CREATE USER IF NOT EXISTS "+rest)+";")
		}
	}
	lines, err := mysqlQuery(ctx, "SHOW GRANTS FOR "+target)
	if err != nil {
		return out
	}
	for _, g := range lines {
		if grantAllowed(g, allow) {
			out = append(out, oneLine(strings.TrimSpace(g))+";")
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// writeDBUsers writes __db__/users.sql for the given databases and returns the
// number of distinct accounts written. The file carries password hashes, so it is
// 0600, the same secrecy class as the rest of the archive's __db__ dumps.
func writeDBUsers(ctx context.Context, dbDir string, dbNames []string) int {
	allow := map[string]bool{}
	for _, n := range dbNames {
		allow[n] = true
	}
	seen := map[string]bool{}
	var body []string
	for _, dbName := range dbNames {
		for _, a := range accountsForDB(ctx, dbName) {
			key := a.User + "@" + a.Host
			if seen[key] {
				continue
			}
			seen[key] = true
			body = append(body, accountStatements(ctx, a, allow)...)
		}
	}
	if len(body) == 0 {
		return 0
	}
	header := "-- servika: database users and grants\n" +
		"-- On restore only grants on this archive's own databases are applied.\n"
	// #nosec G306 G703 -- root-owned backup staging file under BackupRoot (0700), path derived from a validated systemUser; the file carries hashes, hence 0600.
	_ = os.WriteFile(filepath.Join(dbDir, dbUsersFileName),
		[]byte(header+strings.Join(body, "\n")+"\n"), 0600)
	return len(seen)
}

// applyDBUsers applies __db__/users.sql. Every statement is re-validated on read,
// because the archive may have come from outside (a site migration): filtering on
// write is not enough.
func applyDBUsers(ctx context.Context, dbDir string, allow map[string]bool) (int, error) {
	// #nosec G304 G703 -- dbDir is a server-internal restore staging path under the panel temp dir; the file name is a fixed constant.
	raw, err := os.ReadFile(filepath.Join(dbDir, dbUsersFileName))
	if err != nil {
		return 0, err
	}
	n := 0
	for line := range strings.SplitSeq(string(raw), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "--") {
			continue
		}
		s = strings.TrimSuffix(s, ";")
		// Chained statement: `mysql -e` runs several `;`-separated statements. A
		// second statement could be appended after a grant that passes the line
		// filter, e.g.  GRANT ... ON `allowed`.* ...; GRANT ALL ON *.* ...
		// The filter inspects the first statement and accepts it while mysql runs
		// BOTH. A legitimate line (hash, host, privilege list) carries no semicolon,
		// so any line still holding one after the trailing-semicolon trim is refused.
		if strings.Contains(s, ";") {
			// #nosec G706 -- the value is bounded and comes from a root-produced archive file, not a live client request.
			log.Printf("backup: users.sql chained statement refused: %.80s", s)
			continue
		}
		switch {
		case strings.HasPrefix(s, "CREATE USER IF NOT EXISTS "):
		case grantAllowed(s, allow):
		default:
			// #nosec G706 -- the value is bounded and comes from a root-produced archive file, not a live client request.
			log.Printf("backup: users.sql statement refused: %.80s", s)
			continue
		}
		if err := mysqlExec(ctx, s+";"); err != nil {
			// #nosec G706 -- the value is bounded and comes from a root-produced archive file, not a live client request.
			log.Printf("backup: users.sql statement could not be applied (%.60s): %v", s, err)
			continue
		}
		n++
	}
	if n > 0 {
		_ = mysqlExec(ctx, "FLUSH PRIVILEGES;")
	}
	return n, nil
}
