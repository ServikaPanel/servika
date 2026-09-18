package credentials

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"servika/internal/logx"
)

// HealGrantWildcards rewrites the grants written before GrantSchema existed.
//
// A grant whose schema pattern still carries a literal `_` or `%` reaches every
// schema the pattern matches, so one tenant's account can read a neighbour's
// database. Escaping the name fixes every NEW grant; the rows already in
// mysql.db keep the old pattern until they are rewritten, which is what this
// does. It runs at every boot and is idempotent: a row whose pattern already
// carries a backslash is left alone.
//
// Only a schema the panel itself owns (a db_accounts row) is touched, so a grant
// an operator added by hand is never rewritten.
func HealGrantWildcards(ctx context.Context, db *sql.DB) {
	owned, err := panelSchemas(ctx, db)
	if err != nil {
		logx.Errorf("grant wildcard heal: the panel databases could not be read: %v", err)
		return
	}
	if len(owned) == 0 {
		return
	}
	rows, err := wildcardGrantRows(ctx)
	if err != nil {
		logx.Errorf("grant wildcard heal: the grant table could not be read: %v", err)
		return
	}
	repaired := 0
	for _, g := range rows {
		if !owned[g.schema] {
			continue
		}
		if err := repairGrant(g); err != nil {
			logx.Errorf("grant wildcard heal: %s could not be repaired: %v", g.schema, err)
			continue
		}
		repaired++
	}
	if repaired > 0 {
		logx.Infof("grant wildcard heal: %d grants rewritten", repaired)
	}
}

// grantRow is one mysql.db row: the schema pattern and the account it privileges.
type grantRow struct {
	schema string
	user   string
	host   string
}

// panelSchemas returns the database names the panel manages, as a set.
func panelSchemas(ctx context.Context, db *sql.DB) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT db_name FROM db_accounts`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	owned := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		owned[name] = true
	}
	return owned, rows.Err()
}

// wildcardGrantRows lists the mysql.db rows whose schema pattern is still
// unescaped. Only root over the unix socket can read mysql.db, so this goes
// through the privileged client rather than the panel connection.
func wildcardGrantRows(ctx context.Context) ([]grantRow, error) {
	cmd := rootQueryCommand(ctx)
	cmd.Stdin = strings.NewReader("SELECT Db, User, Host FROM mysql.db;")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var list []grantRow
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) != 3 {
			continue
		}
		g := grantRow{schema: f[0], user: f[1], host: f[2]}
		if needsEscape(g) {
			list = append(list, g)
		}
	}
	return list, nil
}

// needsEscape reports whether a grant row still carries an unescaped wildcard
// and names values this package is willing to interpolate.
func needsEscape(g grantRow) bool {
	if !strings.ContainsAny(g.schema, "_%") || strings.Contains(g.schema, `\`) {
		return false
	}
	if !ValidDBIdentifier(g.schema) || !ValidDBIdentifier(g.user) {
		return false
	}
	return g.host == "localhost" || ValidRemoteHost(g.host)
}

// repairGrant replaces one unescaped grant with its escaped equivalent. The
// REVOKE names the pattern exactly as mysql.db stores it, so it removes that one
// row and no other.
func repairGrant(g grantRow) error {
	return runRootSQL(
		fmt.Sprintf("REVOKE ALL PRIVILEGES ON `%s`.* FROM '%s'@'%s';", g.schema, g.user, g.host),
		fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%s';", GrantSchema(g.schema), g.user, g.host),
		"FLUSH PRIVILEGES;",
	)
}
