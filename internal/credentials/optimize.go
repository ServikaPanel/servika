package credentials

import (
	"context"
	"fmt"
	"strings"
)

// schemaTables returns the base-table names in one schema.
//
// Only root over the unix socket can read information_schema for a tenant schema
// (the panel connection, 'panel'@'127.0.0.1' with GRANT ALL on panel.* alone,
// sees none of them), so this goes through the same privileged read-only client
// as SchemaSizes. The schema name is validated before it is interpolated,
// because information_schema takes no placeholder where a schema name goes, and
// every table name the view returns is re-validated too: that view reports the
// name the TENANT gave the table, and MariaDB accepts a backtick inside a quoted
// identifier, so a name that is not a plain identifier is skipped rather than
// interpolated.
func schemaTables(ctx context.Context, dbName string) ([]string, error) {
	if !ValidDBIdentifier(dbName) {
		return nil, ErrInvalidMySQLCredentials
	}
	query := "SELECT table_name FROM information_schema.tables " +
		"WHERE table_schema='" + dbName + "' AND table_type='BASE TABLE';"
	cmd := rootQueryCommand(ctx)
	cmd.Stdin = strings.NewReader(query)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	var tables []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		name := strings.TrimSpace(line)
		if name != "" && ValidDBIdentifier(name) {
			tables = append(tables, name)
		}
	}
	return tables, nil
}

// OptimizeDatabase runs OPTIMIZE TABLE on every base table in one schema.
//
// OPTIMIZE reclaims the space a fragmented table holds. The whole schema is
// optimized in one statement so the privileged client runs once. Nothing a
// customer typed reaches this: the schema name is validated here and every table
// name is re-validated in schemaTables, and both identifiers are backtick-quoted
// even though the validator already forbids a backtick. A schema with no tables
// is a no-op. Callers measure the on-disk size before and after with
// SchemaSizes; this only does the work.
func OptimizeDatabase(ctx context.Context, dbName string) error {
	if !ValidDBIdentifier(dbName) {
		return ErrInvalidMySQLCredentials
	}
	tables, err := schemaTables(ctx, dbName)
	if err != nil {
		return err
	}
	if len(tables) == 0 {
		return nil
	}
	quoted := make([]string, 0, len(tables))
	for _, name := range tables {
		quoted = append(quoted, "`"+dbName+"`.`"+name+"`")
	}
	return runRootSQL("OPTIMIZE TABLE " + strings.Join(quoted, ", ") + ";")
}
