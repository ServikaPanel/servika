package credentials

import (
	"context"
	"os"
	"strings"
	"testing"
)

// OptimizeDatabase lists the schema's tables through the read-only client and
// then OPTIMIZEs them in one statement on the privileged client. The statement
// must name every table returned, backtick-quoted and schema-qualified.
func TestOptimizeDatabaseOptimizesEveryTable(t *testing.T) {
	stubRootQuery(t, "wp_posts\nwp_options\nwp_users\n")
	_, stdinPath := stubRootSQL(t, 0)

	if err := OptimizeDatabase(context.Background(), "c_site_wp"); err != nil {
		t.Fatalf("OptimizeDatabase: %v", err)
	}

	sql := readStub(t, stdinPath)
	if !strings.HasPrefix(strings.TrimSpace(sql), "OPTIMIZE TABLE ") {
		t.Errorf("statement is not an OPTIMIZE TABLE: %q", sql)
	}
	for _, table := range []string{"wp_posts", "wp_options", "wp_users"} {
		if !strings.Contains(sql, "`c_site_wp`.`"+table+"`") {
			t.Errorf("statement does not optimize %s: %q", table, sql)
		}
	}
}

// The table list comes from information_schema, which reports the name the
// TENANT gave the table, so a name that is not a plain identifier (one that
// could carry SQL through a doubled backtick) is skipped, never interpolated.
func TestOptimizeDatabaseSkipsAnUnsafeTableName(t *testing.T) {
	stubRootQuery(t, "wp_posts\nevil`; DROP DATABASE x; --\n")
	_, stdinPath := stubRootSQL(t, 0)

	if err := OptimizeDatabase(context.Background(), "c_site_wp"); err != nil {
		t.Fatalf("OptimizeDatabase: %v", err)
	}

	sql := readStub(t, stdinPath)
	if strings.Contains(sql, "DROP DATABASE") {
		t.Errorf("an unsafe table name reached the statement: %q", sql)
	}
	if !strings.Contains(sql, "`c_site_wp`.`wp_posts`") {
		t.Errorf("the safe table was not optimized: %q", sql)
	}
}

// An invalid schema name is refused before any client runs, because
// information_schema takes no placeholder where a schema name goes.
func TestOptimizeDatabaseRefusesAnInvalidSchema(t *testing.T) {
	if err := OptimizeDatabase(context.Background(), "bad'; DROP SCHEMA x; --"); err == nil {
		t.Fatal("OptimizeDatabase accepted an invalid schema name")
	}
}

// A schema with no tables is a no-op: nothing reaches the privileged client, so
// OPTIMIZE of an empty database does not fail.
func TestOptimizeDatabaseWithNoTablesIsANoOp(t *testing.T) {
	stubRootQuery(t, "")
	_, stdinPath := stubRootSQL(t, 0)

	if err := OptimizeDatabase(context.Background(), "c_site_empty"); err != nil {
		t.Fatalf("OptimizeDatabase: %v", err)
	}
	// The privileged client was never invoked, so its stdin capture file was
	// never created; anything else means a statement was sent for no tables.
	if _, err := os.Stat(stdinPath); !os.IsNotExist(err) {
		t.Errorf("an empty schema still invoked the OPTIMIZE client (stat err=%v)", err)
	}
}
