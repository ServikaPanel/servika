package dbmigrate

// Live-database test for the two UPDATE statements in
// 0129_nginx_client_max_body.sql. Skipped without SERVIKA_TEST_DSN.
//
// The regular expressions are the whole risk in that file: one carries a plan's
// ceiling out of the customer-writable directive block, and the other strips the
// statement so the same directive joining the forbidden list does not refuse
// every save on a domain that already exists. Neither is exercised by anything a
// Go test can reach without MariaDB's own PCRE engine.

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

func migrationDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("SERVIKA_TEST_DSN")
	if dsn == "" {
		t.Skip("SERVIKA_TEST_DSN is not set")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// The statements are run against a scratch table with the same two columns, so
// the test never touches a real nginx_settings row.
const scratchTable = "servika_test_client_max_body"

// withoutLeadingComments drops the blank and `--` lines a statement carries in
// front of it, so the statement itself can be recognised by its first word.
func withoutLeadingComments(statement string) string {
	lines := strings.Split(statement, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		return strings.TrimSpace(strings.Join(lines[i:], "\n"))
	}
	return ""
}

// migrationUpdates reads the UPDATE statements out of the migration itself and
// retargets them at the scratch table.
//
// They are READ rather than copied, because a test holding its own copy of the
// regular expressions would keep passing after somebody changed the file, which
// is exactly the case it exists to catch.
func migrationUpdates(t *testing.T) []string {
	t.Helper()
	body, err := os.ReadFile("../../migrations/0129_nginx_client_max_body.sql")
	if err != nil {
		t.Fatalf("read the migration: %v", err)
	}
	var updates []string
	for statement := range strings.SplitSeq(string(body), ";\n") {
		trimmed := withoutLeadingComments(statement)
		if !strings.HasPrefix(trimmed, "UPDATE nginx_settings") {
			continue
		}
		updates = append(updates, strings.Replace(trimmed, "nginx_settings", scratchTable, 1))
	}
	if len(updates) != 2 {
		t.Fatalf("the migration holds %d UPDATE statements, want the copy and the strip", len(updates))
	}
	return updates
}

func TestTheCeilingMigrationMovesEveryUnitAndStripsTheStatement(t *testing.T) {
	db := migrationDB(t)

	drop := func() {
		if _, err := db.Exec(`DROP TABLE IF EXISTS ` + scratchTable); err != nil {
			t.Fatalf("drop scratch table: %v", err)
		}
	}
	drop()
	t.Cleanup(drop)

	if _, err := db.Exec(`CREATE TABLE ` + scratchTable + ` (
		id INT PRIMARY KEY,
		extra_directives TEXT NOT NULL,
		client_max_body VARCHAR(16) NOT NULL DEFAULT ''
	)`); err != nil {
		t.Fatalf("create scratch table: %v", err)
	}

	cases := []struct {
		id            int
		before        string
		wantCeiling   string
		wantRemaining string
	}{
		{
			id:            1,
			before:        "client_max_body_size 8192m;\n",
			wantCeiling:   "8192m",
			wantRemaining: "",
		},
		{
			// A row an operator edited by hand may name any unit. Reading the value
			// as megabytes would drop this one to zero and put nginx's own 1m
			// default in force without saying so.
			id:            2,
			before:        "client_max_body_size 500k;\nadd_header X-Test safe;",
			wantCeiling:   "500k",
			wantRemaining: "add_header X-Test safe;",
		},
		{
			id:            3,
			before:        "add_header X-First yes;\nclient_max_body_size 2g;\nadd_header X-Last yes;",
			wantCeiling:   "2g",
			wantRemaining: "add_header X-First yes;\nadd_header X-Last yes;",
		},
		{
			// nginx accepts a bare byte count.
			id:            4,
			before:        "client_max_body_size 1048576;",
			wantCeiling:   "1048576",
			wantRemaining: "",
		},
		{
			// A row that never carried the directive keeps its text and stays empty.
			id:            5,
			before:        "add_header X-Test safe;",
			wantCeiling:   "",
			wantRemaining: "add_header X-Test safe;",
		},
	}

	for _, tc := range cases {
		if _, err := db.Exec(
			`INSERT INTO `+scratchTable+`(id, extra_directives) VALUES(?,?)`, tc.id, tc.before); err != nil {
			t.Fatalf("insert row %d: %v", tc.id, err)
		}
	}

	for i, statement := range migrationUpdates(t) {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("migration UPDATE %d: %v\n%s", i+1, err, statement)
		}
	}

	for _, tc := range cases {
		var ceiling, remaining string
		if err := db.QueryRow(
			`SELECT client_max_body, extra_directives FROM `+scratchTable+` WHERE id=?`, tc.id).
			Scan(&ceiling, &remaining); err != nil {
			t.Fatalf("read row %d: %v", tc.id, err)
		}
		if ceiling != tc.wantCeiling {
			t.Errorf("row %d ceiling = %q, want %q", tc.id, ceiling, tc.wantCeiling)
		}
		if remaining != tc.wantRemaining {
			t.Errorf("row %d remaining directives = %q, want %q", tc.id, remaining, tc.wantRemaining)
		}
		// The point of the strip: a row still naming the directive would be refused
		// the moment the customer pressed save, because it is now forbidden.
		if strings.Contains(remaining, "client_max_body_size") {
			t.Errorf("row %d still states the forbidden directive: %q", tc.id, remaining)
		}
	}
}
