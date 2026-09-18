//go:build ignore

// Proves that applying migrations/ a SECOND time changes nothing:
//
//	SERVIKA_TEST_DSN='root@tcp(127.0.0.1:3306)/panel?parseTime=true' go run scripts/migrate_idempotency.go
//
// Run it after scripts/migrate_test_db.go, from the repository root.
//
// The panel calls dbmigrate.Run on EVERY boot. What makes that safe is the
// ledger: a file whose checksum is already in schema_migrations is skipped. A
// change that breaks the ledger does not fail the first install, which is the
// only thing a clean-install gate exercises; it fails the next restart of every
// server in the field, with a duplicate-object error naming a migration that is
// correct.
//
// So this checks the three things a healthy second pass must show:
//
//   - the run returns no error,
//   - schema_migrations has exactly the rows it had before, and
//   - schema_migration_progress is empty, because a row there means a file
//     stopped part way through.
package main

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"

	"servika/internal/dbmigrate"
)

const migrationsDir = "migrations"

func main() {
	dsn := os.Getenv("SERVIKA_TEST_DSN")
	if dsn == "" {
		log.Fatal("SERVIKA_TEST_DSN is not set")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		log.Fatalf("ping: %v", err)
	}

	before := countRows(db, "schema_migrations")
	if before == 0 {
		log.Fatal("schema_migrations is empty: run scripts/migrate_test_db.go first")
	}

	if err := dbmigrate.Run(db, migrationsDir); err != nil {
		log.Fatalf("the second pass failed, so a restart would fail on every server: %v", err)
	}

	after := countRows(db, "schema_migrations")
	if after != before {
		log.Fatalf("the second pass applied something: schema_migrations went from %d rows to %d", before, after)
	}
	if pending := countRows(db, "schema_migration_progress"); pending != 0 {
		log.Fatalf("%d migration(s) stopped part way through; schema_migration_progress must be empty", pending)
	}
	log.Printf("migration idempotency: %d applied migrations, the second pass changed nothing", after)
}

func countRows(db *sql.DB, table string) int {
	var n int
	// #nosec G202 -- table is one of two constants named in this file, never input.
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		log.Fatalf("count %s: %v", table, err)
	}
	return n
}
