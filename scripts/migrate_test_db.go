//go:build ignore

// Builds the panel schema in the database the live-database tests use:
//
//	SERVIKA_TEST_DSN='root@tcp(127.0.0.1:3306)/panel?parseTime=true' go run scripts/migrate_test_db.go
//
// Run it from the repository root. It applies migrations/ through the same
// runner the panel calls at startup, so the tests see the schema a server has
// rather than one rebuilt by a second, drifting path.
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
	// The DSN is read from the environment only. /proc/<pid>/cmdline is readable
	// by every local account, and a flag would publish the password there.
	dsn := os.Getenv("SERVIKA_TEST_DSN")
	if dsn == "" {
		log.Fatal("SERVIKA_TEST_DSN is not set")
	}

	// dbmigrate.Run logs an unreadable directory and returns nil, which is right
	// for a panel booting from a checkout. Here it would leave an empty schema,
	// and the failure would surface later as some unrelated live test missing a
	// table, so the directory is checked first.
	if _, err := os.ReadDir(migrationsDir); err != nil {
		log.Fatalf("the migrations directory could not be read (run from the repository root): %v", err)
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		log.Fatalf("ping: %v", err)
	}
	if err := dbmigrate.Run(db, migrationsDir); err != nil {
		log.Fatalf("migrations: %v", err)
	}
}
