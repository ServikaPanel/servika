package dbmigrate

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

// openTestDB reaches the throwaway MariaDB the repository's live-database tests
// use. Without SERVIKA_TEST_DSN the package still reports ok, so a change to the
// runner's SQL has to be run with the variable set.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("SERVIKA_TEST_DSN")
	if dsn == "" {
		t.Skip("SERVIKA_TEST_DSN is not set")
	}
	d, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := d.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	// The bookkeeping tables are shared with the panel's own schema, which the
	// other live-database tests need applied. Only this package's own rows and
	// probe tables are cleared, never the tables themselves.
	if err := ensureTables(d); err != nil {
		t.Fatalf("ensure tables: %v", err)
	}
	clearProbe(t, d)
	t.Cleanup(func() { clearProbe(t, d) })
	return d
}

const probeFile = "0001_probe.sql"

func clearProbe(t *testing.T, d *sql.DB) {
	t.Helper()
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS mig_probe_two`,
		`DROP TABLE IF EXISTS mig_probe_one`,
		`DELETE FROM schema_migration_progress WHERE filename='` + probeFile + `'`,
		`DELETE FROM schema_migrations WHERE filename='` + probeFile + `'`,
	} {
		if _, err := d.Exec(stmt); err != nil {
			t.Fatalf("reset %q: %v", stmt, err)
		}
	}
}

func writeMigration(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func tableExists(t *testing.T, d *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := d.QueryRow(
		`SELECT COUNT(*) FROM information_schema.tables
		 WHERE table_schema = DATABASE() AND table_name = ?`, name).Scan(&n); err != nil {
		t.Fatalf("table lookup %s: %v", name, err)
	}
	return n == 1
}

func progressOf(t *testing.T, d *sql.DB, name string) (int, bool) {
	t.Helper()
	var done int
	err := d.QueryRow(
		`SELECT statements_done FROM schema_migration_progress WHERE filename=?`, name).Scan(&done)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false
	}
	if err != nil {
		t.Fatalf("progress lookup: %v", err)
	}
	return done, true
}

const brokenBody = `CREATE TABLE mig_probe_one (id INT PRIMARY KEY);
THIS IS NOT SQL;
`

const repairedBody = `CREATE TABLE mig_probe_one (id INT PRIMARY KEY);
CREATE TABLE mig_probe_two (id INT PRIMARY KEY);
`

// A migration that fails part way through must leave a resume point behind, and
// must not be recorded as applied. MariaDB commits DDL implicitly, so the first
// statement really is on disk whatever the runner does about it.
func TestAFailedMigrationRecordsWhereItStopped(t *testing.T) {
	d := openTestDB(t)
	dir := t.TempDir()
	writeMigration(t, dir, probeFile, brokenBody)

	if err := Run(d, dir); err == nil {
		t.Fatal("a broken migration reported success")
	}
	if !tableExists(t, d, "mig_probe_one") {
		t.Error("the first statement did not commit, so there is nothing to resume from")
	}
	var applied int
	if err := d.QueryRow(
		`SELECT COUNT(*) FROM schema_migrations WHERE filename=?`, probeFile).Scan(&applied); err != nil {
		t.Fatalf("count applied: %v", err)
	}
	if applied != 0 {
		t.Errorf("applied rows: want 0, got %d", applied)
	}
	done, ok := progressOf(t, d, probeFile)
	if !ok {
		t.Fatal("no progress row was written")
	}
	if done != 1 {
		t.Errorf("statements_done: want 1, got %d", done)
	}
}

// The repair: a second run resumes at the statement that failed. The old runner
// re-ran the file from the first statement, which answered "table already
// exists" and made the panel unstartable for good.
func TestASecondRunResumesInsteadOfRepeatingTheFirstStatement(t *testing.T) {
	d := openTestDB(t)
	dir := t.TempDir()
	writeMigration(t, dir, probeFile, brokenBody)
	if err := Run(d, dir); err == nil {
		t.Fatal("a broken migration reported success")
	}

	writeMigration(t, dir, probeFile, repairedBody)
	if err := Run(d, dir); err != nil {
		t.Fatalf("the resumed migration failed: %v", err)
	}

	if !tableExists(t, d, "mig_probe_two") {
		t.Error("the remaining statement did not run")
	}
	var applied int
	if err := d.QueryRow(
		`SELECT COUNT(*) FROM schema_migrations WHERE filename=?`, probeFile).Scan(&applied); err != nil {
		t.Fatalf("count applied: %v", err)
	}
	if applied != 1 {
		t.Errorf("applied rows: want 1, got %d", applied)
	}
	if _, ok := progressOf(t, d, probeFile); ok {
		t.Error("the progress row survived a completed migration")
	}
}

// Resuming is only safe while the file is the one whose head already committed.
func TestResumeIsRefusedWhenTheFileChangedShape(t *testing.T) {
	d := openTestDB(t)
	dir := t.TempDir()
	writeMigration(t, dir, probeFile, brokenBody)
	if err := Run(d, dir); err == nil {
		t.Fatal("a broken migration reported success")
	}

	// A different file that still fails, so the run cannot end by succeeding.
	writeMigration(t, dir, probeFile,
		"CREATE TABLE mig_probe_two (id INT PRIMARY KEY);\nSTILL NOT SQL;\n")
	err := Run(d, dir)
	if !errors.Is(err, ErrResumeRefused) {
		t.Errorf("want ErrResumeRefused, got %v", err)
	}
	if tableExists(t, d, "mig_probe_two") {
		t.Error("the refused resume executed a statement anyway")
	}
}

// A migration that never fails must leave the progress table empty, so a healthy
// server carries no rows there at all.
func TestAHealthyMigrationLeavesNoProgressRow(t *testing.T) {
	d := openTestDB(t)
	dir := t.TempDir()
	writeMigration(t, dir, probeFile, repairedBody)

	if err := Run(d, dir); err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	if _, ok := progressOf(t, d, probeFile); ok {
		t.Error("a healthy migration left a progress row behind")
	}
}

// An applied file whose contents changed still stops startup, so the extraction
// did not drop the checksum guard.
func TestAnEditedAppliedMigrationIsStillRefused(t *testing.T) {
	d := openTestDB(t)
	dir := t.TempDir()
	writeMigration(t, dir, probeFile, repairedBody)
	if err := Run(d, dir); err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	writeMigration(t, dir, probeFile, repairedBody+"-- edited\n")
	if err := Run(d, dir); err == nil {
		t.Error("an edited applied migration reported success")
	}
}
