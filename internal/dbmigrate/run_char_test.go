package dbmigrate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The runner decides, on every boot, which SQL files a server has already run.
// The live-database tests above cover it only with SERVIKA_TEST_DSN set, so
// nothing here was measured on a laptop. These tests drive Run against a
// scripted driver and a temporary directory, so every branch of the decision is
// pinned: what counts as a migration file, what a legacy row means, what an
// edited file means, and where a failed file records its resume point.

// runScript answers the four statements the runner makes and records them.
type runScript struct {
	// applied is the schema_migrations content, as filename and checksum pairs.
	applied [][]driver.Value
	// progress is the stored resume point, as checksum and statements_done.
	// A nil entry means the file has no progress row.
	progress []driver.Value
	// failExec fails the first Exec whose text carries the fragment.
	failExec map[string]error
	// failQuery fails the Query whose text carries the fragment.
	failQuery map[string]error

	execs    []string
	execArgs [][]driver.Value
	queries  []string
}

// ran reports whether any recorded statement carries the fragment.
func (s *runScript) ran(fragment string) bool {
	for _, statement := range s.execs {
		if strings.Contains(statement, fragment) {
			return true
		}
	}
	return false
}

// order names the recorded statements of a whole migration, in the order they
// ran.
func (s *runScript) order() []string {
	var order []string
	for _, statement := range s.execs {
		switch {
		case strings.Contains(statement, "mig_one"):
			order = append(order, "one")
		case strings.Contains(statement, "mig_two"):
			order = append(order, "two")
		case strings.Contains(statement, "INSERT INTO schema_migrations"):
			order = append(order, "applied")
		case strings.Contains(statement, "DELETE FROM schema_migration_progress"):
			order = append(order, "cleared")
		}
	}
	return order
}

// argsOf returns the arguments of the first recorded statement carrying the
// fragment.
func (s *runScript) argsOf(t *testing.T, fragment string) []driver.Value {
	t.Helper()
	for i, statement := range s.execs {
		if strings.Contains(statement, fragment) {
			return s.execArgs[i]
		}
	}
	t.Fatalf("no statement carries %q: %v", fragment, s.execs)
	return nil
}

type runConn struct{ script *runScript }

func (c runConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c runConn) Driver() driver.Driver                        { return runDriver{} }
func (c runConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c runConn) Close() error                                 { return nil }
func (c runConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c runConn) failureFor(table map[string]error, query string) error {
	for fragment, err := range table {
		if strings.Contains(query, fragment) {
			return err
		}
	}
	return nil
}

func (c runConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	plain := make([]driver.Value, 0, len(args))
	for _, arg := range args {
		plain = append(plain, arg.Value)
	}
	c.script.execs = append(c.script.execs, query)
	c.script.execArgs = append(c.script.execArgs, plain)
	if err := c.failureFor(c.script.failExec, query); err != nil {
		return nil, err
	}
	return driver.RowsAffected(1), nil
}

func (c runConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.script.queries = append(c.script.queries, query)
	if err := c.failureFor(c.script.failQuery, query); err != nil {
		return nil, err
	}
	if strings.Contains(query, "schema_migration_progress") {
		if c.script.progress == nil {
			return &runRows{columns: []string{"checksum", "statements_done"}}, nil
		}
		return &runRows{
			columns: []string{"checksum", "statements_done"},
			rows:    [][]driver.Value{c.script.progress},
		}, nil
	}
	return &runRows{
		columns: []string{"filename", "checksum"},
		rows:    c.script.applied,
	}, nil
}

type runRows struct {
	columns []string
	rows    [][]driver.Value
	at      int
}

func (r *runRows) Columns() []string { return r.columns }
func (r *runRows) Close() error      { return nil }
func (r *runRows) Next(dest []driver.Value) error {
	if r.at >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.at])
	r.at++
	return nil
}

type runDriver struct{}

func (runDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

func runDB(t *testing.T, script *runScript) *sql.DB {
	t.Helper()
	db := sql.OpenDB(runConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// twoStatements is a migration body with two statements, so a failure on the
// second leaves a resume point behind.
const twoStatements = "CREATE TABLE mig_one (id INT);\nCREATE TABLE mig_two (id INT);\n"

// sumOf is the checksum the runner records for a whole file.
func sumOf(body string) string {
	digest := sha256.Sum256([]byte(body))
	return hex.EncodeToString(digest[:])
}

// migrationDir writes one migration file into a fresh directory.
func migrationDir(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	writeMigration(t, dir, name, body)
	return dir
}

// A directory that cannot be read is not a failure: a checkout carries no
// /opt/servika/src/migrations, and a developer running the binary locally must
// not be stopped by that.
func TestAMigrationDirectoryThatCannotBeReadIsNotAFailure(t *testing.T) {
	script := &runScript{}

	if err := Run(runDB(t, script), filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
	if len(script.execs) != 0 {
		t.Errorf("the runner touched the database anyway: %v", script.execs)
	}
}

// The bookkeeping tables are the runner's own, so they are created before the
// applied list is read. A failure on any of the three stops the run with its own
// message.
func TestTheBookkeepingTablesAreCreatedBeforeTheAppliedListIsRead(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fragment string
		message  string
	}{
		{
			name:     "the applied table",
			fragment: "CREATE TABLE IF NOT EXISTS schema_migrations",
			message:  "could not create schema_migrations",
		},
		{
			name:     "the checksum column",
			fragment: "ADD COLUMN IF NOT EXISTS checksum",
			message:  "could not add checksum column",
		},
		{
			name:     "the progress table",
			fragment: "CREATE TABLE IF NOT EXISTS schema_migration_progress",
			message:  "could not create schema_migration_progress",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := &runScript{failExec: map[string]error{tc.fragment: errors.New("no such server")}}

			err := Run(runDB(t, script), migrationDir(t, "0001_first.sql", twoStatements))

			if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("Run() = %v, want %q", err, tc.message)
			}
			if len(script.queries) != 0 {
				t.Errorf("the applied list was read before the tables were ready: %v", script.queries)
			}
		})
	}
}

// The applied list decides what to skip, so a read that fails stops the run
// rather than re-applying every file.
func TestAnUnreadableAppliedListStopsTheRun(t *testing.T) {
	script := &runScript{failQuery: map[string]error{
		"FROM schema_migrations": errors.New("lost connection"),
	}}

	err := Run(runDB(t, script), migrationDir(t, "0001_first.sql", twoStatements))

	if err == nil || !strings.Contains(err.Error(), "could not read schema_migrations") {
		t.Fatalf("Run() = %v, want the read failure", err)
	}
	if script.ran("CREATE TABLE mig_one") {
		t.Error("a migration ran without knowing what was already applied")
	}
}

// Only .sql files are migrations, and they are applied in name order. A
// directory whose name ends in .sql is not one.
func TestOnlySQLFilesAreAppliedAndInNameOrder(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "0002_second.sql", "CREATE TABLE mig_two (id INT);\n")
	writeMigration(t, dir, "0001_first.sql", "CREATE TABLE mig_one (id INT);\n")
	writeMigration(t, dir, "notes.txt", "CREATE TABLE mig_note (id INT);\n")
	if err := os.Mkdir(filepath.Join(dir, "0003_dir.sql"), 0o750); err != nil {
		t.Fatalf("make the directory: %v", err)
	}
	script := &runScript{}

	if err := Run(runDB(t, script), dir); err != nil {
		t.Fatalf("Run() = %v", err)
	}

	var recorded []string
	for i, statement := range script.execs {
		if strings.Contains(statement, "INSERT INTO schema_migrations") {
			name, _ := script.execArgs[i][0].(string)
			recorded = append(recorded, name)
		}
	}
	want := []string{"0001_first.sql", "0002_second.sql"}
	if strings.Join(recorded, ",") != strings.Join(want, ",") {
		t.Errorf("applied %v, want %v", recorded, want)
	}
	if script.ran("mig_note") {
		t.Error("a file that is not a migration was applied")
	}
}

// A file whose checksum matches its applied row is skipped, and nothing about it
// is written again.
func TestAnAppliedMigrationIsSkipped(t *testing.T) {
	body := "CREATE TABLE mig_one (id INT);\n"
	script := &runScript{applied: [][]driver.Value{{"0001_first.sql", sumOf(body)}}}

	if err := Run(runDB(t, script), migrationDir(t, "0001_first.sql", body)); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if script.ran("mig_one") || script.ran("INSERT INTO schema_migrations") {
		t.Errorf("an applied migration ran again: %v", script.execs)
	}
}

// Existing installs recorded only the filename. Such a row is backfilled with
// the checksum of the file on disk, and the file counts as applied: re-running
// it would fail on "table already exists".
func TestALegacyRowWithoutAChecksumIsBackfilledAndCountsAsApplied(t *testing.T) {
	body := "CREATE TABLE mig_one (id INT);\n"
	script := &runScript{applied: [][]driver.Value{{"0001_first.sql", ""}}}

	if err := Run(runDB(t, script), migrationDir(t, "0001_first.sql", body)); err != nil {
		t.Fatalf("Run() = %v", err)
	}

	args := script.argsOf(t, "UPDATE schema_migrations SET checksum")
	if len(args) != 2 || args[0] != sumOf(body) || args[1] != "0001_first.sql" {
		t.Errorf("backfill arguments = %v, want the checksum of the file and its name", args)
	}
	if script.ran("mig_one") {
		t.Error("a legacy row was treated as unapplied and the file ran again")
	}
}

// Editing an applied migration is the case that puts a server's schema out of
// step with its recorded history, so it stops the run.
func TestAnAppliedMigrationWhoseContentsChangedStopsTheRun(t *testing.T) {
	script := &runScript{applied: [][]driver.Value{{"0001_first.sql", sumOf("something else")}}}

	err := Run(runDB(t, script), migrationDir(t, "0001_first.sql", "CREATE TABLE mig_one (id INT);\n"))

	if err == nil || err.Error() != "0001_first.sql was already applied but its contents changed" {
		t.Fatalf("Run() = %v, want the refusal", err)
	}
}

// The backfill is a write, so its failure stops the run too.
func TestAFailedChecksumBackfillStopsTheRun(t *testing.T) {
	script := &runScript{
		applied:  [][]driver.Value{{"0001_first.sql", ""}},
		failExec: map[string]error{"UPDATE schema_migrations SET checksum": errors.New("read-only server")},
	}

	err := Run(runDB(t, script), migrationDir(t, "0001_first.sql", "CREATE TABLE mig_one (id INT);\n"))

	if err == nil || !strings.Contains(err.Error(), "could not backfill checksum for 0001_first.sql") {
		t.Fatalf("Run() = %v, want the backfill failure", err)
	}
}

// A listed file that cannot be read stops the run: applying the rest would leave
// a gap in a sequence whose order is its only guarantee.
func TestAFileThatCannotBeReadStopsTheRun(t *testing.T) {
	dir := migrationDir(t, "0001_first.sql", "CREATE TABLE mig_one (id INT);\n")
	unreadable := filepath.Join(dir, "0001_first.sql")
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })
	if _, err := os.ReadFile(unreadable); err == nil {
		t.Skip("this user reads a file with no permission bits")
	}
	script := &runScript{}

	err := Run(runDB(t, script), dir)

	if err == nil || !strings.Contains(err.Error(), "could not read 0001_first.sql") {
		t.Fatalf("Run() = %v, want the read failure", err)
	}
}

// A fresh file runs every statement, records itself as applied, and clears the
// progress row, so a healthy server carries no progress rows at all.
func TestAFreshMigrationRunsEveryStatementThenRecordsItself(t *testing.T) {
	script := &runScript{}

	if err := Run(runDB(t, script), migrationDir(t, "0001_first.sql", twoStatements)); err != nil {
		t.Fatalf("Run() = %v", err)
	}

	// Measured order: the two statements, the applied row, then the progress
	// row is cleared.
	order := script.order()
	if strings.Join(order, ",") != "one,two,applied,cleared" {
		t.Errorf("order = %v", order)
	}
	args := script.argsOf(t, "INSERT INTO schema_migrations")
	if len(args) != 2 || args[0] != "0001_first.sql" || args[1] != sumOf(twoStatements) {
		t.Errorf("applied row = %v, want the name and the file checksum", args)
	}
}

// A statement that fails records where the file stopped, against the checksum of
// the statements that already committed. MariaDB commits DDL implicitly, so the
// head of the file is on disk whatever the runner does about it.
func TestAFailedStatementRecordsTheResumePoint(t *testing.T) {
	script := &runScript{failExec: map[string]error{"mig_two": errors.New("syntax error")}}

	err := Run(runDB(t, script), migrationDir(t, "0001_first.sql", twoStatements))

	if err == nil || !strings.Contains(err.Error(), "0001_first.sql failed at statement 2 of 2") {
		t.Fatalf("Run() = %v, want the statement failure", err)
	}
	args := script.argsOf(t, "INSERT INTO schema_migration_progress")
	if len(args) != 3 || args[0] != "0001_first.sql" || args[2] != int64(1) {
		t.Fatalf("progress row = %v, want the name and one committed statement", args)
	}
	if args[1] != sumOf("CREATE TABLE mig_one (id INT)") {
		t.Errorf("progress checksum = %v, want the checksum of the committed statement", args[1])
	}
	if script.ran("INSERT INTO schema_migrations(") {
		t.Error("a failed file was recorded as applied")
	}
}

// The progress row is the resume point: the statements it counts are not run
// again.
func TestARunResumesAtTheRecordedStatement(t *testing.T) {
	script := &runScript{
		progress: []driver.Value{sumOf("CREATE TABLE mig_one (id INT)"), int64(1)},
	}

	if err := Run(runDB(t, script), migrationDir(t, "0001_first.sql", twoStatements)); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if script.ran("mig_one") {
		t.Error("the committed statement ran a second time")
	}
	if !script.ran("mig_two") {
		t.Error("the remaining statement did not run")
	}
}

// Resuming is safe only while the committed head of the file is unchanged. Both
// a rewritten head and a count that no longer fits the file are refused.
func TestAResumeIsRefusedWhenTheCommittedHeadNoLongerMatches(t *testing.T) {
	for _, tc := range []struct {
		name     string
		progress []driver.Value
	}{
		{
			name:     "the committed statements were rewritten",
			progress: []driver.Value{sumOf("CREATE TABLE something_else (id INT)"), int64(1)},
		},
		{
			name:     "the file is shorter than the count",
			progress: []driver.Value{sumOf("whatever"), int64(9)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := &runScript{progress: tc.progress}

			err := Run(runDB(t, script), migrationDir(t, "0001_first.sql", twoStatements))

			if !errors.Is(err, ErrResumeRefused) {
				t.Fatalf("Run() = %v, want ErrResumeRefused", err)
			}
			if script.ran("mig_one") || script.ran("mig_two") {
				t.Errorf("the refused resume ran a statement anyway: %v", script.execs)
			}
		})
	}
}

// A progress row that cannot be read stops the run, because a file applied from
// its first statement is the failure the progress table exists to prevent.
func TestAnUnreadableProgressRowStopsTheRun(t *testing.T) {
	script := &runScript{failQuery: map[string]error{
		"schema_migration_progress": errors.New("lost connection"),
	}}

	err := Run(runDB(t, script), migrationDir(t, "0001_first.sql", twoStatements))

	if err == nil || !strings.Contains(err.Error(), "could not read progress for 0001_first.sql") {
		t.Fatalf("Run() = %v, want the progress read failure", err)
	}
	if script.ran("mig_one") {
		t.Error("the file ran without knowing where it stopped")
	}
}

// The two writes that close a migration each stop the run with their own
// message: a file that ran but was not recorded runs again on the next boot.
func TestTheClosingWritesEachStopTheRun(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fragment string
		message  string
	}{
		{
			name:     "the applied row",
			fragment: "INSERT INTO schema_migrations(",
			message:  "record 0001_first.sql",
		},
		{
			name:     "the progress row",
			fragment: "DELETE FROM schema_migration_progress",
			message:  "clear progress for 0001_first.sql",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := &runScript{failExec: map[string]error{tc.fragment: errors.New("read-only server")}}

			err := Run(runDB(t, script), migrationDir(t, "0001_first.sql", twoStatements))

			if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("Run() = %v, want %q", err, tc.message)
			}
		})
	}
}
