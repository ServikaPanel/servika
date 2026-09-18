package dbmigrate

import (
	"os"
	"path/filepath"
	"testing"
)

// The runner applies a migration as the database superuser, so it must refuse a
// directory another account can write to. The refusal comes before anything is
// read, and Run answers nil, because the panel keeps serving.
func TestAWritableMigrationDirectoryIsRefused(t *testing.T) {
	script := &runScript{}
	dir := t.TempDir()
	writeMigration(t, dir, "0001_one.sql", "CREATE TABLE mig_one (id INT);\n")
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if err := Run(runDB(t, script), dir); err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
	if len(script.execs) != 0 {
		t.Errorf("the runner touched the database anyway: %v", script.execs)
	}
}

// The negative half proves nothing alone: a gate that refused every directory
// would pass it while stopping every upgrade. A directory with the permissions
// the release ships gets through and the migration runs.
func TestAMigrationDirectoryWithTheShippedPermissionsRuns(t *testing.T) {
	script := &runScript{}
	dir := t.TempDir()
	writeMigration(t, dir, "0001_one.sql", "CREATE TABLE mig_one (id INT);\n")
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if err := Run(runDB(t, script), dir); err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
	if len(script.execs) == 0 {
		t.Error("the migration never ran")
	}
}

// A single file is enough: a symlink can be repointed after the check, and a
// writable file can be rewritten, so both are skipped while the rest of the
// directory still applies.
func TestAnUntrustedMigrationFileIsSkipped(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "0001_good.sql", "CREATE TABLE mig_one (id INT);\n")
	writeMigration(t, dir, "0002_loose.sql", "CREATE TABLE mig_two (id INT);\n")
	if err := os.Chmod(filepath.Join(dir, "0002_loose.sql"), 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	target := filepath.Join(dir, "0003_target.txt")
	if err := os.WriteFile(target, []byte("CREATE TABLE mig_three (id INT);\n"), 0o600); err != nil {
		t.Fatalf("write link target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "0003_link.sql")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	names := migrationNames(entries)
	if len(names) != 1 || names[0] != "0001_good.sql" {
		t.Fatalf("got %v, want only 0001_good.sql", names)
	}
}
