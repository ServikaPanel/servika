package transfers

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// configDBNames is the backup path when discovery returns no database. It must
// read a real name out of a copied config, refuse a system database and an
// invalid name, and never return a duplicate, because the value becomes a
// mysqldump argument.
func TestConfigDBNames(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("wp-config.php", "<?php\ndefine('DB_NAME', 'olduser_wp');\ndefine('DB_USER', 'olduser');\n")
	// A second config naming the SAME database must not double it.
	write(".env", "DB_DATABASE=olduser_wp\nDB_PASSWORD=secret\n")
	// A system database must be skipped even when a config names it.
	write("config.php", "<?php $database = 'information_schema';\n")

	got := configDBNames(root)
	if !slices.Contains(got, "olduser_wp") {
		t.Fatalf("the real database name was not read: %v", got)
	}
	if slices.Contains(got, "information_schema") {
		t.Fatalf("a system database was returned: %v", got)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly one name, got %v (dedup failed?)", got)
	}
}

// An empty web root, or one whose config names no database, returns nothing so
// the caller falls through to the visible "no database migrated" warning.
func TestConfigDBNamesEmpty(t *testing.T) {
	root := t.TempDir()
	if got := configDBNames(root); len(got) != 0 {
		t.Fatalf("an empty web root returned %v, want none", got)
	}
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"),
		[]byte("<?php // no database keys here\n$foo = 'bar';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := configDBNames(root); len(got) != 0 {
		t.Fatalf("a config with no database key returned %v, want none", got)
	}
}

// An invalid database name (one that could not be a mysqldump argument) is
// refused rather than passed through.
func TestConfigDBNamesRefusesInvalid(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"),
		[]byte("<?php define('DB_NAME', 'bad name; DROP');\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := configDBNames(root); len(got) != 0 {
		t.Fatalf("an invalid name was returned: %v", got)
	}
}
