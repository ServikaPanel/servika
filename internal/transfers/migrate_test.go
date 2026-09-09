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

// The identity reader has to cover the same configuration shapes configDBNames
// already understands, because the two read the same files.
func TestConfigDBIdentityReadsTheUserAndPassword(t *testing.T) {
	cases := map[string]struct{ file, body, user, password string }{
		"wordpress": {
			file: "wp-config.php",
			body: "<?php\ndefine('DB_NAME', 'acme_wp');\ndefine('DB_USER', 'acme_user');\ndefine('DB_PASSWORD', 's3cr3t');\n",
			user: "acme_user", password: "s3cr3t",
		},
		"laravel": {
			file: ".env",
			body: "DB_DATABASE=acme_app\nDB_USERNAME=acme_user\nDB_PASSWORD=s3cr3t\n",
			user: "acme_user", password: "s3cr3t",
		},
	}
	for name, c := range cases {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, c.file), []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		user, password := configDBIdentity(root)
		if user != c.user || password != c.password {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", name, user, password, c.user, c.password)
		}
	}
}

// A configuration that names no credentials yields nothing, so the caller
// declines to keep the original identity rather than creating an account with
// half of one.
func TestConfigDBIdentityOnAConfigWithoutCredentials(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"),
		[]byte("<?php\ndefine('DB_NAME', 'acme_wp');\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	user, password := configDBIdentity(root)
	if user != "" || password != "" {
		t.Fatalf("got (%q, %q), want both empty", user, password)
	}
}

// Both guards decide whether the migration may take over a name, and both are
// asked about values that reach a mysql statement by concatenation. A name the
// allowlist refuses must read as "taken" rather than being sent to the server,
// so the migration falls back instead of acting on an unknown.
func TestTheDatabaseGuardsFailClosedOnAnUnvalidatedName(t *testing.T) {
	h := &Handlers{}
	hostile := []string{
		"acme'; DROP USER 'root'@'localhost'; --",
		"acme user",
		"acme-user", // reRemoteDBName allows it, ValidDBIdentifier does not
		"acme$user", // same
		"",
	}
	for _, name := range hostile {
		if !h.dbUserExists(t.Context(), name) {
			t.Errorf("dbUserExists(%q) reported the account as free", name)
		}
		if h.dbNameAvailable(t.Context(), name) {
			t.Errorf("dbNameAvailable(%q) reported the name as available", name)
		}
	}
}

// keepOriginalIdentity must refuse as soon as either half of the credentials is
// missing, before it asks the server anything.
func TestKeepOriginalIdentityRefusesAnIncompleteConfiguration(t *testing.T) {
	h := &Handlers{}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"),
		[]byte("DB_DATABASE=acme_app\nDB_USERNAME=acme_user\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	account := RemoteAccount{Databases: []string{"acme_app"}}
	if _, _, ok := h.keepOriginalIdentity(t.Context(), account, root); ok {
		t.Error("a configuration with no password was accepted")
	}
	// No configuration at all is the same answer.
	if _, _, ok := h.keepOriginalIdentity(t.Context(), account, t.TempDir()); ok {
		t.Error("a web root with no configuration was accepted")
	}
}
