package transfers

import (
	"archive/tar"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

// takenBy answers the uniqueness query uniqueTargetDB asks from its candidate
// name: a name taken reports counts one, any other name is free.
func takenBy(taken func(name string) bool) *sqlScript {
	s := newScript()
	s.answer = func(query string, args []driver.Value) ([][]driver.Value, bool) {
		if !strings.Contains(query, "information_schema.schemata") || len(args) == 0 {
			return nil, false
		}
		name, _ := args[0].(string)
		return countRow(taken(name)), true
	}
	return s
}

func takenNames(names ...string) *sqlScript {
	return takenBy(func(name string) bool { return slices.Contains(names, name) })
}

// The target name drops the source account prefix, keeps only identifier
// characters, and resolves a collision or the 64-character limit with a counter
// instead of a silent truncation.
func TestUniqueTargetDB(t *testing.T) {
	longUser := "c_" + strings.Repeat("u", 40)
	longDB := strings.Repeat("d", 30)
	longBase := longUser + "_" + longDB
	cases := []struct {
		name                                string
		systemUser, sourceDB, sourceAccount string
		taken                               []string
		want                                string
	}{
		{"the account prefix is dropped", "c_site", "olduser_wp", "olduser", nil, "c_site_wp"},
		{"a foreign prefix is kept", "c_site", "other_wp", "olduser", nil, "c_site_other_wp"},
		{"a character outside the identifier set becomes an underscore", "c_site", "shop-db$x", "", nil, "c_site_shop_db_x"},
		{"an empty suffix becomes db", "c_site", "olduser_", "olduser", nil, "c_site_db"},
		{"a taken name gets a counter", "c_site", "olduser_wp", "olduser", []string{"c_site_wp", "c_site_wp_2"}, "c_site_wp_3"},
		{"a long name is cut to 64", longUser, longDB, "", nil, longBase[:64]},
		{"a long taken name is cut before its counter", longUser, longDB, "", []string{longBase[:64]}, longBase[:60] + "_2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := &Handlers{DB: scriptDB(t, takenNames(c.taken...))}
			got, err := h.uniqueTargetDB(t.Context(), c.systemUser, c.sourceDB, c.sourceAccount)
			assertErrText(t, err, "")
			if got != c.want {
				t.Fatalf("uniqueTargetDB = %q, want %q", got, c.want)
			}
		})
	}
}

// Fifty taken names end the search, and a uniqueness query that fails reads as
// a free name.
func TestUniqueTargetDBEdges(t *testing.T) {
	s := takenBy(func(string) bool { return true })
	h := &Handlers{DB: scriptDB(t, s)}
	_, err := h.uniqueTargetDB(t.Context(), "c_site", "olduser_wp", "olduser")
	assertErrText(t, err, "could not build a unique database name")
	if len(s.steps) != 50 {
		t.Fatalf("%d names were tried, want 50", len(s.steps))
	}

	failing := newScript()
	failing.fail["information_schema.schemata"] = errScripted
	h = &Handlers{DB: scriptDB(t, failing)}
	if got, err := h.uniqueTargetDB(t.Context(), "c_site", "olduser_wp", "olduser"); err != nil || got != "c_site_wp" {
		t.Fatalf("uniqueTargetDB = %q, %v", got, err)
	}
}

// mysqlCounts answers the two local mysql lookups keepOriginalIdentity makes:
// the account count and the schema count, or a failed client when fail is set.
func mysqlCounts(t *testing.T, users, schemas string, fail bool) *commandRecorder {
	t.Helper()
	return withCommandScript(t, func(argv []string) commandAnswer {
		switch {
		case fail:
			return commandAnswer{stderr: "refused", exit: 1}
		case strings.Contains(argv[len(argv)-1], "mysql.user"):
			return commandAnswer{output: users + "\n"}
		default:
			return commandAnswer{output: schemas + "\n"}
		}
	})
}

// siteWithEnv returns a web root whose .env holds body.
func siteWithEnv(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func assertIdentity(t *testing.T, user, password string, ok, keep bool) {
	t.Helper()
	want := [3]any{"", "", false}
	if keep {
		want = [3]any{"acme_user", "s3cr3t", true}
	}
	if got := [3]any{user, password, ok}; got != want {
		t.Fatalf("keepOriginalIdentity = %v, want %v", got, want)
	}
}

// The source identity is kept only when every condition holds; each one that
// fails sends the migration back to the unique-name path.
func TestKeepOriginalIdentity(t *testing.T) {
	const creds = "DB_DATABASE=acme_app\nDB_USERNAME=%s\nDB_PASSWORD=s3cr3t\n"
	cases := []struct {
		name           string
		user           string
		databases      []string
		users, schemas string
		fail           bool
		keep           bool
	}{
		{"a user outside the identifier set", "acme-user", []string{"acme_app"}, "0", "0", false, false},
		{"a system account name", "mysql", []string{"acme_app"}, "0", "0", false, false},
		{"an account that already exists", "acme_user", []string{"acme_app"}, "1", "0", false, false},
		{"a mysql client that fails", "acme_user", []string{"acme_app"}, "0", "0", true, false},
		{"no database", "acme_user", nil, "0", "0", false, false},
		{"a database outside the remote name set", "acme_user", []string{"acme app"}, "0", "0", false, false},
		{"a database outside the identifier set", "acme_user", []string{"acme-app"}, "0", "0", false, false},
		{"a system database", "acme_user", []string{"information_schema"}, "0", "0", false, false},
		{"a schema that already exists", "acme_user", []string{"acme_app"}, "0", "1", false, false},
		{"every condition holds", "acme_user", []string{"acme_app", "acme_shop"}, "0", "0", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mysqlCounts(t, c.users, c.schemas, c.fail)
			root := siteWithEnv(t, fmt.Sprintf(creds, c.user))
			user, password, ok := (&Handlers{}).keepOriginalIdentity(t.Context(), RemoteAccount{Databases: c.databases}, root)
			assertIdentity(t, user, password, ok, c.keep)
		})
	}
}

// siteRoot returns a web root laid out as <tmp>/c_site/public_html, with the
// configuration backup root pointed at a second temporary directory.
func siteRoot(t *testing.T) (webRoot, backups string) {
	t.Helper()
	webRoot = filepath.Join(t.TempDir(), "c_site", "public_html")
	if err := os.MkdirAll(webRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	backups = t.TempDir()
	setForTest(t, &migrationBackupRoot, backups)
	return webRoot, backups
}

func writeSiteFile(t *testing.T, root, rel, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

var oldWPMapping = map[string]dbTarget{"olduser_wp": {Name: "c_site_wp", User: "c_site_db"}}

// Only the value of a known key changes; a file with nothing to change, a
// symlink and an oversized file are left alone, and the original is backed up
// with its mode kept.
func TestRewriteSiteConfigsRewritesTheKnownKeysOnly(t *testing.T) {
	webRoot, backups := siteRoot(t)
	const original = "<?php\ndefine('DB_NAME', 'olduser_wp');\ndefine('DB_USER', 'olduser');\ndefine('DB_PASSWORD', 'oldpass');\n$table_prefix = 'wp_';\n"
	wp := writeSiteFile(t, webRoot, "wp-config.php", original, 0o640)
	env := writeSiteFile(t, webRoot, ".env", "APP_NAME=site\n", 0o600)
	writeSiteFile(t, webRoot, "sites/default/settings.php", "DB_NAME=olduser_wp\n"+strings.Repeat("#", 4<<20), 0o600)
	if err := os.Symlink(wp, filepath.Join(webRoot, "config.php")); err != nil {
		t.Fatal(err)
	}
	var log logLines

	if n := rewriteSiteConfigs(webRoot, oldWPMapping, "newpass", log.logf); n != 1 {
		t.Fatalf("rewriteSiteConfigs = %d, want 1", n)
	}
	assertFile(t, wp, "<?php\ndefine('DB_NAME', 'c_site_wp');\ndefine('DB_USER', 'c_site_db');\ndefine('DB_PASSWORD', 'newpass');\n$table_prefix = 'wp_';\n")
	assertFile(t, env, "APP_NAME=site\n")
	assertFile(t, filepath.Join(backups, "c_site", "wp-config.php"), original)
	if st, err := os.Stat(wp); err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, %v", st, err)
	}
	assertLog(t, &log, "configuration updated: wp-config.php")
}

// With no mapping nothing is read; with no user and no password only the name
// changes.
func TestRewriteSiteConfigsWithoutAUserOrPassword(t *testing.T) {
	webRoot, _ := siteRoot(t)
	const original = "DB_DATABASE=olduser_wp\nDB_USERNAME=olduser\nDB_PASSWORD=old\n"
	env := writeSiteFile(t, webRoot, ".env", original, 0o600)
	var log logLines
	if n := rewriteSiteConfigs(webRoot, nil, "newpass", log.logf); n != 0 {
		t.Fatalf("an empty mapping rewrote %d files", n)
	}
	assertFile(t, env, original)

	mapping := map[string]dbTarget{"olduser_wp": {Name: "c_site_wp"}}
	if n := rewriteSiteConfigs(webRoot, mapping, "", log.logf); n != 1 {
		t.Fatalf("rewriteSiteConfigs = %d, want 1", n)
	}
	assertFile(t, env, "DB_DATABASE=c_site_wp\nDB_USERNAME=olduser\nDB_PASSWORD=old\n")
}

// A file that cannot be backed up is left unchanged with a warning.
func TestRewriteSiteConfigsLeavesAFileItCannotBackUp(t *testing.T) {
	webRoot, _ := siteRoot(t)
	setForTest(t, &migrationBackupRoot, writeFile(t, "not-a-directory", nil))
	env := writeSiteFile(t, webRoot, ".env", "DB_DATABASE=olduser_wp\n", 0o600)
	var log logLines
	if n := rewriteSiteConfigs(webRoot, oldWPMapping, "", log.logf); n != 0 {
		t.Fatalf("rewriteSiteConfigs = %d, want 0", n)
	}
	assertFile(t, env, "DB_DATABASE=olduser_wp\n")
	assertLogHolds(t, &log, "warning: .env could not be backed up, the file was left unchanged: ")
}

// A file the panel cannot read is skipped, and a rewrite that cannot be written
// is not counted, though its backup is already taken.
func TestRewriteSiteConfigsCountsOnlyAWrittenFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	webRoot, backups := siteRoot(t)
	env := writeSiteFile(t, webRoot, ".env", "DB_DATABASE=olduser_wp\n", 0o600)
	writeSiteFile(t, webRoot, "wp-config.php", "define('DB_NAME', 'olduser_wp');\n", 0o000)
	if err := os.Chmod(webRoot, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(webRoot, 0o750) })
	var log logLines

	if n := rewriteSiteConfigs(webRoot, oldWPMapping, "", log.logf); n != 0 {
		t.Fatalf("rewriteSiteConfigs = %d, want 0", n)
	}
	assertFile(t, env, "DB_DATABASE=olduser_wp\n")
	assertFile(t, filepath.Join(backups, "c_site", ".env"), "DB_DATABASE=olduser_wp\n")
	if _, err := os.Stat(filepath.Join(backups, "c_site", "wp-config.php")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("an unreadable file was backed up: %v", err)
	}
	assertLog(t, &log)
}

// passwordSource is a source reached with a password, so every remote command
// runs through sshpass.
func passwordSource(panel string) *RemoteSource {
	return &RemoteSource{Type: panel, Host: "src.example.com", Port: 22, User: "root", Password: "pw-secret"}
}

// Every way a remote dump can fail is reported in its own words, with the
// password masked, and a complete dump reaches the import.
func TestCopyDatabase(t *testing.T) {
	complete := dumpFile(t, completeDump)
	cut := dumpFile(t, "CREATE TABLE t(id int);\n")
	cases := []struct {
		name           string
		source, target string
		answer         commandAnswer
		importFail     error
		want           string
	}{
		{"an invalid source name", "bad name", "c_site_wp", commandAnswer{}, nil, "invalid database name"},
		{"an invalid target name", "acme_wp", "bad name", commandAnswer{}, nil, "invalid database name"},
		{"a dump the source refuses", "acme_wp", "c_site_wp", commandAnswer{stderr: "mysqldump: Got error: 1045\nfor pw-secret", exit: 2}, nil, "dump: mysqldump: Got error: 1045 for ******"},
		{"an empty dump", "acme_wp", "c_site_wp", commandAnswer{}, nil, "the dump came back empty"},
		{"a dump that is not gzip", "acme_wp", "c_site_wp", commandAnswer{output: "this is not a gzip stream"}, nil, "the dump could not be read (gzip): gzip: invalid header"},
		{"an import the server refuses", "acme_wp", "c_site_wp", commandAnswer{file: complete}, errScripted, "import: scripted failure"},
		{"a dump cut short", "acme_wp", "c_site_wp", commandAnswer{file: cut}, nil, "the dump is incomplete (mysqldump failed on the source server)"},
		{"a complete dump", "acme_wp", "c_site_wp", commandAnswer{file: complete}, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withCommandScript(t, func([]string) commandAnswer { return c.answer })
			withSQLImports(t, c.importFail)
			err := (&Handlers{}).copyDatabase(t.Context(), passwordSource("cpanel"), c.source, c.target)
			assertErrText(t, err, c.want)
		})
	}
}

// The dump runs under bash with pipefail when bash exists, and the import gets
// the target name and the dump text.
func TestCopyDatabaseRunsTheDumpUnderPipefail(t *testing.T) {
	commands := withCommandScript(t, func([]string) commandAnswer { return commandAnswer{file: dumpFile(t, completeDump)} })
	imports := withSQLImports(t, nil)
	if err := (&Handlers{}).copyDatabase(t.Context(), passwordSource("cpanel"), "acme_wp", "c_site_wp"); err != nil {
		t.Fatal(err)
	}
	argv := commands.argvs()[0]
	const remote = `if command -v bash >/dev/null 2>&1; then bash -o pipefail -c 'mysqldump --single-transaction --quick --routines --triggers --no-tablespaces --default-character-set=utf8mb4 '\''acme_wp'\'' | gzip -c'; else mysqldump --single-transaction --quick --routines --triggers --no-tablespaces --default-character-set=utf8mb4 'acme_wp' | gzip -c; fi`
	if !hasArgvPrefix(argv, []string{"sshpass", "-e", "ssh"}) || argv[len(argv)-1] != remote {
		t.Fatalf("argv = %q", argv)
	}
	if !reflect.DeepEqual(imports.targets, []string{"c_site_wp"}) || !strings.Contains(imports.bodies[0], "CREATE TABLE t(id int);") {
		t.Fatalf("imports = %v %q", imports.targets, imports.bodies)
	}
}

// A temporary file that cannot be created stops the copy before any command.
func TestCopyDatabaseNeedsATemporaryFile(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent")
	commands := withCommands(t)
	t.Setenv("TMPDIR", absent)
	err := (&Handlers{}).copyDatabase(t.Context(), passwordSource("cpanel"), "acme_wp", "c_site_wp")
	if !errors.Is(err, fs.ErrNotExist) || len(commands.argvs()) != 0 {
		t.Fatalf("err = %v, commands = %q", err, commands.argvs())
	}
}

// Every mapped dump is imported into its target in one pass, in archive order.
func TestRestoreDatabasesImportsEveryMappedDump(t *testing.T) {
	path := archiveFile(t,
		testEntry{name: "backup-demo/mysql/demo_wp.sql", body: "wp dump"},
		testEntry{name: "backup-demo/homedir/x", body: "x"},
		testEntry{name: "backup-demo/mysql/demo_shop.sql", body: "shop dump"},
		testEntry{name: "backup-demo/mysql/zzz.sql", body: "after"},
	)
	imports := withSQLImports(t, nil)
	maps := []DBMap{{Source: "demo_wp", Target: "c_site_main"}, {Source: "demo_shop", Target: "c_site_shop"}}
	if err := (&Handlers{}).restoreDatabases(t.Context(), path, "backup-demo", maps); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(imports.targets, []string{"c_site_main", "c_site_shop"}) ||
		!reflect.DeepEqual(imports.bodies, []string{"wp dump", "shop dump"}) {
		t.Fatalf("imports = %v %q", imports.targets, imports.bodies)
	}
}

// Every way restoring the dumps can fail is returned.
func TestRestoreDatabasesFailures(t *testing.T) {
	one := []DBMap{{Source: "demo_wp", Target: "c_site_main"}}
	dirDump := archiveFile(t, testEntry{name: "backup-demo/mysql/demo_wp.sql", typ: tar.TypeDir})
	withDump := archiveFile(t, testEntry{name: "backup-demo/mysql/demo_wp.sql", body: "wp dump"})
	three := []DBMap{{Source: "z", Target: "c_z"}, {Source: "a", Target: "c_a"}, {Source: "m", Target: "c_m"}}
	cases := []struct {
		name       string
		path       string
		maps       []DBMap
		importFail error
		want       string
	}{
		{"a missing archive", filepath.Join(t.TempDir(), "absent.tar.gz"), one, nil, "no such file or directory"},
		{"a file that is not gzip", writeFile(t, "plain.tar.gz", []byte("plain text, not gzip")), one, nil, "gzip: invalid header"},
		{"a stream that is not tar", writeFile(t, "garbage.tar.gz", gzipBytes(t, []byte(strings.Repeat("x", 100)))), one, nil, "unexpected EOF"},
		{"a dump that is not a regular file", dirDump, one, nil, "the SQL dump was not found in the archive: c_site_main"},
		{"an import the server refuses", withDump, one, errScripted, "scripted failure"},
		{"several missing dumps", withDump, three, nil, "the SQL dump was not found in the archive: c_a, c_m, c_z"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withSQLImports(t, c.importFail)
			err := (&Handlers{}).restoreDatabases(t.Context(), c.path, "backup-demo", c.maps)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to hold %q", err, c.want)
			}
		})
	}
	if err := (&Handlers{}).restoreDatabases(t.Context(), "/nonexistent", "backup-demo", nil); err != nil {
		t.Fatalf("no mapping = %v", err)
	}
}

// dbCreates records the two database creation seams and fails the names in fail.
type dbCreates struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]bool
}

func withDBCreates(t *testing.T, fail ...string) *dbCreates {
	t.Helper()
	rec := &dbCreates{fail: map[string]bool{}}
	for _, name := range fail {
		rec.fail[name] = true
	}
	setForTest(t, &createMySQLDB, rec.create)
	setForTest(t, &createMySQLDBForUser, rec.createForUser)
	return rec
}

func (d *dbCreates) create(_ *sql.DB, domainID int64, name, user, password string) error {
	return d.record(fmt.Sprintf("create %d %s %s %s", domainID, name, user, password), name)
}

func (d *dbCreates) createForUser(_ *sql.DB, domainID int64, name, user string) error {
	return d.record(fmt.Sprintf("attach %d %s %s", domainID, name, user), name)
}

func (d *dbCreates) record(call, name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, call)
	if d.fail[name] {
		return errScripted
	}
	return nil
}

// dumpsFailingFor answers every dump with a complete one, except the dump whose
// remote command names database, which exits 1 with "boom".
func dumpsFailingFor(t *testing.T, database string) *commandRecorder {
	t.Helper()
	complete := dumpFile(t, completeDump)
	return withCommandScript(t, func(argv []string) commandAnswer {
		if strings.Contains(argv[len(argv)-1], database) {
			return commandAnswer{stderr: "boom", exit: 1}
		}
		return commandAnswer{file: complete}
	})
}

// On the unique-name path each database either migrates or is named in the
// error, and the password is generated once for the first database created.
func TestMigrateDatabasesOnTheUniqueNamePath(t *testing.T) {
	dumpsFailingFor(t, "olduser_logs")
	withSQLImports(t, nil)
	creates := withDBCreates(t, "c_site_wp", "c_site_blog")
	s := takenBy(func(name string) bool { return strings.HasPrefix(name, "c_site_x") })
	h := &Handlers{DB: scriptDB(t, s)}
	account := RemoteAccount{SourceAccount: "olduser", Databases: []string{
		"bad name", "olduser_x", "olduser_wp", "olduser_shop", "olduser_blog", "olduser_logs", "olduser_media",
	}}
	result := &MigrationResult{DomainID: 7}
	var log logLines

	mapping, dbPass, keep, err := h.migrateDatabases(t.Context(), passwordSource("cpanel"), account, "c_site", t.TempDir(), result, log.logf)
	assertErrText(t, err, "database migration failed: olduser_x, olduser_wp, olduser_blog, olduser_logs")
	want := map[string]dbTarget{"olduser_shop": {Name: "c_site_shop", User: "c_site_db"}, "olduser_media": {Name: "c_site_media", User: "c_site_db"}}
	if !reflect.DeepEqual(mapping, want) || keep || len(dbPass) != 24 || result.DBCount != 2 {
		t.Fatalf("mapping = %v, pass %d chars, keep %v, count %d", mapping, len(dbPass), keep, result.DBCount)
	}
	wantCalls := []string{
		"create 7 c_site_wp c_site_db " + dbPass, "create 7 c_site_shop c_site_db " + dbPass,
		"attach 7 c_site_blog c_site_db", "attach 7 c_site_logs c_site_db", "attach 7 c_site_media c_site_db",
	}
	if !reflect.DeepEqual(creates.calls, wantCalls) {
		t.Fatalf("calls =\n%q\nwant\n%q", creates.calls, wantCalls)
	}
	assertLog(t, &log,
		"warning: could not build a target name for olduser_x: could not build a unique database name",
		"database: olduser_wp -> c_site_wp",
		"warning: c_site_wp could not be created: scripted failure",
		"database: olduser_shop -> c_site_shop",
		"database: olduser_blog -> c_site_blog",
		"warning: c_site_blog could not be created: scripted failure",
		"database: olduser_logs -> c_site_logs",
		"ERROR: olduser_logs could not be copied: dump: boom",
		"database: olduser_media -> c_site_media",
	)
}

// When the source identity can be kept, the database keeps its name, user and
// password, and no uniqueness query is asked.
func TestMigrateDatabasesKeepsTheSourceIdentity(t *testing.T) {
	complete := dumpFile(t, completeDump)
	remoteAnswers(t, map[string]commandAnswer{
		"SELECT COUNT(*)": {output: "0\n"},
		"mysqldump":       {file: complete},
	})
	withSQLImports(t, nil)
	creates := withDBCreates(t)
	s := newScript()
	h := &Handlers{DB: scriptDB(t, s)}
	root := siteWithEnv(t, "DB_DATABASE=acme_app\nDB_USERNAME=acme_user\nDB_PASSWORD=s3cr3t\n")
	result := &MigrationResult{DomainID: 7}
	var log logLines

	mapping, dbPass, keep, err := h.migrateDatabases(t.Context(), passwordSource("cpanel"),
		RemoteAccount{SourceAccount: "acme", Databases: []string{"acme_app"}}, "c_site", root, result, log.logf)
	assertErrText(t, err, "")
	if !reflect.DeepEqual(mapping, map[string]dbTarget{"acme_app": {Name: "acme_app", User: "acme_user"}}) ||
		dbPass != "s3cr3t" || !keep || len(s.steps) != 0 {
		t.Fatalf("mapping = %v, pass %q, keep %v, steps %q", mapping, dbPass, keep, s.steps)
	}
	if !reflect.DeepEqual(creates.calls, []string{"create 7 acme_app acme_user s3cr3t"}) {
		t.Fatalf("calls = %q", creates.calls)
	}
	assertLog(t, &log,
		"keeping the source database name, user and password; the site configuration is left untouched",
		"database: acme_app -> acme_app",
	)
}
