package backups

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
)

const (
	ownedListQuery   = "SELECT db_name FROM db_accounts WHERE domain_id=?"
	otherOwnerQuery  = "SELECT COUNT(*) FROM db_accounts WHERE db_name=? AND domain_id<>?"
	reRegisterInsert = "INSERT INTO db_accounts (domain_id, db_name, db_user, db_pass_plain, db_host)"
)

// importRecorder stands in for sqlimport.Import: it records what each database
// received and fails the ones the test names.
type importRecorder struct {
	mu       sync.Mutex
	imported map[string]string
	fail     map[string]error
}

func withImports(t *testing.T, fail map[string]error) *importRecorder {
	t.Helper()
	recorder := &importRecorder{imported: map[string]string{}, fail: fail}
	setForTest(t, &importSQL, func(_ context.Context, dbName string, dump io.Reader) error {
		body, err := io.ReadAll(dump)
		if err != nil {
			return err
		}
		recorder.mu.Lock()
		defer recorder.mu.Unlock()
		if failure := recorder.fail[dbName]; failure != nil {
			return failure
		}
		recorder.imported[dbName] = string(body)
		return nil
	})
	return recorder
}

// grantCommands answers the mysql.db lookup with the accounts given, and every
// other command with success.
func grantCommands(t *testing.T, accounts string) *commandRecorder {
	t.Helper()
	return withCommandScript(t, func(argv []string) (string, int) {
		if hasArgvPrefix(argv, []string{"mysql", "-N", "-B", "-e"}) && strings.Contains(argv[4], "FROM mysql.db") {
			return accounts, 0
		}
		return "", 0
	})
}

// statuses turns a restoreAllDBs result into "db: status" lines in name order,
// because the archive's databases are visited in map order.
func statuses(results []map[string]string) []string {
	out := make([]string, 0, len(results))
	for _, result := range results {
		line := result["db"] + ": " + result["status"]
		if message := result["message"]; message != "" {
			line += " (" + message + ")"
		}
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}

func dumpDir(t *testing.T, files map[string]string) string {
	t.Helper()
	tmp := t.TempDir()
	for name, body := range files {
		writeFixtureFile(t, filepath.Join(tmp, "__db__", name), body)
	}
	return tmp
}

// Every database in an archive ends in one of the statuses the result reports,
// and only the ones that came back carry their accounts back with them.
func TestRestoreAllDBsReportsEveryDatabaseItMeets(t *testing.T) {
	tmp := dumpDir(t, map[string]string{
		"c_example_main.sql": "-- main",
		"c_example_wp.sql":   "-- wp",
		"c_example_gone.sql": "-- gone",
		"mysql.sql":          "-- system",
		"bad-name.sql":       "-- invalid",
		dbUsersFileName: "CREATE USER IF NOT EXISTS 'c_example_user'@'localhost' IDENTIFIED BY PASSWORD '*abc';\n" +
			"GRANT ALL PRIVILEGES ON `c_example_main`.* TO 'c_example_user'@'localhost';\n" +
			"GRANT ALL PRIVILEGES ON `c_example_wp`.* TO 'c_example_user'@'localhost';\n",
	})
	script := &sqlScript{rows: map[string][][]driver.Value{
		ownedListQuery:  {{"c_example_wp"}},
		otherOwnerQuery: {{int64(0)}},
	}}
	imports := withImports(t, map[string]error{"c_example_wp": errors.New("import refused")})
	commands := grantCommands(t, "c_example_user\tlocalhost\n")

	results := restoreAllDBs(context.Background(), scriptDB(t, script), 1, tmp, "c_example", "")

	want := []string{
		"bad-name: error: invalid database name: \"bad-name\"",
		"c_example_gone: restored (user c_example_user restored)",
		"c_example_main: restored",
		"c_example_wp: error: import refused",
		"mysql: rejected (system database)",
	}
	if got := statuses(results); !slices.Equal(got, want) {
		t.Fatalf("results = %q, want %q", got, want)
	}
	if imports.imported["c_example_main"] != "-- main" || imports.imported["c_example_gone"] != "-- gone" {
		t.Errorf("imported = %v", imports.imported)
	}
	// The database whose panel record was gone is registered again and given the
	// account MySQL already holds for it.
	assertExecs(t, script, reRegisterInsert, []driver.Value{int64(1), "c_example_gone"})
	assertExecs(t, script, "UPDATE db_accounts SET db_user=? WHERE domain_id=? AND db_name=?",
		[]driver.Value{"c_example_user", int64(1), "c_example_gone"})
	assertAccountsApplied(t, commands)
}

// assertAccountsApplied checks that only grants on a restored database were
// applied, after the schemas existed, and that privileges were flushed.
func assertAccountsApplied(t *testing.T, commands *commandRecorder) {
	t.Helper()
	if !commands.ran("mysql", "-e", "GRANT ALL PRIVILEGES ON `c_example_main`.* TO 'c_example_user'@'localhost';") {
		t.Error("the grant on a restored database was not applied")
	}
	if commands.ran("mysql", "-e", "GRANT ALL PRIVILEGES ON `c_example_wp`.* TO 'c_example_user'@'localhost';") {
		t.Error("the grant on a database whose import failed was applied")
	}
	if !commands.ran("mysql", "-e", "CREATE USER IF NOT EXISTS 'c_example_user'@'localhost' IDENTIFIED BY PASSWORD '*abc';") ||
		!commands.ran("mysql", "-e", "FLUSH PRIVILEGES;") {
		t.Error("the account statements were not applied")
	}
	for _, name := range []string{"c_example_main", "c_example_gone"} {
		if !commands.ran("mysql", "-e", "CREATE DATABASE IF NOT EXISTS `"+name+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;") {
			t.Errorf("the schema of %s was not created before its import", name)
		}
	}
}

func TestRestoreAllDBsHonoursTheFilter(t *testing.T) {
	tmp := dumpDir(t, map[string]string{"c_example_main.sql": "-- main", "c_example_wp.sql": "-- wp"})
	script := &sqlScript{rows: map[string][][]driver.Value{ownedListQuery: {{"c_example_wp"}}}}
	imports := withImports(t, nil)
	withCommands(t)

	results := restoreAllDBs(context.Background(), scriptDB(t, script), 1, tmp, "c_example", "c_example_wp")

	if got := statuses(results); !slices.Equal(got, []string{"c_example_wp: restored"}) {
		t.Fatalf("results = %q", got)
	}
	if _, ok := imports.imported["c_example_main"]; ok {
		t.Error("a database outside the filter was imported")
	}
}

func TestRestoreAllDBsReportsAnUnreadableOwnershipList(t *testing.T) {
	tmp := dumpDir(t, map[string]string{"c_example_main.sql": "-- main"})
	script := &sqlScript{fail: map[string]error{ownedListQuery: errors.New("connection lost")}}
	imports := withImports(t, nil)

	results := restoreAllDBs(context.Background(), scriptDB(t, script), 1, tmp, "c_example", "")

	want := []string{": failed (could not list the domain's databases)"}
	if got := statuses(results); !slices.Equal(got, want) {
		t.Fatalf("results = %q, want %q", got, want)
	}
	if len(imports.imported) != 0 {
		t.Error("a database was imported without its ownership list")
	}
}

// A database the panel no longer records is restored only when no other domain
// holds the name, and without a recoverable account it says so.
func TestRestoreAllDBsRecoveryPathStatuses(t *testing.T) {
	cases := []struct {
		name   string
		script *sqlScript
		want   string
	}{
		{"registered to another domain", &sqlScript{rows: map[string][][]driver.Value{
			ownedListQuery: {}, otherOwnerQuery: {{int64(1)}},
		}}, "c_example_gone: rejected (registered to another domain)"},
		{"the ownership check fails closed", &sqlScript{
			rows: map[string][][]driver.Value{ownedListQuery: {}},
			fail: map[string]error{otherOwnerQuery: errors.New("timeout")},
		}, "c_example_gone: rejected (registered to another domain)"},
		{"no account can be recovered", &sqlScript{rows: map[string][][]driver.Value{
			ownedListQuery: {}, otherOwnerQuery: {{int64(0)}},
		}}, "c_example_gone: restored (panel record recreated — set a database user)"},
		{"the panel record cannot be written", &sqlScript{
			rows: map[string][][]driver.Value{ownedListQuery: {}, otherOwnerQuery: {{int64(0)}}},
			fail: map[string]error{reRegisterInsert: errors.New("duplicate")},
		}, "c_example_gone: restored (not registered in the panel — add it under Databases)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tmp := dumpDir(t, map[string]string{"c_example_gone.sql": "-- gone"})
			withImports(t, nil)
			grantCommands(t, "")

			results := restoreAllDBs(context.Background(), scriptDB(t, c.script), 1, tmp, "c_example", "")

			if got := statuses(results); !slices.Equal(got, []string{c.want}) {
				t.Fatalf("results = %q, want %q", got, c.want)
			}
		})
	}
}

// createRecorder stands in for credentials.MySQLCreateDBForUser.
type createRecorder struct {
	calls [][]any
	err   error
}

func withCreateDB(t *testing.T, err error) *createRecorder {
	t.Helper()
	recorder := &createRecorder{err: err}
	setForTest(t, &createDBForUser, func(_ *sql.DB, domainID int64, dbName, dbUser string) error {
		recorder.calls = append(recorder.calls, []any{domainID, dbName, dbUser})
		return recorder.err
	})
	return recorder
}

// oneDBCase is one target choice for restoreOneDB.
type oneDBCase struct {
	name, src, target string
	script            *sqlScript
	importFail        error
	createFail        error
	want              string
	wantErr           string
	wantCreate        []any
}

// A single database is restored over itself only when the domain owns it, and
// into a new name only when that name is the tenant's, valid and free.
func TestRestoreOneDBChoosesItsTarget(t *testing.T) {
	owned := map[string][][]driver.Value{
		ownedListQuery: {{"c_example_wp"}},
		"SELECT db_user FROM db_accounts WHERE domain_id=? AND db_name=? LIMIT 1": {{"c_example_user"}},
	}
	cases := []oneDBCase{
		{name: "not in the backup", src: "c_example_missing", script: &sqlScript{rows: owned},
			wantErr: `database "c_example_missing" is not in the backup`},
		{name: "the ownership list cannot be read", src: "c_example_main",
			script:  &sqlScript{fail: map[string]error{ownedListQuery: errors.New("lost")}},
			wantErr: "could not list the domain's databases"},
		{name: "over a database the domain does not own", src: "c_example_other", script: &sqlScript{rows: owned},
			wantErr: `"c_example_other" is not owned by this domain`},
		{name: "over a system database", src: "mysql", script: &sqlScript{rows: owned},
			wantErr: `"mysql" is not owned by this domain`},
		{name: "over itself, import fails", src: "c_example_main", target: "c_example_main", script: &sqlScript{rows: owned},
			importFail: errors.New("import refused"), wantErr: "import refused"},
		{name: "over itself", src: "c_example_main", script: &sqlScript{rows: owned},
			want: "restored over c_example_main"},
		{name: "into a name outside the tenant", src: "c_example_main", target: "c_other_copy", script: &sqlScript{rows: owned},
			wantErr: `invalid target name — must start with "c_example_"`},
		{name: "into an invalid name", src: "c_example_main", target: "c_example_bad-name", script: &sqlScript{rows: owned},
			wantErr: `invalid target name — must start with "c_example_"`},
		{name: "into a database that exists", src: "c_example_main", target: "c_example_wp", script: &sqlScript{rows: owned},
			wantErr: `"c_example_wp" already exists; leave the target empty to overwrite it`},
		{name: "the target cannot be created", src: "c_example_main", target: "c_example_copy", script: &sqlScript{rows: owned},
			createFail: errors.New("no grant"), wantErr: "could not create target database: no grant",
			wantCreate: []any{int64(1), "c_example_copy", "c_example_user"}},
		{name: "into a new name, import fails", src: "c_example_main", target: "c_example_copy", script: &sqlScript{rows: owned},
			importFail: errors.New("import refused"), wantErr: "import refused",
			wantCreate: []any{int64(1), "c_example_copy", "c_example_user"}},
		{name: "into a new name, fallback account", src: "c_example_main", target: "c_example_copy",
			script: &sqlScript{rows: map[string][][]driver.Value{
				ownedListQuery: {},
				"SELECT db_user FROM db_accounts WHERE domain_id=? AND db_name=? LIMIT 1": {},
				"SELECT db_user FROM db_accounts WHERE domain_id=? LIMIT 1":               {},
			}},
			want: "restored into new database c_example_copy", wantCreate: []any{int64(1), "c_example_copy", "c_example_db"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { runOneDBCase(t, c) })
	}
}

func runOneDBCase(t *testing.T, c oneDBCase) {
	t.Helper()
	tmp := dumpDir(t, map[string]string{
		"c_example_main.sql": "-- main", "c_example_other.sql": "-- other", "mysql.sql": "-- system",
	})
	failures := map[string]error{}
	if c.importFail != nil {
		failures[c.target] = c.importFail
		failures[c.src] = c.importFail
	}
	withImports(t, failures)
	creates := withCreateDB(t, c.createFail)
	withCommands(t)

	got, err := restoreOneDB(context.Background(), scriptDB(t, c.script), 1, tmp, "c_example", c.src, c.target)

	assertOutcome(t, got, err, c.want, c.wantErr)
	if c.wantCreate == nil && len(creates.calls) != 0 {
		t.Errorf("a target database was created: %v", creates.calls)
	}
	if c.wantCreate != nil && (len(creates.calls) != 1 || !slices.Equal(creates.calls[0], c.wantCreate)) {
		t.Errorf("create calls = %v, want %v", creates.calls, c.wantCreate)
	}
}
