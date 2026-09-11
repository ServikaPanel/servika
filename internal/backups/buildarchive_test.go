package backups

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

const completeDump = "CREATE TABLE t (id INT);\n-- Dump completed on 2026-01-01 00:00:00\n"

// archiveRun is what the fake tar saw in the staging directory at the moment it
// packaged it, because the staging directory is removed before buildArchive
// returns.
type archiveRun struct {
	mu       sync.Mutex
	staged   []string
	manifest string
	users    string
}

// archiveCommands answers the three kinds of command a backup runs: mysqldump
// through bash writes the body the test gives each database (FAIL exits 1 after
// a partial write), tar czf records the staging directory and writes the
// archive, and mysql answers the account lookups for c_example_main.
func archiveCommands(t *testing.T, dumps map[string]string, tarExit int) (*commandRecorder, *archiveRun) {
	t.Helper()
	run := &archiveRun{}
	recorder := withCommandScript(t, func(argv []string) (string, int) {
		switch {
		case hasArgvPrefix(argv, []string{"bash", "-c"}):
			return dumpResponse(argv[2], dumps)
		case hasArgvPrefix(argv, []string{"tar", "czf"}):
			return run.capture(argv, tarExit)
		case hasArgvPrefix(argv, []string{"mysql", "-N", "-B", "-e"}):
			return accountAnswer(argv[4]), 0
		}
		return "", 0
	})
	return recorder, run
}

// dumpTarget reads the database and the file out of the mysqldump command line.
func dumpTarget(script string) (dbName, target string) {
	before, after, _ := strings.Cut(script, "' > '")
	return before[strings.LastIndex(before, "'")+1:], strings.TrimSuffix(after, "' 2>/dev/null")
}

func dumpResponse(script string, dumps map[string]string) (string, int) {
	dbName, target := dumpTarget(script)
	body := dumps[dbName]
	if body == "FAIL" {
		_ = os.WriteFile(target, []byte("partial"), 0o600)
		return "", 1
	}
	if err := os.WriteFile(target, []byte(body), 0o600); err != nil {
		return err.Error(), 2
	}
	return "", 0
}

// capture reads the staging directory tar was asked to package: argv is
// tar czf <archive> -C /home <user> -C <dir> __db__.
func (r *archiveRun) capture(argv []string, exitCode int) (string, int) {
	dbDir := filepath.Join(argv[7], "__db__")
	entries, _ := os.ReadDir(dbDir)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, entry := range entries {
		r.staged = append(r.staged, entry.Name())
	}
	manifest, _ := os.ReadFile(filepath.Join(dbDir, "manifest.json")) // #nosec G304 -- the test's staging directory.
	users, _ := os.ReadFile(filepath.Join(dbDir, dbUsersFileName))    // #nosec G304 -- the test's staging directory.
	r.manifest, r.users = string(manifest), string(users)
	if err := os.WriteFile(argv[2], []byte(localArchiveBytes), 0o600); err != nil {
		return err.Error(), 2
	}
	return "tar said something", exitCode
}

func accountAnswer(query string) string {
	switch {
	case strings.Contains(query, "FROM mysql.db"):
		return "c_example_user\tlocalhost\n"
	case strings.HasPrefix(query, "SHOW CREATE USER "):
		return "CREATE USER `c_example_user`@`localhost` IDENTIFIED BY PASSWORD '*abc'\n"
	case strings.HasPrefix(query, "SHOW GRANTS FOR "):
		return "GRANT USAGE ON *.* TO `c_example_user`@`localhost`\n" +
			"GRANT ALL PRIVILEGES ON `c_example_main`.* TO `c_example_user`@`localhost`\n" +
			"GRANT SELECT ON `mysql`.* TO `c_example_user`@`localhost`\n"
	}
	return ""
}

// A backup packages the home and every dump that completed, and names the ones
// that did not in the manifest and in its return value.
func TestBuildArchivePackagesTheHomeAndEveryCompleteDump(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "c_example")
	script := &sqlScript{rows: map[string][][]driver.Value{
		ownedListQuery: {{"c_example_wp"}, {"c_example_shop"}, {"c_example_blog"}},
	}}
	commands, run := archiveCommands(t, map[string]string{
		"c_example_main": completeDump,
		"c_example_wp":   "CREATE TABLE t (id INT);\n",
		"c_example_shop": "FAIL",
		"c_example_blog": "",
	}, 0)
	const file = "c_example-20260101-000000.tar.gz"

	size, failed, err := buildArchive(context.Background(), scriptDB(t, script), 7, "c_example", dir, file, "2026-01-01 00:00:00")

	if err != nil || size != int64(len(localArchiveBytes)) {
		t.Fatalf("buildArchive = (%d, %v), want the archive size and no error", size, err)
	}
	if want := []string{"c_example_wp", "c_example_shop", "c_example_blog"}; !slices.Equal(failed, want) {
		t.Errorf("failed = %v, want %v", failed, want)
	}
	if !commands.ran("tar", "czf", filepath.Join(dir, file), "-C", "/home", "c_example", "-C", dir, "__db__") {
		t.Errorf("tar ran as %v", commands.argvs())
	}
	wantDump := "mysqldump --single-transaction --skip-lock-tables --routines --events --triggers " +
		"--default-character-set=utf8mb4 --hex-blob 'c_example_main' > '" +
		filepath.Join(dir, "__db__", "c_example_main.sql") + "' 2>/dev/null"
	if !commands.ran("bash", "-c", wantDump) {
		t.Errorf("mysqldump ran as %v", commands.argvs())
	}
	assertStaged(t, run, failed)
	if _, err := os.Stat(filepath.Join(dir, "__db__")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the staging directory outlived the backup: %v", err)
	}
}

// assertStaged checks what tar packaged: the complete dump, the manifest naming
// every database and the account file for the dumped one.
func assertStaged(t *testing.T, run *archiveRun, failed []string) {
	t.Helper()
	if want := []string{"c_example_main.sql", "manifest.json", dbUsersFileName}; !slices.Equal(run.staged, want) {
		t.Errorf("tar packaged %v, want %v", run.staged, want)
	}
	var manifest archiveManifest
	if err := json.Unmarshal([]byte(run.manifest), &manifest); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	wantManifest := archiveManifest{
		CreatedAt: "2026-01-01 00:00:00", Home: "c_example", MainDB: "c_example_main",
		Databases: []string{"c_example_main"}, FailedDatabases: failed,
	}
	if !reflect.DeepEqual(manifest, wantManifest) {
		t.Errorf("manifest = %+v, want %+v", manifest, wantManifest)
	}
	wantUsers := "-- servika: database users and grants\n" +
		"-- On restore only grants on this archive's own databases are applied.\n" +
		"CREATE USER IF NOT EXISTS `c_example_user`@`localhost` IDENTIFIED BY PASSWORD '*abc';\n" +
		"GRANT USAGE ON *.* TO `c_example_user`@`localhost`;\n" +
		"GRANT ALL PRIVILEGES ON `c_example_main`.* TO `c_example_user`@`localhost`;\n"
	if run.users != wantUsers {
		t.Errorf("users.sql = %q, want %q", run.users, wantUsers)
	}
}

// An archive of a site whose every dump failed is not a backup of the site.
func TestBuildArchiveFailsWhenNoDumpCompleted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "c_example")
	script := &sqlScript{rows: map[string][][]driver.Value{ownedListQuery: {{"c_example_wp"}}}}
	commands, _ := archiveCommands(t, map[string]string{"c_example_main": "FAIL", "c_example_wp": "FAIL"}, 0)

	size, failed, err := buildArchive(context.Background(), scriptDB(t, script), 7, "c_example", dir, "out.tar.gz", "2026-01-01 00:00:00")

	if err == nil || err.Error() != "none of the domain's 2 database(s) could be dumped" || size != 0 {
		t.Fatalf("buildArchive = (%d, %v), want the total-loss error", size, err)
	}
	if !slices.Equal(failed, []string{"c_example_main", "c_example_wp"}) {
		t.Errorf("failed = %v", failed)
	}
	if commands.ran("tar") {
		t.Error("an archive was written without any database")
	}
}

func TestBuildArchiveRefusesAnUnreadableDatabaseList(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "c_example")
	script := &sqlScript{fail: map[string]error{ownedListQuery: errors.New("connection lost")}}
	commands, _ := archiveCommands(t, nil, 0)

	size, failed, err := buildArchive(context.Background(), scriptDB(t, script), 7, "c_example", dir, "out.tar.gz", "2026-01-01 00:00:00")

	if err == nil || err.Error() != "could not list the domain's databases" || size != 0 || failed != nil {
		t.Fatalf("buildArchive = (%d, %v, %v), want the list error", size, failed, err)
	}
	if len(commands.argvs()) != 0 {
		t.Errorf("commands ran without a database list: %v", commands.argvs())
	}
}

// buildWithTarExit builds an archive of one complete dump under a tar that exits
// with code, and returns the archive path beside the result.
func buildWithTarExit(t *testing.T, code int) (string, int64, []string, error) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "c_example")
	script := &sqlScript{rows: map[string][][]driver.Value{ownedListQuery: {}}}
	archiveCommands(t, map[string]string{"c_example_main": completeDump}, code)
	size, failed, err := buildArchive(context.Background(), scriptDB(t, script), 7, "c_example", dir, "out.tar.gz", "2026-01-01 00:00:00")
	return filepath.Join(dir, "out.tar.gz"), size, failed, err
}

// tar exit 1 means a file changed while it was read, and the archive is still
// complete.
func TestBuildArchiveKeepsAnArchiveTarReportedAsChanged(t *testing.T) {
	abs, size, failed, err := buildWithTarExit(t, 1)
	if err != nil || size != int64(len(localArchiveBytes)) || len(failed) != 0 {
		t.Fatalf("buildArchive = (%d, %v, %v), want the archive kept", size, failed, err)
	}
	if _, statErr := os.Stat(abs); statErr != nil {
		t.Errorf("the archive was removed: %v", statErr)
	}
}

// Exit 2 is a real failure, and the archive is removed.
func TestBuildArchiveDiscardsAnArchiveTarFailedOn(t *testing.T) {
	abs, size, failed, err := buildWithTarExit(t, 2)
	if err == nil || err.Error() != "tar: tar said something: exit status 2" || size != 0 || len(failed) != 0 {
		t.Fatalf("buildArchive = (%d, %v, %v), want the tar error", size, failed, err)
	}
	if _, statErr := os.Stat(abs); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the failed archive was kept: %v", statErr)
	}
}
