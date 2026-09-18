package apps

import (
	"context"
	"database/sql/driver"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// backupApp is the application these tests operate on.
func backupApp() App {
	return App{ID: 4, DomainID: 7, Name: "api", Runtime: "node",
		AppRoot: "app", Port: 31000, Enabled: true}
}

// backupRow is one app_backups row in SELECT order.
func backupRow(id int64, path string) []driver.Value {
	return []driver.Value{id, int64(4), int64(7), path,
		int64(2048), strings.Repeat("a", 64), "", time.Unix(0, 0).UTC()}
}

const (
	listFragment   = "FROM app_backups WHERE app_id=? AND domain_id=?"
	singleFragment = "FROM app_backups WHERE id=? AND app_id=? AND domain_id=?"
)

// Each application keeps its archives in its own directory, and that directory
// is outside every tenant home: the tree being archived is writable by the
// account that owns it, so an archive kept inside it could be replaced by the
// very account it protects.
func TestAnApplicationKeepsItsArchivesOutsideTheTenantHome(t *testing.T) {
	t.Setenv("SERVIKA_APP_BACKUP_DIR", "/var/lib/servika/app-backups")

	dir := BackupDir(4)

	if dir != "/var/lib/servika/app-backups/4" {
		t.Errorf("BackupDir = %q", dir)
	}
	if strings.HasPrefix(dir, "/home/") {
		t.Error("the archives sit inside a tenant home")
	}
	if BackupDir(4) == BackupDir(5) {
		t.Error("two applications share one backup directory")
	}
}

// The application root is resolved through SafeAppDir on every call rather than
// read from the row: the field is home-relative, the home belongs to the
// tenant, and a path that no longer resolves must stop the archive.
func TestAnApplicationRootThatLeavesTheHomeIsRefused(t *testing.T) {
	app := backupApp()
	app.AppRoot = "../../etc"

	if _, err := backupTarget(app, "c_example"); err == nil {
		t.Fatal("an application root outside the home was accepted")
	}
}

// The unit file and the EnvironmentFile travel WITH the tree, and the probe
// uses the application's own port.
func TestTheUnitAndEnvironmentFileAreArchivedWithTheTree(t *testing.T) {
	target, err := backupTarget(backupApp(), "c_example")

	if err != nil {
		t.Fatalf("target: %v", err)
	}
	if !strings.HasSuffix(target.Root, "/c_example/app") {
		t.Errorf("Root = %q, want the resolved application directory", target.Root)
	}
	if len(target.Extra) != 2 ||
		target.Extra[0] != UnitPath(4) || target.Extra[1] != EnvPath(4) {
		t.Errorf("Extra = %v, want the unit file and the env file", target.Extra)
	}
	if target.Port != 31000 {
		t.Errorf("Port = %d, want the application's own port", target.Port)
	}
	if target.Stop == nil || target.Start == nil {
		t.Error("the target carries no unit control")
	}
}

// The listing narrows on the domain as well as the application. The ownership
// chain the route checked is the DOMAIN's, so an application id on its own
// would answer for another customer's row.
func TestTheListingNarrowsOnTheDomainAsWellAsTheApplication(t *testing.T) {
	script := newScript()
	script.rows[listFragment] = [][]driver.Value{
		backupRow(2, "/var/lib/servika/app-backups/4/b.tar.gz"),
		backupRow(1, "/var/lib/servika/app-backups/4/a.tar.gz"),
	}
	db := scriptDB(t, script)

	list, err := ListBackups(context.Background(), db, 7, 4)

	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d rows, want 2", len(list))
	}
	if list[0].ID != 2 {
		t.Errorf("the newest row is %d, want 2", list[0].ID)
	}
}

// A backup id that belongs to another domain is not found, because the lookup
// carries the domain.
func TestABackupOfAnotherDomainIsNotFound(t *testing.T) {
	script := newScript()
	script.rows[singleFragment] = nil
	db := scriptDB(t, script)

	err := DeleteBackup(context.Background(), db, backupApp(), 99)

	if err == nil {
		t.Fatal("a backup from another domain was deleted")
	}
	if script.ran("DELETE FROM app_backups") {
		t.Error("the delete statement ran for a row that was not found")
	}
}

// Deleting an archive takes the file first and the row second. A row with no
// file offers a restore that cannot run; a file with no row is invisible and is
// never rotated away.
func TestDeletingAnArchiveTakesTheFileAndThenTheRow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVIKA_APP_BACKUP_DIR", dir)
	path := writeArchiveFile(t, dir, 4, "one.tar.gz")

	script := newScript()
	script.rows[singleFragment] = [][]driver.Value{backupRow(1, path)}
	db := scriptDB(t, script)

	if err := DeleteBackup(context.Background(), db, backupApp(), 1); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the archive is still on disk: %v", err)
	}
	args := script.argsOf(t, "DELETE FROM app_backups")
	if len(args) != 3 {
		t.Fatalf("the delete carries %d arguments, want the backup, the application and the domain", len(args))
	}
}

// The rotation drops everything past the newest five, file and row together.
func TestTheRotationDropsEverythingPastTheNewestFive(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVIKA_APP_BACKUP_DIR", dir)

	script := newScript()
	var listed [][]driver.Value
	for id := int64(7); id >= 1; id-- {
		path := writeArchiveFile(t, dir, 4, "archive-"+strconv.FormatInt(id, 10)+".tar.gz")
		listed = append(listed, backupRow(id, path))
	}
	script.rows[listFragment] = listed
	// Each delete looks its row up first. The script answers every lookup with
	// the same row, so what this measures is HOW MANY deletes the rotation
	// issued, which is the number the ceiling decides.
	script.rows[singleFragment] = [][]driver.Value{listed[len(listed)-1]}
	db := scriptDB(t, script)

	rotateBackups(context.Background(), db, backupApp())

	if deletes := countDeletes(script); deletes != 2 {
		t.Errorf("the rotation issued %d deletes over seven archives, want 2", deletes)
	}
	if _, err := os.Stat(filepath.Join(dir, "4", "archive-1.tar.gz")); !os.IsNotExist(err) {
		t.Errorf("the oldest archive is still on disk: %v", err)
	}
}

func countDeletes(script *sqlScript) int {
	script.mu.Lock()
	defer script.mu.Unlock()
	n := 0
	for _, exec := range script.execs {
		if strings.Contains(exec.query, "DELETE FROM app_backups") {
			n++
		}
	}
	return n
}

// A list shorter than the ceiling is left alone.
func TestTheRotationLeavesAShortListAlone(t *testing.T) {
	t.Setenv("SERVIKA_APP_BACKUP_DIR", t.TempDir())
	script := newScript()
	script.rows[listFragment] = [][]driver.Value{
		backupRow(1, "/var/lib/servika/app-backups/4/one.tar.gz"),
	}
	db := scriptDB(t, script)

	rotateBackups(context.Background(), db, backupApp())

	if script.ran("DELETE FROM app_backups") {
		t.Error("a list of one archive was rotated")
	}
}

func writeArchiveFile(t *testing.T, root string, appID int64, name string) string {
	t.Helper()
	dir := filepath.Join(root, strconv.FormatInt(appID, 10))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create the backup directory: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write the archive: %v", err)
	}
	return path
}
