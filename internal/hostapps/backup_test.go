package hostapps

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A scripted driver for the backup rows. The existing recorder in switch_test.go
// answers one setting; these tests need a table of archives, because what is
// being pinned is which row a restore accepts and which files a rotation takes
// away.

type backupRow struct {
	id int64
	// appID defaults to the test application when zero. A row naming another
	// application is what proves the id lookup narrows on app_id.
	appID int64
	path  string
	sha   string
}

func (r backupRow) owner() int64 {
	if r.appID == 0 {
		return testAppID
	}
	return r.appID
}

const testAppID = 9

type backupScript struct {
	mu       sync.Mutex
	rows     []backupRow
	deleted  []int64
	statemnt []string
}

func (s *backupScript) record(query string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statemnt = append(s.statemnt, query)
}

func (s *backupScript) ran(fragment string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, query := range s.statemnt {
		if strings.Contains(query, fragment) {
			return true
		}
	}
	return false
}

var (
	backupMu    sync.Mutex
	backupState = map[string]*backupScript{}
	backupOnce  sync.Once
)

type backupDriver struct{}

func (backupDriver) Open(name string) (driver.Conn, error) {
	backupMu.Lock()
	defer backupMu.Unlock()
	script, ok := backupState[name]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return &backupConn{script: script}, nil
}

type backupConn struct{ script *backupScript }

func (c *backupConn) Prepare(query string) (driver.Stmt, error) {
	c.script.record(query)
	return &backupStmt{script: c.script, query: query}, nil
}
func (c *backupConn) Close() error              { return nil }
func (c *backupConn) Begin() (driver.Tx, error) { return nil, io.ErrUnexpectedEOF }

type backupStmt struct {
	script *backupScript
	query  string
}

func (s *backupStmt) Close() error  { return nil }
func (s *backupStmt) NumInput() int { return -1 }

func (s *backupStmt) Exec(args []driver.Value) (driver.Result, error) {
	if strings.Contains(s.query, "DELETE FROM host_app_backups") && len(args) > 0 {
		if id, ok := args[0].(int64); ok {
			s.script.mu.Lock()
			s.script.deleted = append(s.script.deleted, id)
			s.script.mu.Unlock()
		}
	}
	return driver.RowsAffected(1), nil
}

var backupColumns = []string{
	"id", "app_id", "code", "archive_path", "size_bytes", "sha256", "note", "created_at",
}

func (s *backupStmt) Query(args []driver.Value) (driver.Rows, error) {
	if !strings.Contains(s.query, "host_app_backups") {
		return &backupRows{columns: []string{"x"}}, nil
	}
	// The id lookup and the list read the same columns; they are told apart by
	// the id predicate, because a restore must not be answered by the first row
	// of the list.
	if strings.Contains(s.query, "WHERE id=?") {
		return s.single(args)
	}
	values := make([][]driver.Value, 0, len(s.script.rows))
	for _, row := range s.script.rows {
		values = append(values, rowValues(row))
	}
	return &backupRows{columns: backupColumns, values: values}, nil
}

// single answers the id lookup by applying the predicates the STATEMENT names,
// the way the database would: app_id is only honoured when the query asks for
// it. A lookup that dropped that clause would let one application restore
// another's tree, and a fake that narrowed on app_id regardless would hide it.
func (s *backupStmt) single(args []driver.Value) (driver.Rows, error) {
	wanted, _ := args[0].(int64)
	byOwner := strings.Contains(s.query, "app_id=?") && len(args) > 1
	owner := int64(0)
	if byOwner {
		owner, _ = args[1].(int64)
	}
	for _, row := range s.script.rows {
		if row.id != wanted || (byOwner && row.owner() != owner) {
			continue
		}
		return &backupRows{columns: backupColumns,
			values: [][]driver.Value{rowValues(row)}}, nil
	}
	return &backupRows{columns: backupColumns}, nil
}

func rowValues(row backupRow) []driver.Value {
	return []driver.Value{row.id, row.owner(), "gitea", row.path,
		int64(1024), row.sha, "", time.Unix(0, 0).UTC()}
}

type backupRows struct {
	columns []string
	values  [][]driver.Value
	at      int
}

func (r *backupRows) Columns() []string { return r.columns }
func (r *backupRows) Close() error      { return nil }
func (r *backupRows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

func openBackupScript(t *testing.T, script *backupScript) *sql.DB {
	t.Helper()
	backupOnce.Do(func() { sql.Register("hostapps-backups", backupDriver{}) })

	name := t.Name()
	backupMu.Lock()
	backupState[name] = script
	backupMu.Unlock()

	db, err := sql.Open("hostapps-backups", name)
	if err != nil {
		t.Fatalf("open the scripted database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// testApp is the application every test here operates on.
func testApp() App {
	return App{ID: 9, Code: "gitea", Name: "Gitea", Port: 3000,
		SystemUser: "servika-gitea", State: "installed"}
}

// Each application's archives live in their own directory, so a rotation
// driven by one application's row count cannot reach another's files.
func TestEachApplicationKeepsItsArchivesInItsOwnDirectory(t *testing.T) {
	t.Setenv("SERVIKA_HOST_APP_BACKUP_DIR", "/var/lib/servika/host-app-backups")

	if got := BackupDir("gitea"); got != "/var/lib/servika/host-app-backups/gitea" {
		t.Errorf("BackupDir = %q", got)
	}
	if BackupDir("gitea") == BackupDir("grafana") {
		t.Error("two applications share one backup directory")
	}
}

// The unit file and the EnvironmentFile travel WITH the tree. A restore that
// put back only the install directory would leave the unit naming arguments the
// restored version does not take, and the env file carries the token the
// application was installed with.
func TestTheUnitAndEnvironmentFileAreArchivedWithTheTree(t *testing.T) {
	target := backupTarget(testApp())

	if target.Root != InstallDir("gitea") {
		t.Errorf("Root = %q, want the install directory", target.Root)
	}
	if len(target.Extra) != 2 ||
		target.Extra[0] != UnitPath("gitea") || target.Extra[1] != EnvPath("gitea") {
		t.Errorf("Extra = %v, want the unit file and the env file", target.Extra)
	}
	if target.Port != 3000 {
		t.Errorf("Port = %d, want the application's own port", target.Port)
	}
}

// A row written before this feature existed carries no digest, and the listing
// says so rather than offering a restore that cannot be verified.
func TestARowWithoutADigestIsListedAsNotRestorable(t *testing.T) {
	script := &backupScript{rows: []backupRow{
		{id: 2, path: "/var/lib/servika/host-app-backups/gitea/new.tar.gz", sha: strings.Repeat("a", 64)},
		{id: 1, path: "/var/lib/servika/host-app-backups/gitea-old.tar.gz"},
	}}
	db := openBackupScript(t, script)

	list, err := ListBackups(context.Background(), db, 9)

	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d rows, want 2", len(list))
	}
	if !list[0].Restorable {
		t.Error("a row with a digest was reported as not restorable")
	}
	if list[1].Restorable {
		t.Error("a row with no digest was offered as restorable")
	}
}

// Restoring an archive with no digest is refused. Unpacking an unverifiable
// file over a working tree is exactly the risk the digest exists to close.
func TestRestoringAnArchiveWithNoDigestIsRefused(t *testing.T) {
	script := &backupScript{rows: []backupRow{
		{id: 1, path: "/var/lib/servika/host-app-backups/gitea-old.tar.gz"},
	}}
	db := openBackupScript(t, script)

	err := RestoreBackup(context.Background(), db, testApp(), 1)

	if err == nil {
		t.Fatal("an archive with no digest was restored")
	}
	if ReasonOf(err) != ReasonNotFound {
		t.Errorf("reason = %q, want %q", ReasonOf(err), ReasonNotFound)
	}
}

// A backup id that belongs to another application is not found. The id
// predicate carries app_id for that reason, and a lookup on the id alone would
// let one application restore another's tree.
func TestABackupOfAnotherApplicationIsNotFound(t *testing.T) {
	db := openBackupScript(t, &backupScript{rows: []backupRow{
		{id: 44, appID: 12, path: "/var/lib/servika/host-app-backups/grafana/one.tar.gz",
			sha: strings.Repeat("e", 64)},
	}})

	err := RestoreBackup(context.Background(), db, testApp(), 44)

	if ReasonOf(err) != ReasonNotFound {
		t.Fatalf("err = %v, want a not-found refusal", err)
	}
}

// The rotation keeps the newest archives and drops the rest, file and row
// together.
func TestTheRotationDropsEverythingPastTheNewestFive(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVIKA_HOST_APP_BACKUP_DIR", dir)
	appDir := filepath.Join(dir, "gitea")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatalf("create the backup directory: %v", err)
	}
	script := &backupScript{}
	for id := int64(7); id >= 1; id-- {
		path := filepath.Join(appDir, "archive-"+string(rune('a'+id))+".tar.gz")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		script.rows = append(script.rows, backupRow{id: id, path: path, sha: strings.Repeat("b", 64)})
	}
	db := openBackupScript(t, script)

	rotateBackups(context.Background(), db, testApp())

	left, err := os.ReadDir(appDir)
	if err != nil {
		t.Fatalf("read the backup directory: %v", err)
	}
	if len(left) != 5 {
		t.Errorf("%d archives are left, want 5", len(left))
	}
	if len(script.deleted) != 2 {
		t.Errorf("%d rows were deleted, want 2", len(script.deleted))
	}
}

// A rotation with fewer archives than the ceiling deletes nothing.
func TestTheRotationLeavesAShortListAlone(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVIKA_HOST_APP_BACKUP_DIR", dir)
	script := &backupScript{rows: []backupRow{
		{id: 1, path: filepath.Join(dir, "gitea", "one.tar.gz"), sha: strings.Repeat("c", 64)},
	}}
	db := openBackupScript(t, script)

	rotateBackups(context.Background(), db, testApp())

	if len(script.deleted) != 0 {
		t.Errorf("%d rows were deleted from a list of one", len(script.deleted))
	}
}

// Deleting an archive takes the file first and the row second. A row with no
// file offers a restore that cannot run; a file with no row is invisible and is
// never rotated away.
func TestDeletingAnArchiveTakesTheFileAndThenTheRow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SERVIKA_HOST_APP_BACKUP_DIR", dir)
	appDir := filepath.Join(dir, "gitea")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatalf("create the backup directory: %v", err)
	}
	path := filepath.Join(appDir, "one.tar.gz")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	script := &backupScript{rows: []backupRow{
		{id: 1, path: path, sha: strings.Repeat("d", 64)},
	}}
	db := openBackupScript(t, script)

	if err := DeleteBackup(context.Background(), db, testApp(), 1); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the archive is still on disk: %v", err)
	}
	if !script.ran("DELETE FROM host_app_backups") {
		t.Error("the row was left behind")
	}
}
