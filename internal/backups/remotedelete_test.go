package backups

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
)

// A recording driver in the same shape as internal/mail's. What has to be
// asserted is whether a deletion path ever asks for the domain's destination,
// which is the only step that can reach the remote copy.
type remoteRecorder struct {
	mu    sync.Mutex
	steps []string
}

func (r *remoteRecorder) record(query string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, strings.Join(strings.Fields(query), " "))
}

func (r *remoteRecorder) askedForTheDestination() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, step := range r.steps {
		if strings.Contains(step, "FROM backup_destinations WHERE domain_id=?") {
			return true
		}
	}
	return false
}

var (
	remoteStateMu sync.Mutex
	remoteState   = map[string]*remoteRecorder{}
)

type remoteDriver struct{}

func (remoteDriver) Open(name string) (driver.Conn, error) {
	remoteStateMu.Lock()
	defer remoteStateMu.Unlock()
	recorder, ok := remoteState[name]
	if !ok {
		return nil, fmt.Errorf("no recorder registered for %q", name)
	}
	return &remoteConn{recorder: recorder}, nil
}

func init() { sql.Register("backups_remote_recorder", remoteDriver{}) }

type remoteConn struct{ recorder *remoteRecorder }

func (c *remoteConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not used by this test")
}
func (c *remoteConn) Close() error              { return nil }
func (c *remoteConn) Begin() (driver.Tx, error) { return nil, errors.New("no transactions here") }

func (c *remoteConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.recorder.record(query)
	return retentionResult{}, nil
}

// QueryContext answers the lookups each deletion path makes before it can act.
// The destination lookup is recorded and then answered EMPTY, so the test never
// reaches a network call while still proving the path asked.
func (c *remoteConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.recorder.record(query)
	switch {
	case strings.Contains(query, "type='scheduled'"):
		return &retentionRows{
			columns: []string{"id", "file", "remote_status"},
			values: [][]driver.Value{
				{int64(2), "c_example-auto-new.tar.gz", "successful"},
				{int64(1), "c_example-auto-old.tar.gz", "successful"},
			},
		}, nil
	case strings.Contains(query, "type='full'"):
		return &retentionRows{
			columns: []string{"id", "file", "remote_status"},
			values:  [][]driver.Value{{int64(3), "c_example-old.tar.gz", "successful"}},
		}, nil
	case strings.Contains(query, "FROM backups b"):
		return &retentionRows{
			columns: []string{"system_user", "file", "remote_status"},
			values:  [][]driver.Value{{"c_example", "c_example-old.tar.gz", "successful"}},
		}, nil
	}
	return &retentionRows{}, nil
}

func remoteRecorderDB(t *testing.T) (*sql.DB, *remoteRecorder) {
	t.Helper()
	recorder := &remoteRecorder{}
	name := "remote-" + t.Name()
	remoteStateMu.Lock()
	remoteState[name] = recorder
	remoteStateMu.Unlock()
	db, err := sql.Open("backups_remote_recorder", name)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, recorder
}

// Only an upload that reported success wrote an object. Sending a delete for a
// failed or never-started upload would name something that was never there, and
// on lftp that is an error the log then carries on every prune.
func TestOnlyAnUploadedCopyIsDeletedRemotely(t *testing.T) {
	for _, status := range []string{"", "uploading", "failed"} {
		db, recorder := remoteRecorderDB(t)
		removeRemoteCopy(db, 1, "c_example-old.tar.gz", status)
		if recorder.askedForTheDestination() {
			t.Fatalf("remote_status=%q still reached the destination", status)
		}
	}
	db, recorder := remoteRecorderDB(t)
	removeRemoteCopy(db, 1, "c_example-old.tar.gz", "successful")
	if !recorder.askedForTheDestination() {
		t.Fatal("an uploaded copy was never looked up, so it is never deleted")
	}
	// An empty file name would delete the destination directory's own entry.
	db, recorder = remoteRecorderDB(t)
	removeRemoteCopy(db, 1, "", "successful")
	if recorder.askedForTheDestination() {
		t.Fatal("an empty file name reached the destination")
	}
}

// Scheduled retention drops the archives past the keep count. Removing only the
// local file left the bucket growing for good.
func TestScheduledRetentionDeletesTheRemoteCopy(t *testing.T) {
	t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())
	db, recorder := remoteRecorderDB(t)
	if err := pruneOld(db, 1, "c_example", 1); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if !recorder.askedForTheDestination() {
		t.Fatal("a pruned scheduled backup kept its remote copy")
	}
}

// Manual retention has the same gap and the same fix.
func TestManualRetentionDeletesTheRemoteCopy(t *testing.T) {
	t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())
	db, recorder := remoteRecorderDB(t)
	pruneManualBackups(db, 1, "c_example")
	if !recorder.askedForTheDestination() {
		t.Fatal("a pruned manual backup kept its remote copy")
	}
}

// The delete button is the one the customer presses believing the backup is
// gone, so it is the worst place to leave a copy behind.
func TestDeletingABackupDeletesTheRemoteCopy(t *testing.T) {
	t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())
	db, recorder := remoteRecorderDB(t)

	route := chi.NewRouteContext()
	route.URLParams.Add("id", "1")
	route.URLParams.Add("bid", "3")
	r := httptest.NewRequest(http.MethodDelete, "/domains/1/backups/3", nil).
		WithContext(context.WithValue(context.Background(), chi.RouteCtxKey, route))

	w := httptest.NewRecorder()
	(&Handlers{DB: db}).Delete(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("delete answered %d: %s", w.Code, w.Body.String())
	}
	if !recorder.askedForTheDestination() {
		t.Fatal("a deleted backup kept its remote copy")
	}
}
