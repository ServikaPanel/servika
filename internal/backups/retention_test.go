package backups

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// A recording driver, in the same shape as internal/mail's: the repository has
// no sqlmock dependency, and what has to be asserted here is which statements a
// scheduler tick issues when the archive itself fails.
type retentionRecorder struct {
	mu    sync.Mutex
	steps []string
}

func (r *retentionRecorder) record(query string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, strings.Join(strings.Fields(query), " "))
}

func (r *retentionRecorder) sawQueryContaining(parts ...string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, step := range r.steps {
		hit := true
		for _, part := range parts {
			if !strings.Contains(step, part) {
				hit = false
				break
			}
		}
		if hit {
			return true
		}
	}
	return false
}

var (
	retentionStateMu sync.Mutex
	retentionState   = map[string]*retentionRecorder{}
)

type retentionDriver struct{}

func (retentionDriver) Open(name string) (driver.Conn, error) {
	retentionStateMu.Lock()
	defer retentionStateMu.Unlock()
	recorder, ok := retentionState[name]
	if !ok {
		return nil, fmt.Errorf("no recorder registered for %q", name)
	}
	return &retentionConn{recorder: recorder}, nil
}

func init() { sql.Register("backups_retention_recorder", retentionDriver{}) }

type retentionConn struct{ recorder *retentionRecorder }

func (c *retentionConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not used by this test")
}
func (c *retentionConn) Close() error              { return nil }
func (c *retentionConn) Begin() (driver.Tx, error) { return nil, errors.New("no transactions here") }

func (c *retentionConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.recorder.record(query)
	return retentionResult{}, nil
}

// QueryContext answers the one lookup the tick needs to find a due domain and
// returns nothing for everything else, which surfaces as an empty result rather
// than an error.
func (c *retentionConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.recorder.record(query)
	if strings.Contains(query, "FROM domains") && strings.Contains(query, "backup_freq") {
		return &retentionRows{
			columns: []string{"id", "domain_name", "system_user", "backup_freq", "backup_hour",
				"backup_retention", "is_demo", "last_backup_at"},
			// The hour is never re-checked in Go, so the value only has to scan:
			// the tick binds it into the WHERE clause, which this driver ignores.
			values: [][]driver.Value{{int64(1), "example.com", "c_example", "daily", int64(3),
				int64(7), int64(0), nil}},
		}, nil
	}
	return &retentionRows{}, nil
}

type retentionResult struct{}

func (retentionResult) LastInsertId() (int64, error) { return 1, nil }
func (retentionResult) RowsAffected() (int64, error) { return 1, nil }

type retentionRows struct {
	columns []string
	values  [][]driver.Value
	pos     int
}

func (r *retentionRows) Columns() []string { return r.columns }
func (r *retentionRows) Close() error      { return nil }
func (r *retentionRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.pos])
	r.pos++
	return nil
}

// A backup that FAILS must not stop the cleanup. The domain that cannot be
// backed up is usually the one with no room left, so keeping retention in the
// success branch made the archives pile up at exactly the moment there was least
// room for them. Nothing new is written on the failure path, so this only trims
// what is already there.
func TestRetentionRunsEvenWhenTheBackupFails(t *testing.T) {
	// backupRoot is redirected at a temporary directory, so the archive step
	// fails without touching the host. That failure is the point of the test.
	t.Setenv("SERVIKA_BACKUP_ROOT", t.TempDir())

	recorder := &retentionRecorder{}
	name := "retention-" + t.Name()
	retentionStateMu.Lock()
	retentionState[name] = recorder
	retentionStateMu.Unlock()

	db, err := sql.Open("backups_retention_recorder", name)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	tickOnce(db)

	if !recorder.sawQueryContaining("INSERT INTO backup_jobs") {
		t.Fatal("the tick never found the due domain, so this test proves nothing")
	}
	if !recorder.sawQueryContaining("FROM backups", "type='scheduled'") {
		t.Fatal("retention did not run after the backup failed")
	}
}
