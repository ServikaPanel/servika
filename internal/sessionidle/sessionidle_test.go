package sessionidle

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// A recording driver, as used elsewhere in the repository: there is no sqlmock
// dependency, and what these tests need is which statements ran.
//
// The answers are modelled as ROWS, so the query text decides the outcome. A
// recorder that answered regardless of the statement would keep passing if the
// setting read were dropped, which is one of the things these tests exist to
// catch.
type recorder struct {
	mu sync.Mutex
	// minutes is panel_settings.session_idle_minutes.
	minutes int
	// stamp is users.last_activity_ts for the identity under test.
	stamp int64
	// statements is every query and exec the package issued.
	statements []string
}

func (r *recorder) saw(fragment string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, statement := range r.statements {
		if strings.Contains(statement, fragment) {
			return true
		}
	}
	return false
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.statements)
}

var (
	stateMu sync.Mutex
	state   = map[string]*recorder{}
	once    sync.Once
)

type idleDriver struct{}

func (idleDriver) Open(name string) (driver.Conn, error) {
	stateMu.Lock()
	defer stateMu.Unlock()
	rec, ok := state[name]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return &idleConn{recorder: rec}, nil
}

type idleConn struct{ recorder *recorder }

func (c *idleConn) Prepare(query string) (driver.Stmt, error) {
	c.recorder.mu.Lock()
	c.recorder.statements = append(c.recorder.statements, query)
	c.recorder.mu.Unlock()
	return &idleStmt{recorder: c.recorder, query: query}, nil
}
func (c *idleConn) Close() error              { return nil }
func (c *idleConn) Begin() (driver.Tx, error) { return nil, io.ErrUnexpectedEOF }

type idleStmt struct {
	recorder *recorder
	query    string
}

func (s *idleStmt) Close() error  { return nil }
func (s *idleStmt) NumInput() int { return -1 }

func (s *idleStmt) Exec([]driver.Value) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

func (s *idleStmt) Query([]driver.Value) (driver.Rows, error) {
	switch {
	case strings.Contains(s.query, "session_idle_minutes"):
		return &idleRows{columns: []string{"minutes"}, values: [][]driver.Value{{int64(s.recorder.minutes)}}}, nil
	case strings.Contains(s.query, "last_activity_ts"):
		return &idleRows{columns: []string{"ts"}, values: [][]driver.Value{{s.recorder.stamp}}}, nil
	}
	return &idleRows{columns: []string{"x"}}, nil
}

type idleRows struct {
	columns []string
	values  [][]driver.Value
	at      int
}

func (r *idleRows) Columns() []string { return r.columns }
func (r *idleRows) Close() error      { return nil }
func (r *idleRows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

// openRecorded returns a database backed by rec, plus a fixed clock the test
// can move.
func openRecorded(t *testing.T, rec *recorder, at time.Time) *sql.DB {
	t.Helper()
	once.Do(func() { sql.Register("sessionidle-recorder", idleDriver{}) })

	name := t.Name()
	stateMu.Lock()
	state[name] = rec
	stateMu.Unlock()

	db, err := sql.Open("sessionidle-recorder", name)
	if err != nil {
		t.Fatalf("open the recorded database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	previous := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = previous })
	Invalidate()
	t.Cleanup(Invalidate)
	return db
}

// The default is off, and off has to cost nothing: an installation that never
// turns this on must not gain a users row read on every authenticated request.
func TestTheFeatureOffReadsNothingBeyondTheSetting(t *testing.T) {
	rec := &recorder{minutes: 0, stamp: 1}
	db := openRecorded(t, rec, time.Unix(1_700_000_000, 0))

	expired, err := Enforce(context.Background(), db, 7)
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if expired {
		t.Error("a session expired while the feature is off")
	}
	if rec.saw("last_activity_ts") {
		t.Error("the identity row was read while the feature is off")
	}
	if rec.saw("UPDATE users") {
		t.Error("the identity row was written while the feature is off")
	}
}

// A stamp older than the timeout ends the session, and the stamp is NOT
// rewritten: touching it here would reset the clock on the very request being
// refused, so a client that kept polling would never be signed out.
func TestAnIdleSessionExpiresWithoutBeingTouched(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	rec := &recorder{minutes: 30, stamp: at.Unix() - 31*60}
	db := openRecorded(t, rec, at)

	expired, err := Enforce(context.Background(), db, 7)
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if !expired {
		t.Error("a session idle for 31 minutes survived a 30 minute limit")
	}
	if rec.saw("UPDATE users") {
		t.Error("the expired session's stamp was refreshed")
	}
}

// Right at the limit the session is still alive. The boundary is stated once
// here so a later change to > or >= is a failing test rather than a surprise.
func TestASessionExactlyAtTheLimitSurvives(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	rec := &recorder{minutes: 30, stamp: at.Unix() - 30*60}
	db := openRecorded(t, rec, at)

	expired, err := Enforce(context.Background(), db, 7)
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if expired {
		t.Error("a session exactly at the limit was ended")
	}
}

// Turning the feature on must not sign everybody out at once. A stamp of 0 is
// an identity that has never been stamped, not one idle since 1970.
func TestANeverStampedIdentityIsStampedRatherThanExpired(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	rec := &recorder{minutes: 30, stamp: 0}
	db := openRecorded(t, rec, at)

	expired, err := Enforce(context.Background(), db, 7)
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if expired {
		t.Error("an identity with no stamp was treated as idle since the epoch")
	}
	if !rec.saw("UPDATE users") {
		t.Error("the identity was not stamped")
	}
}

// The dashboard polls, so a write per request would be a row update per second
// per open screen for a value nothing reads at that resolution.
func TestAFreshStampIsNotRewritten(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	rec := &recorder{minutes: 30, stamp: at.Unix() - 5}
	db := openRecorded(t, rec, at)

	if _, err := Enforce(context.Background(), db, 7); err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if rec.saw("UPDATE users") {
		t.Error("a stamp five seconds old was rewritten")
	}
}

// Past the touch interval and inside the timeout, the stamp moves. Without this
// the clock never advances and every session expires at the timeout however
// busy it was.
func TestAStaleStampInsideTheTimeoutIsRewritten(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	rec := &recorder{minutes: 30, stamp: at.Unix() - 120}
	db := openRecorded(t, rec, at)

	expired, err := Enforce(context.Background(), db, 7)
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if expired {
		t.Error("a session two minutes idle was ended by a 30 minute limit")
	}
	if !rec.saw("UPDATE users") {
		t.Error("the stamp was not moved forward")
	}
}

// The cache is what keeps the setting read off every request; Invalidate is
// what stops an operator watching the old value stay in force after saving.
func TestTheSettingIsCachedUntilInvalidated(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	rec := &recorder{minutes: 0}
	db := openRecorded(t, rec, at)

	for range 3 {
		if _, err := Minutes(context.Background(), db); err != nil {
			t.Fatalf("minutes: %v", err)
		}
	}
	if got := rec.count(); got != 1 {
		t.Errorf("the setting was read %d times, want 1", got)
	}
	Invalidate()
	if _, err := Minutes(context.Background(), db); err != nil {
		t.Fatalf("minutes: %v", err)
	}
	if got := rec.count(); got != 2 {
		t.Errorf("after Invalidate the setting was read %d times in total, want 2", got)
	}
}

// Out of range is refused on the write path rather than clamped: an operator
// who typed 5000 asked for something this cannot do.
func TestTheRangeIsRefusedRatherThanClamped(t *testing.T) {
	for _, minutes := range []int{0, 1, MaxMinutes} {
		if !Valid(minutes) {
			t.Errorf("%d was refused but is in range", minutes)
		}
	}
	for _, minutes := range []int{-1, MaxMinutes + 1, 100000} {
		if Valid(minutes) {
			t.Errorf("%d was accepted but is out of range", minutes)
		}
	}
}
