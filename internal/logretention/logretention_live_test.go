package logretention

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"servika/internal/db"
)

// liveDB opens the shared test database, or skips.
func liveDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("SERVIKA_TEST_DSN")
	if dsn == "" {
		t.Skip("SERVIKA_TEST_DSN is unset, so there is no server to ask")
	}
	handle, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	return handle
}

// setDays writes the setting and restores it when the test ends.
func setDays(t *testing.T, handle *sql.DB, days int) {
	t.Helper()
	var previous int
	if err := handle.QueryRow(
		`SELECT log_retention_days FROM panel_settings WHERE id=1`).Scan(&previous); err != nil {
		t.Fatalf("read the setting: %v", err)
	}
	if _, err := handle.Exec(
		`UPDATE panel_settings SET log_retention_days=? WHERE id=1`, days); err != nil {
		t.Fatalf("write the setting: %v", err)
	}
	Invalidate()
	t.Cleanup(func() {
		_, _ = handle.Exec(`UPDATE panel_settings SET log_retention_days=? WHERE id=1`, previous)
		Invalidate()
	})
}

// countApp reports how many rows one test's logger still has.
func countApp(t *testing.T, handle *sql.DB, logger string) int {
	t.Helper()
	var n int
	if err := handle.QueryRow(
		`SELECT COUNT(*) FROM app_logs WHERE logger_name=?`, logger).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// The whole point of the setting: a row past the window goes, and a row inside
// it stays. A sweep that deletes both is worse than no sweep at all.
func TestOnlyTheRowsPastTheWindowAreDeleted(t *testing.T) {
	handle := liveDB(t)
	const logger = "logretention-live-test"
	t.Cleanup(func() {
		_, _ = handle.Exec(`DELETE FROM app_logs WHERE logger_name=?`, logger)
	})
	setDays(t, handle, 1)

	old := time.Now().UTC().Add(-48 * time.Hour)
	fresh := time.Now().UTC().Add(-1 * time.Hour)
	for _, ts := range []time.Time{old, fresh} {
		if _, err := handle.Exec(
			`INSERT INTO app_logs (ts, level, logger_name, message) VALUES (?, 'INFO', ?, 'retention test')`,
			ts, logger); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	Sweep(t.Context(), handle)

	if got := countApp(t, handle, logger); got != 1 {
		t.Errorf("%d row(s) survived the sweep, expected 1", got)
	}
	var age float64
	if err := handle.QueryRow(
		`SELECT TIMESTAMPDIFF(HOUR, ts, UTC_TIMESTAMP()) FROM app_logs WHERE logger_name=?`,
		logger).Scan(&age); err != nil {
		t.Fatalf("read: %v", err)
	}
	if age > 24 {
		t.Errorf("the surviving row is %.0f hour(s) old, so the wrong one was kept", age)
	}
}

// The interface and replay tables were added after this package, and each one
// dates its rows in a different column. A sweep that only knows ts leaves them
// growing for ever, and the replay tables are the largest the panel writes.
//
// audit_log is checked in the SAME pass: it is the one log an operator may have
// to produce months later, so it must survive a sweep that deleted everything
// around it.
func TestTheInterfaceAndReplayTablesAreSweptAndTheAuditLogIsNot(t *testing.T) {
	handle := liveDB(t)
	const marker = "logretention-tables-test"
	seedExpired(t, handle, marker)
	setDays(t, handle, 1)

	Sweep(t.Context(), handle)

	for _, check := range []struct {
		table     string
		statement string
	}{
		{"ui_events", `SELECT COUNT(*) FROM ui_events WHERE session_id=?`},
		{"replay_events", `SELECT COUNT(*) FROM replay_events e JOIN replay_sessions s ON s.id=e.session_id WHERE s.session_id=?`},
		{"replay_sessions", `SELECT COUNT(*) FROM replay_sessions WHERE session_id=?`},
	} {
		var n int
		if err := handle.QueryRow(check.statement, marker).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", check.table, err)
		}
		if n != 0 {
			t.Errorf("%d expired row(s) survived in %s", n, check.table)
		}
	}

	var audits int
	if err := handle.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action=?`, marker).Scan(&audits); err != nil {
		t.Fatalf("count audit_log: %v", err)
	}
	if audits != 1 {
		t.Errorf("%d audit row(s) remain, expected the sweep to leave 1", audits)
	}
}

// A recording that began before the window but is still receiving batches must
// keep its session row. Deleting it would leave the batches pointing at a row
// that is gone, and nothing would find them again.
func TestALiveRecordingKeepsItsSessionRow(t *testing.T) {
	handle := liveDB(t)
	const marker = "logretention-live-recording"
	t.Cleanup(func() {
		_, _ = handle.Exec(
			`DELETE e FROM replay_events e JOIN replay_sessions s ON s.id=e.session_id
			  WHERE s.session_id=?`, marker)
		_, _ = handle.Exec(`DELETE FROM replay_sessions WHERE session_id=?`, marker)
	})
	// Began 90 days ago, last batch a minute ago.
	result, err := handle.Exec(
		`INSERT INTO replay_sessions (session_id, page_url, started_at, updated_at, batches)
		 VALUES (?,'/',?,UTC_TIMESTAMP(3),2)`,
		marker, time.Now().UTC().Add(-90*24*time.Hour))
	if err != nil {
		t.Fatalf("insert the recording: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("insert the recording: %v", err)
	}
	if _, err := handle.Exec(
		`INSERT INTO replay_events (session_id, seq, batch) VALUES (?,0,'[]')`, id); err != nil {
		t.Fatalf("insert the batch: %v", err)
	}
	setDays(t, handle, 1)

	Sweep(t.Context(), handle)

	var sessions int
	if err := handle.QueryRow(
		`SELECT COUNT(*) FROM replay_sessions WHERE session_id=?`, marker).Scan(&sessions); err != nil {
		t.Fatalf("count: %v", err)
	}
	if sessions != 1 {
		t.Errorf("the recording lost its session row while a batch inside the window pointed at it")
	}
}

// seedExpired writes one expired row in each table the check above reads.
func seedExpired(t *testing.T, handle *sql.DB, marker string) {
	t.Helper()
	expired := time.Now().UTC().Add(-90 * 24 * time.Hour)
	t.Cleanup(func() {
		_, _ = handle.Exec(
			`DELETE e FROM replay_events e JOIN replay_sessions s ON s.id=e.session_id
			  WHERE s.session_id=?`, marker)
		_, _ = handle.Exec(`DELETE FROM replay_sessions WHERE session_id=?`, marker)
		_, _ = handle.Exec(`DELETE FROM ui_events WHERE session_id=?`, marker)
		_, _ = handle.Exec(`DELETE FROM audit_log WHERE action=?`, marker)
	})

	if _, err := handle.Exec(
		`INSERT INTO ui_events (ts, session_id, event_type, path) VALUES (?,?,'page_view','/')`,
		expired, marker); err != nil {
		t.Fatalf("insert the interface event: %v", err)
	}
	result, err := handle.Exec(
		`INSERT INTO replay_sessions (session_id, page_url, started_at, updated_at, batches)
		 VALUES (?,'/',?,?,1)`,
		marker, expired, expired)
	if err != nil {
		t.Fatalf("insert the recording: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("insert the recording: %v", err)
	}
	if _, err := handle.Exec(
		`INSERT INTO replay_events (session_id, seq, batch, created_at) VALUES (?,0,'[]',?)`,
		id, expired); err != nil {
		t.Fatalf("insert the batch: %v", err)
	}
	if _, err := handle.Exec(
		`INSERT INTO audit_log (ts, action, target) VALUES (?,?,'')`, expired, marker); err != nil {
		t.Fatalf("insert the audit row: %v", err)
	}
}

// A window nobody can set through the panel was written by hand. Acting on it
// would delete rows on a number nobody meant, so the sweep must refuse.
func TestAnOutOfRangeWindowDeletesNothing(t *testing.T) {
	handle := liveDB(t)
	const logger = "logretention-refuse-test"
	t.Cleanup(func() {
		_, _ = handle.Exec(`DELETE FROM app_logs WHERE logger_name=?`, logger)
	})
	setDays(t, handle, 0)

	if _, err := handle.Exec(
		`INSERT INTO app_logs (ts, level, logger_name, message) VALUES (?, 'INFO', ?, 'retention test')`,
		time.Now().UTC().Add(-90*24*time.Hour), logger); err != nil {
		t.Fatalf("insert: %v", err)
	}

	Sweep(t.Context(), handle)

	if got := countApp(t, handle, logger); got != 1 {
		t.Errorf("%d row(s) survived, expected the sweep to refuse and keep 1", got)
	}
}

// The setting is cached, so a change made outside the panel must still reach a
// running sweep. Invalidate is what every write path calls to make that
// immediate.
func TestInvalidateMakesTheNewWindowVisible(t *testing.T) {
	handle := liveDB(t)
	setDays(t, handle, 30)

	if days, err := Days(t.Context(), handle); err != nil || days != 30 {
		t.Fatalf("Days is %d (%v), want 30", days, err)
	}
	if _, err := handle.Exec(`UPDATE panel_settings SET log_retention_days=7 WHERE id=1`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if days, _ := Days(t.Context(), handle); days != 30 {
		t.Errorf("the cache was not used: Days is %d, want the cached 30", days)
	}
	Invalidate()
	if days, err := Days(t.Context(), handle); err != nil || days != 7 {
		t.Errorf("Days is %d (%v) after Invalidate, want 7", days, err)
	}
}
