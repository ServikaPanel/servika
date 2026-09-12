package panelsettings

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"servika/internal/db"
	"servika/internal/uievents"
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

// The switch is read through a cache with a one minute window, so a save that
// does not invalidate it leaves recording running after the screen said it had
// stopped. This test writes through the handler and asks the SAME reader the
// ingest path uses.
func TestSavingTheSwitchIsVisibleAtOnce(t *testing.T) {
	handle := liveDB(t)
	restoreReplay(t, handle)
	handlers := &Handlers{DB: handle}

	saveReplay(t, handlers, `{"enabled":true}`, true)
	if on, err := uievents.ReplayEnabled(t.Context(), handle); err != nil || !on {
		t.Fatalf("the ingest path reads %v (%v) after the switch was turned on", on, err)
	}
	saveReplay(t, handlers, `{"enabled":false}`, false)
	if on, err := uievents.ReplayEnabled(t.Context(), handle); err != nil || on {
		t.Errorf("the ingest path reads %v (%v) after the switch was turned off", on, err)
	}
}

// saveReplay puts one value through the handler and checks what it answered.
func saveReplay(t *testing.T, handlers *Handlers, body string, want bool) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/api/v1/system/session-replay", strings.NewReader(body))
	response := httptest.NewRecorder()
	handlers.SessionReplaySave(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("the save answered %d: %s", response.Code, response.Body.String())
	}
	var answered struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &answered); err != nil {
		t.Fatalf("the answer did not parse: %v", err)
	}
	if answered.Enabled != want {
		t.Errorf("the save answered enabled=%v, want %v", answered.Enabled, want)
	}
}

// replaySwitchLock names the advisory lock that serialises the switch.
//
// session_replay_enabled is ONE row of panel_settings, and go test runs this
// package and internal/uievents at the same time against the same database.
// Without this, turning the switch off here makes a batch that package just
// sent be refused. internal/uievents takes the same lock.
const replaySwitchLock = "servika_test_replay_switch"

// restoreReplay takes the switch lock and puts the operator's own value back
// when the test ends.
//
// The lock is held on ONE connection: MariaDB releases it when that connection
// closes, and database/sql would otherwise hand the release to a different one.
func restoreReplay(t *testing.T, handle *sql.DB) {
	t.Helper()
	conn, err := handle.Conn(t.Context())
	if err != nil {
		t.Fatalf("open a connection for the lock: %v", err)
	}
	var got sql.NullInt64
	if err := conn.QueryRowContext(context.Background(),
		`SELECT GET_LOCK(?, 30)`, replaySwitchLock).Scan(&got); err != nil {
		t.Fatalf("take the lock: %v", err)
	}
	if !got.Valid || got.Int64 != 1 {
		t.Fatalf("the switch lock was not free within 30 seconds")
	}
	t.Cleanup(func() {
		_ = conn.QueryRowContext(context.Background(),
			`SELECT RELEASE_LOCK(?)`, replaySwitchLock).Scan(&got)
		_ = conn.Close()
	})

	var previous int
	if err := handle.QueryRow(
		`SELECT session_replay_enabled FROM panel_settings WHERE id=1`).Scan(&previous); err != nil {
		t.Fatalf("read the setting: %v", err)
	}
	t.Cleanup(func() {
		_, _ = handle.Exec(`UPDATE panel_settings SET session_replay_enabled=? WHERE id=1`, previous)
		uievents.Invalidate()
	})
}
