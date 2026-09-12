package uievents

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"servika/internal/auth"
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

// The account every replay test records. It is created here rather than
// borrowed, so a test never turns a real operator's consent on.
const replayTestUser = "uievents-replay-test"

// testActor creates the account, sets its consent, and returns its id.
func testActor(t *testing.T, handle *sql.DB, consented bool) int64 {
	t.Helper()
	// dashboard_layout has no default, so it is named here rather than left out.
	result, err := handle.Exec(
		`INSERT INTO users (username, email, password_hash, role, dashboard_layout)
		 VALUES (?,?,'x','user','')`,
		replayTestUser, replayTestUser+"@example.test")
	if err != nil {
		t.Fatalf("create the account: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("create the account: %v", err)
	}
	t.Cleanup(func() { _, _ = handle.Exec(`DELETE FROM users WHERE id=?`, id) })

	if consented {
		if _, err := handle.Exec(
			`UPDATE users SET replay_consent_at=UTC_TIMESTAMP() WHERE id=?`, id); err != nil {
			t.Fatalf("record the consent: %v", err)
		}
	}
	return id
}

// setReplay turns the feature on or off and restores it when the test ends.
func setReplay(t *testing.T, handle *sql.DB, on bool) {
	t.Helper()
	var previous int
	if err := handle.QueryRow(
		`SELECT session_replay_enabled FROM panel_settings WHERE id=1`).Scan(&previous); err != nil {
		t.Fatalf("read the setting: %v", err)
	}
	value := 0
	if on {
		value = 1
	}
	if _, err := handle.Exec(
		`UPDATE panel_settings SET session_replay_enabled=? WHERE id=1`, value); err != nil {
		t.Fatalf("write the setting: %v", err)
	}
	Invalidate()
	t.Cleanup(func() {
		_, _ = handle.Exec(`UPDATE panel_settings SET session_replay_enabled=? WHERE id=1`, previous)
		Invalidate()
	})
}

// sendBatch posts one batch as the given account.
func sendBatch(t *testing.T, handle *sql.DB, userID int64, body string) *httptest.ResponseRecorder {
	t.Helper()
	handlers := &Handlers{DB: handle}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/replay", strings.NewReader(body))
	claims := &auth.Claims{UserID: userID, Username: replayTestUser, Role: "user"}
	request = request.WithContext(auth.WithClaims(request.Context(), claims))
	response := httptest.NewRecorder()
	handlers.Replay(response, request)
	return response
}

// countBatches reports how many batches one browser session has stored.
func countBatches(t *testing.T, handle *sql.DB, sessionID string) int {
	t.Helper()
	var n int
	if err := handle.QueryRow(
		`SELECT COUNT(*) FROM replay_events e
		   JOIN replay_sessions s ON s.id = e.session_id
		  WHERE s.session_id=?`, sessionID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// cleanupSession removes what one test wrote.
func cleanupSession(t *testing.T, handle *sql.DB, sessionID string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = handle.Exec(
			`DELETE e FROM replay_events e JOIN replay_sessions s ON s.id=e.session_id
			  WHERE s.session_id=?`, sessionID)
		_, _ = handle.Exec(`DELETE FROM replay_sessions WHERE session_id=?`, sessionID)
	})
}

// Two batches of the same browser session join ONE recording, and the first
// batch is the one that opens it.
func TestTheSecondBatchJoinsTheSameSession(t *testing.T) {
	handle := liveDB(t)
	const sessionID = "replay-live-join"
	cleanupSession(t, handle, sessionID)
	setReplay(t, handle, true)
	userID := testActor(t, handle, true)

	for _, seq := range []int{0, 1} {
		response := sendBatch(t, handle, userID,
			`{"session_id":"`+sessionID+`","seq":`+itoa(seq)+`,"url":"https://panel.test/domains","events":[{"type":`+itoa(seq)+`}]}`)
		if response.Code != http.StatusNoContent {
			t.Fatalf("batch %d answered %d: %s", seq, response.Code, response.Body.String())
		}
	}

	var sessions, batches int
	if err := handle.QueryRow(
		`SELECT COUNT(*), COALESCE(MAX(batches),0) FROM replay_sessions WHERE session_id=?`,
		sessionID).Scan(&sessions, &batches); err != nil {
		t.Fatalf("count: %v", err)
	}
	if sessions != 1 {
		t.Errorf("%d recording(s) were opened for one browser session, expected 1", sessions)
	}
	if batches != 2 {
		t.Errorf("the recording counted %d batch(es), expected 2", batches)
	}
	if got := countBatches(t, handle, sessionID); got != 2 {
		t.Errorf("%d batch row(s) were stored, expected 2", got)
	}
}

// beforeunload can send the batch the interval already sent. Storing it twice
// would play those seconds twice.
func TestTheSameBatchIsNotStoredTwice(t *testing.T) {
	handle := liveDB(t)
	const sessionID = "replay-live-dup"
	cleanupSession(t, handle, sessionID)
	setReplay(t, handle, true)
	userID := testActor(t, handle, true)

	body := `{"session_id":"` + sessionID + `","seq":0,"url":"https://panel.test/","events":[{"type":0}]}`
	sendBatch(t, handle, userID, body)
	response := sendBatch(t, handle, userID, body)

	if response.Code != http.StatusNoContent {
		t.Fatalf("the repeated batch answered %d", response.Code)
	}
	if got := countBatches(t, handle, sessionID); got != 1 {
		t.Errorf("%d batch row(s) were stored for one seq, expected 1", got)
	}
}

// The switch is the operator's, so a recorder that ignores it must still store
// nothing.
func TestNothingIsStoredWhileTheFeatureIsOff(t *testing.T) {
	handle := liveDB(t)
	const sessionID = "replay-live-off"
	cleanupSession(t, handle, sessionID)
	setReplay(t, handle, false)
	userID := testActor(t, handle, true)

	response := sendBatch(t, handle, userID,
		`{"session_id":"`+sessionID+`","seq":0,"url":"https://panel.test/","events":[{"type":0}]}`)

	if response.Code != http.StatusForbidden {
		t.Errorf("the batch answered %d, want 403", response.Code)
	}
	if !strings.Contains(response.Body.String(), reasonReplayOff) {
		t.Errorf("the refusal did not name its reason: %s", response.Body.String())
	}
	if got := countBatches(t, handle, sessionID); got != 0 {
		t.Errorf("%d batch row(s) were stored while the feature was off", got)
	}
}

// Consent is asked on the SERVER. A client that answers it for itself is not a
// control.
func TestABatchWithoutConsentIsRefused(t *testing.T) {
	handle := liveDB(t)
	const sessionID = "replay-live-noconsent"
	cleanupSession(t, handle, sessionID)
	setReplay(t, handle, true)
	userID := testActor(t, handle, false)

	response := sendBatch(t, handle, userID,
		`{"session_id":"`+sessionID+`","seq":0,"url":"https://panel.test/","events":[{"type":0}]}`)

	if response.Code != http.StatusForbidden {
		t.Errorf("the batch answered %d, want 403", response.Code)
	}
	if !strings.Contains(response.Body.String(), reasonNoConsent) {
		t.Errorf("the refusal did not name its reason: %s", response.Body.String())
	}
	if got := countBatches(t, handle, sessionID); got != 0 {
		t.Errorf("%d batch row(s) were stored without consent", got)
	}
}

// The cached switch must see a change made outside the panel once Invalidate
// runs, or the operator turns recording off and it keeps recording.
func TestInvalidateMakesTheSwitchVisible(t *testing.T) {
	handle := liveDB(t)
	setReplay(t, handle, true)

	if on, err := ReplayEnabled(context.Background(), handle); err != nil || !on {
		t.Fatalf("the switch reads %v (%v), want on", on, err)
	}
	if _, err := handle.Exec(`UPDATE panel_settings SET session_replay_enabled=0 WHERE id=1`); err != nil {
		t.Fatalf("write: %v", err)
	}
	if on, _ := ReplayEnabled(context.Background(), handle); !on {
		t.Error("the cache was not used")
	}
	Invalidate()
	if on, _ := ReplayEnabled(context.Background(), handle); on {
		t.Error("the switch still reads on after Invalidate")
	}
}

// itoa keeps the test bodies readable. Every caller passes a single digit.
func itoa(n int) string { return strconv.Itoa(n) }
