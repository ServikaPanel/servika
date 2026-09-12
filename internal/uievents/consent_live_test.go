package uievents

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/auth"
)

// consentRequest runs one consent call as the test account.
func consentRequest(t *testing.T, handle *sql.DB, userID int64, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	handlers := &Handlers{DB: handle}
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	claims := &auth.Claims{UserID: userID, Username: replayTestUser, Role: "user"}
	request = request.WithContext(auth.WithClaims(request.Context(), claims))
	response := httptest.NewRecorder()
	switch method {
	case http.MethodGet:
		handlers.ConsentGet(response, request)
	case http.MethodPut:
		handlers.ConsentSave(response, request)
	default:
		handlers.ConsentForget(response, request)
	}
	return response
}

// readConsent parses one consent answer.
func readConsent(t *testing.T, response *httptest.ResponseRecorder) consentBody {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("the consent call answered %d: %s", response.Code, response.Body.String())
	}
	var body consentBody
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("the answer did not parse: %v", err)
	}
	return body
}

// Agreeing has to make the write path accept a batch, and withdrawing has to
// make it refuse one again. The consent screen and the ingest path read the
// same column, so this is the pairing worth measuring.
func TestWithdrawnConsentStopsTheNextBatch(t *testing.T) {
	handle := liveDB(t)
	const sessionID = "replay-live-consent"
	cleanupSession(t, handle, sessionID)
	setReplay(t, handle, true)
	userID := testActor(t, handle, false)

	accepted := readConsent(t, consentRequest(t, handle, userID, http.MethodPut,
		"/api/v1/me/replay-consent", `{"accepted":true}`))
	if !accepted.Consented || accepted.At == "" {
		t.Fatalf("the account agreed but the answer is %+v", accepted)
	}
	batch := `{"session_id":"` + sessionID + `","seq":0,"url":"https://panel.test/","events":[{"type":0}]}`
	if response := sendBatch(t, handle, userID, batch); response.Code != http.StatusNoContent {
		t.Fatalf("the batch of a consenting account answered %d: %s", response.Code, response.Body.String())
	}

	withdrawn := readConsent(t, consentRequest(t, handle, userID, http.MethodPut,
		"/api/v1/me/replay-consent", `{"accepted":false}`))
	if withdrawn.Consented || withdrawn.At != "" {
		t.Errorf("the consent was withdrawn but the answer is %+v", withdrawn)
	}
	response := sendBatch(t, handle, userID,
		`{"session_id":"`+sessionID+`","seq":1,"url":"https://panel.test/","events":[{"type":1}]}`)
	if response.Code != http.StatusForbidden {
		t.Errorf("the batch after the withdrawal answered %d, want 403", response.Code)
	}
	if got := countBatches(t, handle, sessionID); got != 1 {
		t.Errorf("%d batch row(s) are stored, expected only the one sent while consent stood", got)
	}
}

// Withdrawing stops the NEXT batch. An account that asks to be forgotten means
// the ones already stored.
func TestForgettingRemovesTheStoredRecordings(t *testing.T) {
	handle := liveDB(t)
	const sessionID = "replay-live-forget"
	cleanupSession(t, handle, sessionID)
	setReplay(t, handle, true)
	userID := testActor(t, handle, true)

	if response := sendBatch(t, handle, userID,
		`{"session_id":"`+sessionID+`","seq":0,"url":"https://panel.test/","events":[{"type":0}]}`); response.Code != http.StatusNoContent {
		t.Fatalf("the batch answered %d", response.Code)
	}
	// The id is read BEFORE the deletion and the batches are counted by it
	// afterwards. Counting them through a join with replay_sessions would drop
	// to zero the moment the session row went, whether or not the batches did.
	var id int64
	if err := handle.QueryRow(
		`SELECT id FROM replay_sessions WHERE session_id=?`, sessionID).Scan(&id); err != nil {
		t.Fatalf("read the recording: %v", err)
	}
	if got := countBatches(t, handle, sessionID); got != 1 {
		t.Fatalf("%d batch row(s) were stored before the deletion, expected 1", got)
	}

	response := consentRequest(t, handle, userID, http.MethodDelete, "/api/v1/me/replay-data", "")
	if response.Code != http.StatusNoContent {
		t.Fatalf("the deletion answered %d: %s", response.Code, response.Body.String())
	}
	var orphans int
	if err := handle.QueryRow(
		`SELECT COUNT(*) FROM replay_events WHERE session_id=?`, id).Scan(&orphans); err != nil {
		t.Fatalf("count: %v", err)
	}
	if orphans != 0 {
		t.Errorf("%d batch row(s) survived the deletion", orphans)
	}
	var sessions int
	if err := handle.QueryRow(
		`SELECT COUNT(*) FROM replay_sessions WHERE session_id=?`, sessionID).Scan(&sessions); err != nil {
		t.Fatalf("count: %v", err)
	}
	if sessions != 0 {
		t.Errorf("%d recording(s) survived the deletion", sessions)
	}
}
