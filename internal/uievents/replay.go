package uievents

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"servika/internal/httpx"
	"servika/internal/middleware"
)

// Session replay: the rrweb recording of the same session ui_events describes.
//
// The batches are written SYNCHRONOUSLY, unlike every other row this package
// writes. The request being served here IS the log, so there is nothing to keep
// waiting, and the browser has to be told when a batch was refused: a recorder
// that keeps sending into a feature the operator turned off would waste the
// panel's bandwidth for the life of the tab.

// maxBatchBytes bounds one batch.
//
// The first batch carries a full DOM snapshot and is the largest by far.
// middleware.BodyLimit already caps a JSON body at 10 MB; this is the smaller
// number the handler itself refuses on, so the reason is reported rather than
// the connection being cut.
const maxBatchBytes = 8 << 20

// settingTTL bounds how long a changed switch takes to reach a running panel
// when it was changed OUTSIDE the panel. Save calls Invalidate, so an operator
// using the screen never waits this out.
const settingTTL = 60 * time.Second

// now is a seam so a test can move time without sleeping.
var now = time.Now

var (
	settingMu sync.RWMutex
	enabled   bool
	enabledAt time.Time
)

// Invalidate drops the cached switch. The write path calls it.
func Invalidate() {
	settingMu.Lock()
	enabled, enabledAt = false, time.Time{}
	settingMu.Unlock()
}

// ReplayEnabled reports whether the operator has turned session replay on.
func ReplayEnabled(ctx context.Context, db *sql.DB) (bool, error) {
	settingMu.RLock()
	if enabledAt.After(now().Add(-settingTTL)) {
		value := enabled
		settingMu.RUnlock()
		return value, nil
	}
	settingMu.RUnlock()

	var on int
	if err := db.QueryRowContext(ctx,
		`SELECT session_replay_enabled FROM panel_settings WHERE id=1`).Scan(&on); err != nil {
		return false, err
	}
	settingMu.Lock()
	enabled, enabledAt = on == 1, now()
	settingMu.Unlock()
	return on == 1, nil
}

// The stable reason codes a refused batch answers with.
const (
	reasonReplayOff     = "session_replay_disabled"
	reasonNoConsent     = "session_replay_no_consent"
	reasonBatchTooLarge = "session_replay_batch_too_large"
)

// replayIn is one POST body. The events are kept as raw JSON: the server never
// reads inside them, it stores what the browser sent and returns it unchanged.
type replayIn struct {
	SessionID string          `json:"session_id"`
	Seq       int             `json:"seq"`
	URL       string          `json:"url"`
	Events    json.RawMessage `json:"events"`
}

// Replay — POST /api/v1/replay (any authenticated role).
func (h *Handlers) Replay(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFrom(r)
	if claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !h.replayAllowed(w, r, claims.UserID) {
		return
	}

	var body replayIn
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reasonBadBatch)
		return
	}
	if strings.TrimSpace(body.SessionID) == "" || len(body.Events) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, reasonBadBatch)
		return
	}
	if len(body.Events) > maxBatchBytes {
		httpx.WriteError(w, http.StatusRequestEntityTooLarge, reasonBatchTooLarge)
		return
	}

	sessionID, err := h.openSession(r, body, claims.UserID, claims.Username)
	if err != nil {
		httpx.LogR(r, "replay session: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the replay could not be stored")
		return
	}
	// INSERT IGNORE: the browser retries a batch it could not confirm, and
	// beforeunload can send the one the interval already sent. Storing it twice
	// would play those seconds twice.
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT IGNORE INTO replay_events (session_id, seq, batch) VALUES (?,?,?)`,
		sessionID, body.Seq, string(body.Events)); err != nil {
		httpx.LogR(r, "replay batch: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the replay could not be stored")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// replayAllowed answers the two questions that decide whether a recording may
// be stored at all, and writes the refusal itself.
//
// Both are asked on the SERVER. The recorder asks them too, but a client that
// answers them for itself is not a control.
func (h *Handlers) replayAllowed(w http.ResponseWriter, r *http.Request, userID int64) bool {
	on, err := ReplayEnabled(r.Context(), h.DB)
	if err != nil {
		httpx.LogR(r, "replay setting read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "panel settings could not be read")
		return false
	}
	if !on {
		httpx.WriteError(w, http.StatusForbidden, reasonReplayOff)
		return false
	}

	var consented int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM users WHERE id=? AND replay_consent_at IS NOT NULL`,
		userID).Scan(&consented); err != nil {
		httpx.LogR(r, "replay consent read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the consent could not be read")
		return false
	}
	if consented == 0 {
		httpx.WriteError(w, http.StatusForbidden, reasonNoConsent)
		return false
	}
	return true
}

// openSession returns the replay_sessions id for this browser session, creating
// the row on the first batch.
//
// LAST_INSERT_ID(id) on the duplicate branch makes MariaDB report the EXISTING
// row's id, so one statement both creates and finds. Without it the second
// batch would need a SELECT and two batches racing would open two sessions.
func (h *Handlers) openSession(r *http.Request, body replayIn, userID int64, username string) (int64, error) {
	var owner any
	if userID > 0 {
		owner = userID
	}
	result, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO replay_sessions (session_id, user_id, username, page_url, batches)
		 VALUES (?,?,?,?,1)
		 ON DUPLICATE KEY UPDATE
		   id=LAST_INSERT_ID(id), updated_at=CURRENT_TIMESTAMP(3), batches=batches+1`,
		body.SessionID, owner, username, clip(body.URL, 255))
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// clip shortens a value to what its column accepts, on a rune boundary so a
// multi-byte character is never cut in half.
func clip(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	runes := []rune(value)
	for len(string(runes)) > limit {
		runes = runes[:len(runes)-1]
	}
	return string(runes)
}
