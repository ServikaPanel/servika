// Package uievents records what the panel's INTERFACE did, which the server
// side cannot see.
//
// The panel is a single-page application: moving between screens changes no URL
// the server is asked for, so request_logs holds no row for it, and a button
// that was pressed without the request it should have made leaves no trace at
// all. The browser reports those actions here.
//
// The rows are written through internal/logsink, the same buffered writer
// request_logs and app_logs use, so a report never waits on the database and a
// burst is dropped rather than queued.
package uievents

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"servika/internal/httpx"
	"servika/internal/logsink"
	"servika/internal/middleware"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// Handlers serves the interface event endpoints.
type Handlers struct {
	DB *sql.DB
}

// maxBatch bounds one POST.
//
// The browser flushes every ten seconds or every 25 events, so a batch larger
// than this is not a busy operator: it is a client that has been queueing for
// minutes, or one that is not the panel at all.
const maxBatch = 100

// maxEventData bounds one event's payload. The interface reports what happened,
// not what was on the screen, so a larger payload is a mistake in the caller.
const maxEventData = 2 << 10

// knownTypes is the accepted set of event_type values.
//
// The column is free text so a new type needs no migration, but an unknown
// value is REFUSED rather than stored: the screens group by this column, and a
// typo would silently create a category nobody queries.
var knownTypes = map[string]bool{
	"page_view":    true,
	"search":       true,
	"form_submit":  true,
	"click_action": true,
	"client_error": true,
}

// eventIn is one event as the browser sends it.
type eventIn struct {
	Type string          `json:"type"`
	Path string          `json:"path"`
	Data json.RawMessage `json:"data"`
}

// batchIn is one POST body.
type batchIn struct {
	SessionID string    `json:"session_id"`
	Events    []eventIn `json:"events"`
}

// The stable reason codes. The screens render the sentence in twelve
// languages, so they match on these rather than on prose.
const (
	reasonBadBatch  = "invalid event batch"
	reasonBatchLong = "event batch too long"
)

// Collect — POST /api/v1/ui-events (any authenticated role).
//
// It answers 204 and queues the rows. Nothing here waits on a write: the report
// is about something that already happened in the browser, so making the
// browser wait for it would add latency to a screen for no gain.
func (h *Handlers) Collect(w http.ResponseWriter, r *http.Request) {
	var body batchIn
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reasonBadBatch)
		return
	}
	if len(body.Events) > maxBatch {
		httpx.WriteError(w, http.StatusBadRequest, reasonBatchLong)
		return
	}

	base := logsink.UIRow{
		SessionID: body.SessionID,
		RequestID: chimw.GetReqID(r.Context()),
	}
	if claims := middleware.ClaimsFrom(r); claims != nil {
		base.UserID = claims.UserID
		base.Username = claims.Username
	}
	for _, event := range body.Events {
		queue(rowFor(base, event))
	}
	w.WriteHeader(http.StatusNoContent)
}

// queue is where a finished row goes. A test replaces it to read what the
// handler assembled without opening a database.
var queue = logsink.UIEvent

// rowFor fills one row from one reported event.
//
// An unknown type becomes "client_error" rather than being dropped, because the
// event still says the interface did something the panel does not model, and
// dropping it would hide that.
func rowFor(base logsink.UIRow, event eventIn) logsink.UIRow {
	row := base
	row.EventType = strings.TrimSpace(event.Type)
	if !knownTypes[row.EventType] {
		row.EventType = "client_error"
	}
	row.Path = event.Path
	row.EventData = redactedData(event.Data)
	return row
}

// redactedData returns the payload to store, or "" to store NULL.
//
// It runs the SAME redaction request_logs uses, so a field named token or
// password never reaches the table whichever surface reported it. A payload
// that does not parse, or is oversized, is stored as NULL: the panel cannot
// know which field of an unknown shape is a secret.
//
// Only an OBJECT is stored. A bare string or number is valid JSON and the
// column would take it, but the screens read the payload as named fields, and a
// scalar carries no name to redact by either.
func redactedData(data json.RawMessage) string {
	if len(data) == 0 || len(data) > maxEventData {
		return ""
	}
	if trimmed := strings.TrimSpace(string(data)); !strings.HasPrefix(trimmed, "{") {
		return ""
	}
	stored, ok := logsink.RedactJSON(data)
	if !ok {
		return ""
	}
	return stored
}
