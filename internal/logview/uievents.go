package logview

import (
	"net/http"

	"servika/internal/httpx"
)

// UIEntry is one ui_events row as the screen reads it.
type UIEntry struct {
	ID        int64  `json:"id"`
	Time      string `json:"ts"`
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	SessionID string `json:"session_id"`
	RequestID string `json:"request_id"`
	EventType string `json:"event_type"`
	Path      string `json:"path"`
	EventData string `json:"event_data"`
}

// uiColumns is the projection, in the order UIEntry scans them.
const uiColumns = `id, DATE_FORMAT(ts, '%Y-%m-%d %H:%i:%s'), COALESCE(user_id,0), username,
	session_id, request_id, event_type, path, COALESCE(event_data,'')`

// buildUIQuery assembles the ui_events SELECT from the filters.
func buildUIQuery(values map[string]string, limit int) (string, []any, bool) {
	var f filter
	f.eq("session_id", values["session_id"])
	f.eq("request_id", values["request_id"])
	f.eq("event_type", values["event_type"])
	ok := f.numeric("user_id", values["user_id"]) && f.since(values["since"])
	if !ok {
		return "", nil, false
	}
	statement, arg := f.query(uiColumns, "ui_events", limit)
	return statement, arg, true
}

// UIList — GET /api/v1/system/ui-events (AdminOnly).
//
// Filters: ?session_id, ?request_id, ?event_type, ?user_id, ?since, ?limit.
func (h *Handlers) UIList(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	statement, arg, ok := buildUIQuery(map[string]string{
		"session_id": query.Get("session_id"),
		"request_id": query.Get("request_id"),
		"event_type": query.Get("event_type"),
		"user_id":    query.Get("user_id"),
		"since":      query.Get("since"),
	}, parseLimit(query.Get("limit")))
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, badFilter)
		return
	}

	// #nosec G701 -- buildUIQuery pastes only constant column and table names into the text; filter.eq/oneOf/numeric/since bind every query-string value as a placeholder.
	rows, err := h.DB.QueryContext(r.Context(), statement, arg...)
	if err != nil {
		httpx.LogR(r, "interface event list: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "interface event read failed")
		return
	}
	defer func() { _ = rows.Close() }() // read-only query: closing the result set has nothing to flush

	out := make([]UIEntry, 0)
	for rows.Next() {
		var e UIEntry
		if err := rows.Scan(&e.ID, &e.Time, &e.UserID, &e.Username, &e.SessionID,
			&e.RequestID, &e.EventType, &e.Path, &e.EventData); err != nil {
			// #nosec G706 -- the logged value is a database error; no request-controlled string reaches the log.
			httpx.WarnR(r, "interface event list: skipping an unreadable row: %v", err)
			continue
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		httpx.LogR(r, "interface event read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "interface event read failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
