package logview

import (
	"net/http"

	"servika/internal/httpx"
)

// AppEntry is one app_logs row as the screen reads it.
type AppEntry struct {
	ID         int64  `json:"id"`
	Time       string `json:"ts"`
	Level      string `json:"level"`
	LoggerName string `json:"logger_name"`
	Message    string `json:"message"`
	Context    string `json:"context"`
	RequestID  string `json:"request_id"`
}

// appColumns is the projection, in the order AppEntry scans them.
const appColumns = `id, DATE_FORMAT(ts, '%Y-%m-%d %H:%i:%s'), level, logger_name,
	message, COALESCE(context,''), request_id`

// buildAppQuery assembles the app_logs SELECT from the filters.
func buildAppQuery(values map[string]string, limit int) (string, []any, bool) {
	var f filter
	f.eq("logger_name", values["logger_name"])
	f.eq("request_id", values["request_id"])
	// The level column is an ENUM, so a value outside the set matches nothing.
	// Answering an empty list to a typo reads as "the panel logged no errors",
	// which is the opposite of what an operator is checking.
	ok := f.oneOf("level", values["level"], "INFO", "WARN", "ERROR") && f.since(values["since"])
	if !ok {
		return "", nil, false
	}
	statement, arg := f.query(appColumns, "app_logs", limit)
	return statement, arg, true
}

// AppList — GET /api/v1/system/app-logs (AdminOnly).
//
// Filters: ?level, ?logger_name, ?request_id, ?since, ?limit.
func (h *Handlers) AppList(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	statement, arg, ok := buildAppQuery(map[string]string{
		"level":       query.Get("level"),
		"logger_name": query.Get("logger_name"),
		"request_id":  query.Get("request_id"),
		"since":       query.Get("since"),
	}, parseLimit(query.Get("limit")))
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, badFilter)
		return
	}

	// #nosec G701 -- buildAppQuery pastes only constant column and table names into the text; filter.eq/oneOf/numeric/since bind every query-string value as a placeholder.
	rows, err := h.DB.QueryContext(r.Context(), statement, arg...)
	if err != nil {
		httpx.LogR(r, "app log list: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "app log read failed")
		return
	}
	defer func() { _ = rows.Close() }() // read-only query: closing the result set has nothing to flush

	out := make([]AppEntry, 0)
	for rows.Next() {
		var e AppEntry
		if err := rows.Scan(&e.ID, &e.Time, &e.Level, &e.LoggerName, &e.Message,
			&e.Context, &e.RequestID); err != nil {
			// #nosec G706 -- the logged value is a database error; no request-controlled string reaches the log.
			httpx.WarnR(r, "app log list: skipping an unreadable row: %v", err)
			continue
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		httpx.LogR(r, "app log read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "app log read failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
