package logview

import (
	"net/http"

	"servika/internal/httpx"
)

// RequestEntry is one request_logs row as the screen reads it.
type RequestEntry struct {
	ID           int64  `json:"id"`
	Time         string `json:"ts"`
	RequestID    string `json:"request_id"`
	UserID       int64  `json:"user_id"`
	Username     string `json:"username"`
	IP           string `json:"ip"`
	UserAgent    string `json:"user_agent"`
	Method       string `json:"method"`
	Endpoint     string `json:"endpoint"`
	Module       string `json:"module"`
	Action       string `json:"action"`
	QueryParams  string `json:"query_params"`
	RequestBody  string `json:"request_body"`
	Status       int    `json:"response_status"`
	Milliseconds int    `json:"response_ms"`
	ErrorMessage string `json:"error_message"`
}

// requestColumns is the projection, in the order RequestEntry scans them.
const requestColumns = `id, DATE_FORMAT(ts, '%Y-%m-%d %H:%i:%s'), request_id,
	COALESCE(user_id,0), username, ip, user_agent, method, endpoint, module, action,
	COALESCE(query_params,''), COALESCE(request_body,''), response_status, response_ms, error_message`

// buildRequestQuery assembles the request_logs SELECT from the filters.
//
// Kept separate from the handler so the filter and injection-safety logic is
// unit-testable without a database.
func buildRequestQuery(values map[string]string, limit int) (string, []any, bool) {
	var f filter
	f.eq("request_id", values["request_id"])
	f.eq("method", values["method"])
	f.eq("module", values["module"])
	ok := f.numeric("user_id", values["user_id"]) &&
		f.numeric("response_status", values["status"]) &&
		f.since(values["since"])
	if !ok {
		return "", nil, false
	}
	statement, arg := f.query(requestColumns, "request_logs", limit)
	return statement, arg, true
}

// List — GET /api/v1/system/request-logs (AdminOnly).
//
// Filters: ?request_id, ?method, ?module, ?user_id, ?status, ?since, ?limit.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	statement, arg, ok := buildRequestQuery(map[string]string{
		"request_id": query.Get("request_id"),
		"method":     query.Get("method"),
		"module":     query.Get("module"),
		"user_id":    query.Get("user_id"),
		"status":     query.Get("status"),
		"since":      query.Get("since"),
	}, parseLimit(query.Get("limit")))
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, badFilter)
		return
	}

	rows, err := h.DB.QueryContext(r.Context(), statement, arg...)
	if err != nil {
		httpx.LogR(r, "request log list: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "request log read failed")
		return
	}
	defer func() { _ = rows.Close() }() // read-only query: closing the result set has nothing to flush

	out := make([]RequestEntry, 0)
	for rows.Next() {
		var e RequestEntry
		if err := rows.Scan(&e.ID, &e.Time, &e.RequestID, &e.UserID, &e.Username, &e.IP,
			&e.UserAgent, &e.Method, &e.Endpoint, &e.Module, &e.Action, &e.QueryParams,
			&e.RequestBody, &e.Status, &e.Milliseconds, &e.ErrorMessage); err != nil {
			// #nosec G706 -- the logged value is a database error; no request-controlled string reaches the log.
			httpx.WarnR(r, "request log list: skipping an unreadable row: %v", err)
			continue
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		httpx.LogR(r, "request log read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "request log read failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
