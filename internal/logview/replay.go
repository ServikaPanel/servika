package logview

import (
	"net/http"
	"strconv"
	"strings"

	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// ReplayEntry is one replay_sessions row as the list reads it.
type ReplayEntry struct {
	ID        int64  `json:"id"`
	SessionID string `json:"session_id"`
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	PageURL   string `json:"page_url"`
	StartedAt string `json:"started_at"`
	UpdatedAt string `json:"updated_at"`
	Batches   int    `json:"batches"`
}

// replayColumns is the projection, in the order ReplayEntry scans them.
const replayColumns = `id, session_id, COALESCE(user_id,0), username, page_url,
	DATE_FORMAT(started_at, '%Y-%m-%d %H:%i:%s'), DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s'), batches`

// buildReplayQuery assembles the replay_sessions SELECT from the filters.
func buildReplayQuery(values map[string]string, limit int) (string, []any, bool) {
	var f filter
	f.eq("session_id", values["session_id"])
	if !f.numeric("user_id", values["user_id"]) {
		return "", nil, false
	}
	// started_at, not ts: this table names the moment the recording began.
	statement := "SELECT " + replayColumns + " FROM replay_sessions" + f.where() +
		" ORDER BY id DESC LIMIT ?"
	return statement, append(append([]any{}, f.arg...), limit), true
}

// ReplayList — GET /api/v1/system/replay-sessions (AdminOnly).
func (h *Handlers) ReplayList(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	statement, arg, ok := buildReplayQuery(map[string]string{
		"session_id": query.Get("session_id"),
		"user_id":    query.Get("user_id"),
	}, parseLimit(query.Get("limit")))
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, badFilter)
		return
	}

	rows, err := h.DB.QueryContext(r.Context(), statement, arg...)
	if err != nil {
		httpx.LogR(r, "replay list: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the replay list could not be read")
		return
	}
	defer func() { _ = rows.Close() }() // read-only query: closing the result set has nothing to flush

	out := make([]ReplayEntry, 0)
	for rows.Next() {
		var e ReplayEntry
		if err := rows.Scan(&e.ID, &e.SessionID, &e.UserID, &e.Username, &e.PageURL,
			&e.StartedAt, &e.UpdatedAt, &e.Batches); err != nil {
			// #nosec G706 -- the logged value is a database error; no request-controlled string reaches the log.
			httpx.WarnR(r, "replay list: skipping an unreadable row: %v", err)
			continue
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		httpx.LogR(r, "replay list read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the replay list could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// ReplayEvents — GET /api/v1/system/replay/{id} (AdminOnly).
//
// The batches are concatenated in seq order into one JSON array, which is what
// the player takes. The server never reads inside a batch: it was stored as the
// browser sent it and it is returned that way.
func (h *Handlers) ReplayEvents(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid replay id")
		return
	}

	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT batch FROM replay_events WHERE session_id=? ORDER BY seq`, id)
	if err != nil {
		httpx.LogR(r, "replay read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the replay could not be read")
		return
	}
	defer func() { _ = rows.Close() }() // read-only query: closing the result set has nothing to flush

	joined, err := joinBatches(rows.Scan, rows.Next)
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		httpx.LogR(r, "replay read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the replay could not be read")
		return
	}
	writeReplayJSON(w, joined)
}

// joinBatches concatenates the stored arrays into one, without parsing them.
//
// Each batch is a JSON array as the browser produced it, so joining is dropping
// the brackets and putting one comma between them. Parsing and re-encoding
// megabytes of events would cost the server real time to produce the same
// bytes.
func joinBatches(scan func(...any) error, next func() bool) (string, error) {
	var out strings.Builder
	out.WriteString("[")
	first := true
	for next() {
		var batch string
		if err := scan(&batch); err != nil {
			return "", err
		}
		inner := strings.TrimSpace(batch)
		inner = strings.TrimPrefix(inner, "[")
		inner = strings.TrimSuffix(inner, "]")
		if strings.TrimSpace(inner) == "" {
			continue
		}
		if !first {
			out.WriteString(",")
		}
		out.WriteString(inner)
		first = false
	}
	out.WriteString("]")
	return out.String(), nil
}

// writeReplayJSON answers with the already-encoded array.
//
// httpx.WriteJSON would encode the string as a JSON string. The bytes are
// already JSON, so they are written as they are, with the same no-store header
// every other reply carries.
func writeReplayJSON(w http.ResponseWriter, events string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"events":` + events + `}`))
}
