package panelsettings

// Session replay. The server-wide switch that decides whether the browser may
// record anything at all. It is the operator's, not a per-account preference:
// the recording covers every account's screens.

import (
	"encoding/json"
	"net/http"
	"strconv"

	"servika/internal/httpx"
	"servika/internal/middleware"
	"servika/internal/uievents"
)

type sessionReplayBody struct {
	Enabled bool `json:"enabled"`
}

// SessionReplayGet — GET /api/v1/system/session-replay (AdminOnly).
func (h *Handlers) SessionReplayGet(w http.ResponseWriter, r *http.Request) {
	on, err := uievents.ReplayEnabled(r.Context(), h.DB)
	if err != nil {
		httpx.LogR(r, "session replay setting read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "panel settings could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sessionReplayBody{Enabled: on})
}

// SessionReplaySave — PUT /api/v1/system/session-replay (AdminOnly).
//
// Turning the switch off stops new batches at once. It does NOT delete what was
// already recorded: retention deletes those rows on its own window, and an
// operator who wants them gone earlier removes them from the replay screen.
func (h *Handlers) SessionReplaySave(w http.ResponseWriter, r *http.Request) {
	var req sessionReplayBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	value := 0
	if req.Enabled {
		value = 1
	}
	target := "enabled=" + strconv.Itoa(value)
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE panel_settings SET session_replay_enabled=? WHERE id=1`, value); err != nil {
		middleware.RecordAudit(h.DB, r, "panel.session_replay", target, false)
		httpx.LogR(r, "session replay setting write: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "panel settings could not be saved")
		return
	}
	middleware.RecordAudit(h.DB, r, "panel.session_replay", target, true)
	// Without this a switch turned OFF keeps accepting batches for up to a
	// minute after the screen said recording had stopped.
	uievents.Invalidate()
	httpx.WriteJSON(w, http.StatusOK, sessionReplayBody{Enabled: req.Enabled})
}
