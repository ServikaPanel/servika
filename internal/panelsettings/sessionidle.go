package panelsettings

// Session idle timeout. This is the server-wide policy, distinct from the JWT
// lifetime: the lifetime ends a session a fixed time after it was issued, this
// one ends it a fixed time after the last request. Both apply at once.

import (
	"encoding/json"
	"log"
	"net/http"

	"servika/internal/httpx"
	"servika/internal/sessionidle"
)

// reasonIdleOutOfRange is the stable code an out-of-range value answers with.
// The screen renders the sentence in twelve languages, so it matches on this
// rather than on prose.
const reasonIdleOutOfRange = "session_idle_out_of_range"

type sessionIdleBody struct {
	Minutes int `json:"minutes"`
	Max     int `json:"max"`
}

// SessionIdleGet — GET /api/v1/system/session-idle (AdminOnly).
func (h *Handlers) SessionIdleGet(w http.ResponseWriter, r *http.Request) {
	minutes, err := sessionidle.Minutes(r.Context(), h.DB)
	if err != nil {
		log.Printf("session idle setting read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "panel settings could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sessionIdleBody{Minutes: minutes, Max: sessionidle.MaxMinutes})
}

// SessionIdleSave — PUT /api/v1/system/session-idle (AdminOnly).
//
// An out-of-range value is REFUSED rather than clamped. An operator who typed
// 5000 asked for something this cannot do, and quietly storing 1440 tells them
// it can.
func (h *Handlers) SessionIdleSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Minutes int `json:"minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !sessionidle.Valid(req.Minutes) {
		httpx.WriteError(w, http.StatusBadRequest, reasonIdleOutOfRange)
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE panel_settings SET session_idle_minutes=? WHERE id=1`, req.Minutes); err != nil {
		log.Printf("session idle setting write: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "panel settings could not be saved")
		return
	}
	// Without this the operator watches the old value stay in force for up to a
	// minute after the screen said it was saved.
	sessionidle.Invalidate()
	httpx.WriteJSON(w, http.StatusOK, sessionIdleBody{Minutes: req.Minutes, Max: sessionidle.MaxMinutes})
}
