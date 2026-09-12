package panelsettings

// Log retention. How long the panel keeps its own request and application log
// rows before deleting them.

import (
	"encoding/json"
	"net/http"
	"strconv"

	"servika/internal/httpx"
	"servika/internal/logretention"
	"servika/internal/middleware"
)

// reasonRetentionOutOfRange is the stable code an out-of-range value answers
// with. The screen renders the sentence in twelve languages, so it matches on
// this rather than on prose.
const reasonRetentionOutOfRange = "log_retention_out_of_range"

type logRetentionBody struct {
	Days int `json:"days"`
	Min  int `json:"min"`
	Max  int `json:"max"`
}

// LogRetentionGet — GET /api/v1/system/log-retention (AdminOnly).
func (h *Handlers) LogRetentionGet(w http.ResponseWriter, r *http.Request) {
	days, err := logretention.Days(r.Context(), h.DB)
	if err != nil {
		httpx.LogR(r, "log retention setting read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "panel settings could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, logRetentionBody{
		Days: days, Min: logretention.MinDays, Max: logretention.MaxDays,
	})
}

// LogRetentionSave — PUT /api/v1/system/log-retention (AdminOnly).
//
// An out-of-range value is REFUSED rather than clamped, for the same reason the
// idle timeout refuses one: storing a different number than the operator typed
// tells them the panel can do something it cannot.
func (h *Handlers) LogRetentionSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Days int `json:"days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !logretention.Valid(req.Days) {
		httpx.WriteError(w, http.StatusBadRequest, reasonRetentionOutOfRange)
		return
	}
	target := "days=" + strconv.Itoa(req.Days)
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE panel_settings SET log_retention_days=? WHERE id=1`, req.Days); err != nil {
		middleware.RecordAudit(h.DB, r, "panel.log_retention", target, false)
		httpx.LogR(r, "log retention setting write: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "panel settings could not be saved")
		return
	}
	middleware.RecordAudit(h.DB, r, "panel.log_retention", target, true)
	// Without this the sweep keeps the old window for up to a minute after the
	// screen said the new one was saved.
	logretention.Invalidate()
	httpx.WriteJSON(w, http.StatusOK, logRetentionBody{
		Days: req.Days, Min: logretention.MinDays, Max: logretention.MaxDays,
	})
}
