package backups

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"servika/internal/httpx"
)

// GetSchedule returns a domain's backup schedule.
func (h *Handlers) GetSchedule(w http.ResponseWriter, r *http.Request) {
	id, _, _, err := h.lookupDomain(r)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	var s Schedule
	var last sql.NullString
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(backup_freq,'none'), COALESCE(backup_hour,3), COALESCE(backup_retention,7),
		        DATE_FORMAT(last_backup_at,'%Y-%m-%dT%H:%i:%sZ')
		 FROM domains WHERE id=?`, id).
		Scan(&s.Frequency, &s.Hour, &s.Retention, &last); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if last.Valid {
		s.LastBackupAt = last.String
	}
	httpx.WriteJSON(w, http.StatusOK, s)
}

// SetSchedule updates a domain's backup schedule.
func (h *Handlers) SetSchedule(w http.ResponseWriter, r *http.Request) {
	id, _, _, err := h.lookupDomain(r)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	var s Schedule
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validFrequency(s.Frequency) {
		httpx.WriteError(w, http.StatusBadRequest, "frequency must be none, daily, or weekly")
		return
	}
	if s.Hour < 0 || s.Hour > 23 {
		httpx.WriteError(w, http.StatusBadRequest, "hour: 0-23")
		return
	}
	if s.Retention < 1 {
		s.Retention = 1
	}
	if s.Retention > 90 {
		s.Retention = 90
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET backup_freq=?, backup_hour=?, backup_retention=? WHERE id=?`,
		s.Frequency, s.Hour, s.Retention, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update backup schedule")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "schedule": s})
}

// TickNow starts an immediate scheduler pass for due domains.
func (h *Handlers) TickNow(w http.ResponseWriter, r *http.Request) {
	go TickOnce(h.DB)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "tick": "started"})
}
