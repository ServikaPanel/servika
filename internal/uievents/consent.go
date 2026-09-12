package uievents

// The account's own consent to being recorded.
//
// Recording a screen is processing personal data, so the switch alone is not
// enough: the account has to agree, and it has to be able to withdraw. Both the
// switch and the consent are asked again on the write path, so an agreement
// withdrawn here stops the next batch even if the browser keeps recording.

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"servika/internal/httpx"
	"servika/internal/middleware"
)

// consentBody is what the banner and the recorder read.
//
// It carries the server-wide switch as well, because a browser that only knew
// its own consent would keep asking for one on a panel where recording is off.
type consentBody struct {
	Enabled   bool   `json:"enabled"`
	Consented bool   `json:"consented"`
	At        string `json:"at"`
}

// ConsentGet — GET /api/v1/me/replay-consent (any authenticated role).
func (h *Handlers) ConsentGet(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFrom(r)
	if claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	body, err := h.consentOf(r, claims.UserID)
	if err != nil {
		httpx.LogR(r, "replay consent read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the consent could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

// ConsentSave — PUT /api/v1/me/replay-consent (any authenticated role).
//
// Withdrawing clears the timestamp rather than storing a "declined" value: the
// write path asks whether the column is NULL, and one question with one answer
// cannot drift out of step with a second column.
func (h *Handlers) ConsentSave(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFrom(r)
	if claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req struct {
		Accepted bool `json:"accepted"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	statement := `UPDATE users SET replay_consent_at=NULL WHERE id=?`
	target := "accepted=false"
	if req.Accepted {
		statement = `UPDATE users SET replay_consent_at=UTC_TIMESTAMP() WHERE id=?`
		target = "accepted=true"
	}
	if _, err := h.DB.ExecContext(r.Context(), statement, claims.UserID); err != nil {
		middleware.RecordAudit(h.DB, r, "replay.consent", target, false)
		httpx.LogR(r, "replay consent write: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the consent could not be saved")
		return
	}
	middleware.RecordAudit(h.DB, r, "replay.consent", target, true)

	body, err := h.consentOf(r, claims.UserID)
	if err != nil {
		httpx.LogR(r, "replay consent read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the consent could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

// ConsentForget — DELETE /api/v1/me/replay-data (any authenticated role).
//
// It removes the account's own recordings. Withdrawing consent only stops the
// next batch; an account that asks to be forgotten means the ones already
// stored, and waiting for the retention window is not an answer to that.
func (h *Handlers) ConsentForget(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFrom(r)
	if claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	// The batches go first: a session row deleted before them would leave rows
	// nothing points at.
	if _, err := h.DB.ExecContext(r.Context(),
		`DELETE e FROM replay_events e JOIN replay_sessions s ON s.id=e.session_id
		  WHERE s.user_id=?`, claims.UserID); err != nil {
		middleware.RecordAudit(h.DB, r, "replay.forget", "", false)
		httpx.LogR(r, "replay forget: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the recordings could not be deleted")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM replay_sessions WHERE user_id=?`, claims.UserID); err != nil {
		middleware.RecordAudit(h.DB, r, "replay.forget", "", false)
		httpx.LogR(r, "replay forget: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the recordings could not be deleted")
		return
	}
	middleware.RecordAudit(h.DB, r, "replay.forget", "", true)
	w.WriteHeader(http.StatusNoContent)
}

// consentOf reads the switch and the account's own answer together.
func (h *Handlers) consentOf(r *http.Request, userID int64) (consentBody, error) {
	on, err := ReplayEnabled(r.Context(), h.DB)
	if err != nil {
		return consentBody{}, err
	}
	var at sql.NullString
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT DATE_FORMAT(replay_consent_at, '%Y-%m-%d %H:%i:%s') FROM users WHERE id=?`,
		userID).Scan(&at); err != nil {
		return consentBody{}, err
	}
	return consentBody{Enabled: on, Consented: at.Valid, At: at.String}, nil
}
