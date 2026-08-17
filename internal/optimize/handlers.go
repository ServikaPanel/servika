package optimize

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"

	"servika/internal/httpx"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

// Handlers serves the server tuning screen.
type Handlers struct {
	DB *sql.DB

	// applying serialises apply and revert against each other. Both edit the
	// same files and reload the same services, and two of them at once would
	// interleave a backup with somebody else's edit, leaving a copy that
	// restores a state that never existed.
	applying sync.Mutex
}

// actorOf returns the acting user, or 0 when the request carries no identity.
func actorOf(r *http.Request) int64 {
	if claims := middleware.ClaimsFrom(r); claims != nil {
		return claims.UserID
	}
	return 0
}

// writeRefusal answers with a stable reason CODE beside the English message,
// because the screen renders twelve languages and cannot translate a sentence
// this package composed.
func writeRefusal(w http.ResponseWriter, status int, reason, message string) {
	httpx.WriteJSON(w, status, map[string]string{"error": message, "reason": reason})
}

// Proposals — GET /system/optimize/proposals (AdminOnly).
//
// The response carries what was measured beside what is proposed, because a
// number computed from the host is only as trustworthy as the reading it came
// from, and the operator is the one being asked to approve it.
func (h *Handlers) Proposals(w http.ResponseWriter, r *http.Request) {
	facts := Measure()
	current, problems := Current(r.Context(), h.DB)

	notes := make([]string, 0, len(problems))
	for _, problem := range problems {
		log.Printf("optimize read: %v", problem)
		notes = append(notes, problem.Error())
	}

	proposals := Compute(facts, current)
	if proposals == nil {
		proposals = []Proposal{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"memory_mb": facts.MemoryMB,
		"cpus":      facts.CPUs,
		"proposals": proposals,
		// unreadable names what could not be read. A screen that showed an
		// empty list without saying the reading failed would report a tuned
		// server, which is the one answer this must never give by accident.
		"unreadable": notes,
	})
}

// ApplyChosen — POST /system/optimize/apply (AdminOnly).
func (h *Handlers) ApplyChosen(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(body.IDs) == 0 || len(body.IDs) > 64 {
		writeRefusal(w, http.StatusBadRequest, ReasonNothingChosen, "no parameter was chosen")
		return
	}

	h.applying.Lock()
	defer h.applying.Unlock()

	result, err := Apply(r.Context(), h.DB, body.IDs, actorOf(r))
	if err != nil {
		log.Printf("optimize apply: %v", err)
		if reason := ReasonOf(err); reason != "" {
			writeRefusal(w, http.StatusConflict, reason, err.Error())
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, result)
}

// ListHistory — GET /system/optimize/history (AdminOnly).
func (h *Handlers) ListHistory(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	changes, err := History(r.Context(), h.DB, limit)
	if err != nil {
		log.Printf("optimize history: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"changes": changes})
}

// RevertChange — POST /system/optimize/history/{id}/revert (AdminOnly).
func (h *Handlers) RevertChange(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid change id")
		return
	}

	h.applying.Lock()
	defer h.applying.Unlock()

	if err := Revert(r.Context(), h.DB, id); err != nil {
		log.Printf("optimize revert %d: %v", id, err)
		if reason := ReasonOf(err); reason != "" {
			writeRefusal(w, http.StatusConflict, reason, err.Error())
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"reverted": id})
}
