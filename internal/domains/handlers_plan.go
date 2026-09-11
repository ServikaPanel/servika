// Domain plan assignment and resource-limit reapplication.
package domains

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"servika/internal/httpx"
	"servika/internal/mail"
	"servika/internal/provisioner"
	"servika/internal/resourcelimit"

	"github.com/go-chi/chi/v5"
)

// PUT /domains/{id}/plan  body: {"plan_id": 3}  (null removes the plan)
type setPlanReq struct {
	PlanID *int64 `json:"plan_id"`
}

func (h *Handlers) SetPlan(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var req setPlanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// verify the plan exists
	if req.PlanID != nil {
		var n int
		if err := h.DB.QueryRowContext(r.Context(),
			`SELECT COUNT(*) FROM service_plans WHERE id=?`, *req.PlanID).Scan(&n); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
			return
		}
		if n == 0 {
			httpx.WriteError(w, http.StatusBadRequest, "plan not found")
			return
		}
	}
	// Verify that the domain exists.
	var systemUser string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).Scan(&systemUser); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			httpx.WriteError(w, http.StatusNotFound, "domain not found")
		} else {
			httpx.WriteError(w, http.StatusInternalServerError, "database operation failed")
		}
		return
	}
	// update
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET plan_id=? WHERE id=?`, req.PlanID, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "plan assignment failed")
		return
	}
	// Reapply resource limits in the background with an independent context.
	// The request context is cancelled when the HTTP request ends and would interrupt the cgroup write.
	// #nosec G118 -- intentional detached context, see comment above.
	go func(did int64) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := resourcelimit.ApplyAll(ctx, h.DB, did); err != nil {
			httpx.LogR(r, "resource limit apply domain=%d: %v", did, err)
		}
		// Plan change may also change the WAF default; re-render the vhost with WAF
		// (domain override takes precedence, plan default is the fallback).
		if err := provisioner.WAFApply(h.DB, did); err != nil {
			httpx.LogR(r, "waf apply (plan change) domain=%d: %v", did, err)
		}
		// Mail limits follow the plan as well. A mailbox whose limits were set by
		// hand keeps them; everything else moves to the new plan's values, so the
		// plan on the screen and the limits Dovecot and the policy server enforce
		// describe the same thing.
		if _, err := mail.ApplyPlanLimitsToDomain(ctx, h.DB, did); err != nil {
			httpx.LogR(r, "mail limit apply (plan change) domain=%d: %v", did, err)
		}
	}(id)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "plan_id": req.PlanID})
}
