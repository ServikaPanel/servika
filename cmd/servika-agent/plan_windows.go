//go:build windows

package main

// The local panel's hosting plan endpoints: the plans themselves, assigning one
// to a site, and installing the disk quota engine a plan's disk limit needs.

import (
	"net/http"

	"servika/internal/platform"
)

// registerPlanRoutes wires the plan endpoints.
func registerPlanRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/local/plans", guarded(plansEndpoint))
	mux.HandleFunc("/api/local/plan-save", changing("plan-save", planSaveEndpoint))
	mux.HandleFunc("/api/local/plan-delete", changing("plan-delete", planDeleteEndpoint))
	mux.HandleFunc("/api/local/plan-assign", changing("plan-assign", planAssignEndpoint))
	mux.HandleFunc("/api/local/plan-remove", changing("plan-remove", planRemoveEndpoint))
	mux.HandleFunc("/api/local/quota-engine-install", changing("quota-engine-install", quotaEngineEndpoint))
}

// plansEndpoint answers GET /api/local/plans with the plans, their assignments
// and whether the quota engine is installed.
func plansEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodGet) {
		return
	}
	status, err := plans.Status(platform.QuotaEngineInstalled())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, err)
		return
	}
	panelJSON(w, http.StatusOK, status)
}

// planSaveEndpoint answers POST /api/local/plan-save with a whole plan.
func planSaveEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodPost) {
		return
	}
	var plan platform.Plan
	if !readRequest(w, r, &plan) {
		return
	}
	if err := plans.Save(plan); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// planDeleteEndpoint answers POST /api/local/plan-delete {name}. A plan a site
// still carries is refused in the platform.
func planDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if !readRequest(w, r, &request) {
		return
	}
	if err := plans.Delete(request.Name); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// planAssignEndpoint answers POST /api/local/plan-assign {site, plan}.
//
// The result says which limits were actually applied, because a disk quota
// needs the quota engine and a plan assigned without it would otherwise look
// fully enforced.
func planAssignEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		Site string `json:"site"`
		Plan string `json:"plan"`
	}
	if !readRequest(w, r, &request) {
		return
	}
	result, err := plans.AssignPlan(request.Site, request.Plan)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	panelJSON(w, http.StatusOK, result)
}

// planRemoveEndpoint answers POST /api/local/plan-remove {site}.
func planRemoveEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		Site string `json:"site"`
	}
	if !readRequest(w, r, &request) {
		return
	}
	if err := plans.RemovePlan(request.Site); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// quotaEngineEndpoint answers POST /api/local/quota-engine-install.
//
// Installing File Server Resource Manager takes minutes. There is no
// WriteTimeout on this server, so the request can wait it out.
func quotaEngineEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodPost) {
		return
	}
	restart, err := platform.InstallQuotaEngine()
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	panelJSON(w, http.StatusOK, map[string]bool{"ok": true, "restart": restart})
}
