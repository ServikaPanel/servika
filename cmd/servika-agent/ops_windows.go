//go:build windows

package main

// The local panel's OPERATIONS endpoints: managing a site and its application
// pool through appcmd, plus the services and the host's load.
//
// The status contract is the same on every endpoint here:
//
//	a failure wrapping platform.ErrInvalidRequest  -> 400
//	any other failure on a READ endpoint           -> 500
//	any other failure on a CHANGING endpoint       -> 422
//	the wrong HTTP method                          -> 405

import (
	"net/http"

	"servika/internal/platform"
)

// registerOpsRoutes wires the operations endpoints.
//
// Read endpoints are NOT wrapped by the audit: they change nothing and would
// only add noise. Every state-changing one is.
func registerOpsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/local/site-detail", guarded(siteDetailEndpoint))
	mux.HandleFunc("/api/local/pool-action", changing("pool-action", poolActionEndpoint))
	mux.HandleFunc("/api/local/pool-runtime", changing("pool-runtime", poolRuntimeEndpoint))
	mux.HandleFunc("/api/local/binding-add", changing("binding-add", bindingAddEndpoint))
	mux.HandleFunc("/api/local/binding", changing("binding-remove", bindingRemoveEndpoint))
	mux.HandleFunc("/api/local/site-ssl", changing("site-ssl", siteSSLEndpoint))
	mux.HandleFunc("/api/local/services", guarded(servicesEndpoint))
	mux.HandleFunc("/api/local/service-action", changing("service-action", serviceActionEndpoint))
	mux.HandleFunc("/api/local/resources", guarded(resourcesEndpoint))
	mux.HandleFunc("/api/local/clear-install-lock", changing("clear-install-lock", clearInstallLockEndpoint))
}

// wantMethod checks the method and writes the standard 405 when it is wrong.
func wantMethod(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.Method != want {
		methodFailure(w, r)
		return false
	}
	return true
}

// siteDetailEndpoint answers GET /api/local/site-detail?domain=<name>.
func siteDetailEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodGet) {
		return
	}
	detail, err := platform.ReadSiteDetail(r.URL.Query().Get("domain"))
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, err)
		return
	}
	panelJSON(w, http.StatusOK, detail)
}

// poolActionEndpoint answers POST /api/local/pool-action {name, action}.
func poolActionEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		Name   string `json:"name"`
		Action string `json:"action"`
	}
	if !readRequest(w, r, &request) {
		return
	}
	if err := platform.PoolAction(request.Name, request.Action); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// poolRuntimeEndpoint answers POST /api/local/pool-runtime {name, version}.
func poolRuntimeEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if !readRequest(w, r, &request) {
		return
	}
	if err := platform.PoolRuntime(request.Name, request.Version); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// bindingAddEndpoint answers POST /api/local/binding-add
// {site, protocol, port, host}.
//
// The port is a string on purpose: the DELETE side carries it as a query
// parameter, so both sides use one type and the range check lives in the
// platform.
func bindingAddEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		Site     string `json:"site"`
		Protocol string `json:"protocol"`
		Port     string `json:"port"`
		Host     string `json:"host"`
	}
	if !readRequest(w, r, &request) {
		return
	}
	if err := platform.AddBinding(request.Site, request.Protocol, request.Port, request.Host); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// bindingRemoveEndpoint answers
// DELETE /api/local/binding?site=&protocol=&port=&host=.
func bindingRemoveEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodDelete) {
		return
	}
	q := r.URL.Query()
	if err := platform.RemoveBinding(q.Get("site"), q.Get("protocol"), q.Get("port"), q.Get("host")); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// siteSSLEndpoint answers POST /api/local/site-ssl {site}.
//
// A certificate that was issued answers 200 with what happened; a win-acme
// timeout or failure answers 422. There is no failure hidden inside a 200.
func siteSSLEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		Site string `json:"site"`
	}
	if !readRequest(w, r, &request) {
		return
	}
	note, err := platform.IssueSiteCertificate(request.Site)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	panelJSON(w, http.StatusOK, map[string]string{"message": note})
}

// servicesEndpoint answers GET /api/local/services.
func servicesEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodGet) {
		return
	}
	list, err := platform.ListServices()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, err)
		return
	}
	panelJSON(w, http.StatusOK, map[string]any{"services": list})
}

// serviceActionEndpoint answers POST /api/local/service-action {name, action}.
func serviceActionEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		Name   string `json:"name"`
		Action string `json:"action"`
	}
	if !readRequest(w, r, &request) {
		return
	}
	if err := platform.ServiceAction(request.Name, request.Action); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// resourcesEndpoint answers GET /api/local/resources with the host's load.
func resourcesEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodGet) {
		return
	}
	view, err := platform.ReadResources()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, err)
		return
	}
	panelJSON(w, http.StatusOK, view)
}

// clearInstallLockEndpoint answers POST /api/local/clear-install-lock.
//
// It clears the lock a cut-short installation left behind. The operator calls
// it once they are sure no installer is still running, which is why it is a
// deliberate action rather than something the agent does on its own.
func clearInstallLockEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodPost) {
		return
	}
	installer.ClearPending()
	panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
