//go:build windows

package main

// The local panel's database endpoints.
//
//	GET    /api/local/db-engines             -> {"engines":[{Kind,Name,Installed}]}
//	GET    /api/local/db-list?engine=mssql   -> {"databases":[{Name,SizeMB}]}
//	POST   /api/local/db-create {engine,name,user,password}
//	DELETE /api/local/db-drop?engine=&name=
//
// mysql and pgsql answer 422 with PASSWORD_REQUIRED: the agent does not keep
// their administrator password, and saying so is better than reporting a
// success that did not happen.

import (
	"net/http"

	"servika/internal/platform"
)

// registerDatabaseRoutes wires the database endpoints.
func registerDatabaseRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/local/db-engines", guarded(dbEnginesEndpoint))
	mux.HandleFunc("/api/local/db-list", guarded(dbListEndpoint))
	mux.HandleFunc("/api/local/db-create", changing("db-create", dbCreateEndpoint))
	mux.HandleFunc("/api/local/db-drop", changing("db-drop", dbDropEndpoint))
}

// dbEnginesEndpoint reports which engines are installed.
func dbEnginesEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodGet) {
		return
	}
	panelJSON(w, http.StatusOK, map[string]any{"engines": platform.DatabaseEngines()})
}

// dbListEndpoint lists one engine's databases.
func dbListEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodGet) {
		return
	}
	engine := r.URL.Query().Get("engine")
	if engine == "" {
		writeEnvelope(w, r, http.StatusBadRequest, CodeInvalidRequest, "the engine parameter is required", false)
		return
	}
	list, err := platform.ListDatabases(engine)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, err)
		return
	}
	panelJSON(w, http.StatusOK, map[string]any{"databases": list})
}

// dbCreateEndpoint creates a database with its own login and user.
func dbCreateEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		Engine   string `json:"engine"`
		Name     string `json:"name"`
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if !readRequest(w, r, &request) {
		return
	}
	if err := platform.CreateDatabase(request.Engine, request.Name, request.User, request.Password); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	// The password is NOT logged. It reached the agent to be applied, not to be
	// kept in the scrollback.
	panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// dbDropEndpoint drops a database. A system database is refused in the
// platform, which answers PROTECTED.
func dbDropEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodDelete) {
		return
	}
	engine := r.URL.Query().Get("engine")
	name := r.URL.Query().Get("name")
	if engine == "" || name == "" {
		writeEnvelope(w, r, http.StatusBadRequest, CodeInvalidRequest, "the engine and name parameters are required", false)
		return
	}
	if err := platform.DropDatabase(engine, name); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
