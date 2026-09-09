package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"servika/internal/httpx"
	"servika/internal/quota"
)

// Handlers provides per-domain application HTTP handlers.
type Handlers struct {
	DB *sql.DB
}

// scope is the domain an application request is about.
type scope struct {
	DomainID   int64
	SystemUser string
	PHPVersion string
	Demo       bool
}

// lookup reads the domain named in the URL. Ownership of that domain is already
// settled by middleware.CustomerScope on the route.
func (h *Handlers) lookup(r *http.Request) (scope, bool) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var s scope
	var demo int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, COALESCE(php_version,'8.3'), is_demo FROM domains WHERE id=?`, id).
		Scan(&s.SystemUser, &s.PHPVersion, &demo); err != nil {
		return scope{}, false
	}
	s.DomainID = id
	s.Demo = demo == 1
	if !ValidSystemUser(s.SystemUser) {
		return scope{}, false
	}
	return s, true
}

// loadApp reads the application named in the URL within its domain.
func (h *Handlers) loadApp(r *http.Request, s scope) (App, bool) {
	appID, _ := strconv.ParseInt(chi.URLParam(r, "aid"), 10, 64)
	app, err := Get(r.Context(), h.DB, s.DomainID, appID)
	if err != nil {
		return App{}, false
	}
	return app, true
}

// view is what the list and detail endpoints return. It carries the resolved
// command so a screen can show what actually runs without being told the
// interpreter's full version path.
type view struct {
	App
	Status  Status `json:"status"`
	Command string `json:"resolved_command"`
	URL     string `json:"url"`
}

func (h *Handlers) view(app App, s scope) view {
	out := view{App: app, Status: UnitStatus(app.ID)}
	if appDir, err := SafeAppDir(s.SystemUser, app.AppRoot); err == nil {
		if argv, err := ParseStartCommand(app.Start); err == nil {
			if execStart, err := ResolveExec(app.Runtime, app.Version, appDir, argv); err == nil {
				out.Command = DisplayExec(execStart)
			}
		}
	}
	out.URL = app.Mount
	return out
}

// List returns every application on the domain.
// GET /domains/{id}/apps
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	s, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	list, err := ListForDomain(r.Context(), h.DB, s.DomainID)
	if err != nil {
		log.Printf("apps: list for domain %d: %v", s.DomainID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "applications could not be listed")
		return
	}
	views := make([]view, 0, len(list))
	for _, app := range list {
		views = append(views, h.view(app, s))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"apps": views})
}

// appRequest is the create and update body.
type appRequest struct {
	Name        string `json:"name"`
	Runtime     string `json:"runtime"`
	Version     string `json:"runtime_version"`
	AppRoot     string `json:"app_root"`
	Start       string `json:"start_command"`
	Mount       string `json:"mount_path"`
	SubdomainID int64  `json:"subdomain_id"`
}

// validated is a request that has passed every check, with the derived values
// the caller needs.
type validated struct {
	request appRequest
	appDir  string
	argv    []string
	mount   string
}

// validate refuses everything that must not reach a unit file, and resolves the
// runtime so an application is never created against an interpreter that is not
// installed.
func (h *Handlers) validate(r *http.Request, s scope, req appRequest) (validated, error) {
	req.Name = strings.TrimSpace(req.Name)
	if !ValidName(req.Name) {
		return validated{}, errors.New("invalid application name")
	}
	mount, err := NormalizeMount(req.Mount)
	if err != nil {
		return validated{}, err
	}
	appDir, err := SafeAppDir(s.SystemUser, req.AppRoot)
	if err != nil {
		return validated{}, err
	}
	argv, err := ParseStartCommand(req.Start)
	if err != nil {
		return validated{}, err
	}
	if _, err := ResolveRuntime(req.Runtime, req.Version); err != nil {
		return validated{}, err
	}
	if req.SubdomainID > 0 {
		var n int
		if err := h.DB.QueryRowContext(r.Context(),
			`SELECT COUNT(*) FROM subdomains WHERE id=? AND domain_id=?`,
			req.SubdomainID, s.DomainID).Scan(&n); err != nil {
			// FAIL-CLOSED: an unreadable count must not let an application be
			// attached to a subdomain of another domain.
			return validated{}, errors.New("the subdomain could not be verified")
		}
		if n == 0 {
			return validated{}, errors.New("that subdomain does not belong to this domain")
		}
	}
	req.Mount = mount
	return validated{request: req, appDir: appDir, argv: argv, mount: mount}, nil
}

// Create registers an application, allocates its port and starts it.
// POST /domains/{id}/apps
func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	s, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if s.Demo {
		httpx.WriteError(w, http.StatusForbidden, "applications cannot be managed for a demo subscription")
		return
	}
	var req appRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := quota.CheckAppAllowed(r.Context(), h.DB, s.DomainID); err != nil {
		if limit, ok := errors.AsType[*quota.LimitError](err); ok {
			httpx.WriteError(w, http.StatusForbidden, limit.Message)
			return
		}
		log.Printf("apps: application limit check for domain %d: %v", s.DomainID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the plan limit could not be verified")
		return
	}
	valid, err := h.validate(r, s, req)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	var appID int64
	var subdomain any
	if valid.request.SubdomainID > 0 {
		subdomain = valid.request.SubdomainID
	}
	_, err = AllocatePort(r.Context(), h.DB, func(ctx context.Context, port int) error {
		result, err := h.DB.ExecContext(ctx,
			`INSERT INTO apps(domain_id, subdomain_id, name, runtime, runtime_version,
			   app_root, start_command, mount_path, port, enabled)
			 VALUES(?,?,?,?,?,?,?,?,?,1)`,
			s.DomainID, subdomain, valid.request.Name, valid.request.Runtime, valid.request.Version,
			strings.Trim(valid.request.AppRoot, "/"), valid.request.Start, valid.mount, port)
		if err != nil {
			return err
		}
		appID, err = result.LastInsertId()
		return err
	})
	if err != nil {
		if errors.Is(err, ErrNoFreePort) {
			httpx.WriteError(w, http.StatusServiceUnavailable, "no free application port is available on this server")
			return
		}
		if isDuplicateKey(err) {
			httpx.WriteError(w, http.StatusConflict, "another application already answers on that path")
			return
		}
		log.Printf("apps: create on domain %d: %v", s.DomainID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the application could not be created")
		return
	}

	app, err := Get(r.Context(), h.DB, s.DomainID, appID)
	if err != nil {
		log.Printf("apps: reread application %d: %v", appID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the application could not be created")
		return
	}
	if err := h.apply(r, s, app, valid.appDir, valid.argv); err != nil {
		// The row exists but the host does not match it. Remove both rather
		// than leaving a port allocated to an application that never ran.
		Teardown(app.ID)
		if _, delErr := h.DB.ExecContext(r.Context(), `DELETE FROM apps WHERE id=?`, app.ID); delErr != nil {
			log.Printf("apps: roll back application %d: %v", app.ID, delErr)
		}
		log.Printf("apps: apply application %d: %v", app.ID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the application could not be started")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, h.view(app, s))
}

// Update rewrites an application and restarts it under the new settings.
// PUT /domains/{id}/apps/{aid}
func (h *Handlers) Update(w http.ResponseWriter, r *http.Request) {
	s, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if s.Demo {
		httpx.WriteError(w, http.StatusForbidden, "applications cannot be managed for a demo subscription")
		return
	}
	app, ok := h.loadApp(r, s)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "application not found")
		return
	}
	var req appRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.SubdomainID = app.SubdomainID // The scope is fixed at creation.
	valid, err := h.validate(r, s, req)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE apps SET name=?, runtime=?, runtime_version=?, app_root=?, start_command=?, mount_path=?
		 WHERE id=? AND domain_id=?`,
		valid.request.Name, valid.request.Runtime, valid.request.Version,
		strings.Trim(valid.request.AppRoot, "/"), valid.request.Start, valid.mount,
		app.ID, s.DomainID); err != nil {
		if isDuplicateKey(err) {
			httpx.WriteError(w, http.StatusConflict, "another application already answers on that path")
			return
		}
		log.Printf("apps: update application %d: %v", app.ID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the application could not be updated")
		return
	}
	updated, err := Get(r.Context(), h.DB, s.DomainID, app.ID)
	if err != nil {
		log.Printf("apps: reread application %d: %v", app.ID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the application could not be updated")
		return
	}
	if err := h.apply(r, s, updated, valid.appDir, valid.argv); err != nil {
		log.Printf("apps: apply application %d: %v", app.ID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the application could not be restarted")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.view(updated, s))
}

// Delete removes an application from the host and the database.
// DELETE /domains/{id}/apps/{aid}
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	s, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	app, ok := h.loadApp(r, s)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "application not found")
		return
	}
	Teardown(app.ID)
	if _, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM apps WHERE id=? AND domain_id=?`, app.ID, s.DomainID); err != nil {
		log.Printf("apps: delete application %d: %v", app.ID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the application could not be removed")
		return
	}
	if err := h.render(s, app.SubdomainID); err != nil {
		// The application is gone; a stale proxy block is the remaining
		// problem, and saying so is better than reporting a clean delete.
		log.Printf("apps: re-render after deleting application %d: %v", app.ID, err)
		httpx.WriteError(w, http.StatusInternalServerError,
			"the application was removed but the web server configuration could not be rewritten")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Action starts, stops or restarts an application.
// POST /domains/{id}/apps/{aid}/action
func (h *Handlers) Action(w http.ResponseWriter, r *http.Request) {
	s, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if s.Demo {
		httpx.WriteError(w, http.StatusForbidden, "applications cannot be managed for a demo subscription")
		return
	}
	app, ok := h.loadApp(r, s)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "application not found")
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var err error
	enabled := app.Enabled
	switch req.Action {
	case "start":
		err, enabled = Enable(app.ID), true
	case "stop":
		err, enabled = Disable(app.ID), false
	case "restart":
		err = Restart(app.ID)
	default:
		httpx.WriteError(w, http.StatusBadRequest, "action must be start, stop or restart")
		return
	}
	if err != nil {
		log.Printf("apps: %s application %d: %v", req.Action, app.ID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the application did not answer the request")
		return
	}
	if enabled != app.Enabled {
		if _, err := h.DB.ExecContext(r.Context(),
			`UPDATE apps SET enabled=? WHERE id=? AND domain_id=?`,
			map[bool]int{true: 1, false: 0}[enabled], app.ID, s.DomainID); err != nil {
			log.Printf("apps: record state of application %d: %v", app.ID, err)
			httpx.WriteError(w, http.StatusInternalServerError,
				"the application answered but its state could not be recorded")
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "status": UnitStatus(app.ID)})
}

// StatusOf reports what systemd says about one application.
// GET /domains/{id}/apps/{aid}/status
func (h *Handlers) StatusOf(w http.ResponseWriter, r *http.Request) {
	s, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	app, ok := h.loadApp(r, s)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "application not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, UnitStatus(app.ID))
}

// Log returns the end of an application's output.
// GET /domains/{id}/apps/{aid}/log
func (h *Handlers) Log(w http.ResponseWriter, r *http.Request) {
	s, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	app, ok := h.loadApp(r, s)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "application not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"log":    LogTail(app.ID),
		"status": UnitStatus(app.ID),
	})
}

// EnvRead returns the application's environment.
// GET /domains/{id}/apps/{aid}/env
func (h *Handlers) EnvRead(w http.ResponseWriter, r *http.Request) {
	s, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	app, ok := h.loadApp(r, s)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "application not found")
		return
	}
	values, err := ReadEnv(r.Context(), h.DB, app.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"env":      values,
		"reserved": []string{"PORT", "HOST"},
		"port":     app.Port,
	})
}

// EnvWrite replaces the application's environment and restarts it.
// PUT /domains/{id}/apps/{aid}/env
func (h *Handlers) EnvWrite(w http.ResponseWriter, r *http.Request) {
	s, ok := h.lookup(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if s.Demo {
		httpx.WriteError(w, http.StatusForbidden, "applications cannot be managed for a demo subscription")
		return
	}
	app, ok := h.loadApp(r, s)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "application not found")
		return
	}
	var req struct {
		Env map[string]string `json:"env"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Env) > 200 {
		httpx.WriteError(w, http.StatusBadRequest, "too many environment variables")
		return
	}
	for name, value := range req.Env {
		if !ValidEnvName(name) {
			httpx.WriteError(w, http.StatusBadRequest,
				fmt.Sprintf("%q is not a valid environment variable name", name))
			return
		}
		if ReservedEnvNames[name] {
			httpx.WriteError(w, http.StatusBadRequest,
				fmt.Sprintf("%s is set by the panel and cannot be overridden", name))
			return
		}
		if !ValidEnvValue(value) {
			httpx.WriteError(w, http.StatusBadRequest,
				fmt.Sprintf("the value of %s holds a line break or is too long", name))
			return
		}
	}
	if err := ReplaceEnv(r.Context(), h.DB, app.ID, req.Env); err != nil {
		log.Printf("apps: write environment of application %d: %v", app.ID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the environment could not be saved")
		return
	}
	if err := WriteEnvFile(app, req.Env); err != nil {
		log.Printf("apps: install environment file of application %d: %v", app.ID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the environment could not be published")
		return
	}
	if app.Enabled {
		if err := Restart(app.ID); err != nil {
			log.Printf("apps: restart application %d after an environment change: %v", app.ID, err)
			httpx.WriteError(w, http.StatusInternalServerError,
				"the environment was saved but the application could not be restarted")
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
