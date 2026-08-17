package hostapps

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"servika/internal/httpx"
	"servika/internal/middleware"
)

// Handlers serves the server applications screen. Every route is AdminOnly:
// these applications belong to no customer, so there is no ownership chain to
// scope them by and no scoped view that would mean anything.
type Handlers struct {
	DB *sql.DB
}

func actorOf(r *http.Request) any {
	if claims := middleware.ClaimsFrom(r); claims != nil && claims.UserID > 0 {
		return claims.UserID
	}
	return nil
}

func writeRefusal(w http.ResponseWriter, status int, reason, message string) {
	httpx.WriteJSON(w, status, map[string]string{"error": message, "reason": reason})
}

func (h *Handlers) fail(w http.ResponseWriter, err error, fallback string) {
	if reason := ReasonOf(err); reason != "" {
		writeRefusal(w, http.StatusConflict, reason, err.Error())
		return
	}
	complain("%v", err)
	httpx.WriteError(w, http.StatusInternalServerError, fallback)
}

// offered is one catalog row as the screen sees it.
type offered struct {
	Entry
	Available bool   `json:"available"`
	Reason    string `json:"unavailable_reason,omitempty"`
}

// List — GET /system/host-apps (AdminOnly).
//
// The catalog is answered with an explicit availability verdict per row rather
// than by silently dropping what this architecture cannot run. TeamSpeak has no
// arm64 Linux build at all, and a row that simply vanished on an arm64 server
// would read as a panel that forgot it.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	catalog, err := Catalog(r.Context(), h.DB)
	if err != nil {
		complain("catalog: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	installed, err := Installed(r.Context(), h.DB)
	if err != nil {
		complain("installed: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	for index := range installed {
		installed[index].Status = UnitStatus(installed[index].Code)
	}

	rows := make([]offered, 0, len(catalog))
	for _, entry := range catalog {
		item := offered{Entry: entry, Available: true}
		if _, _, err := Download(entry); err != nil {
			item.Available = false
			item.Reason = ReasonOf(err)
		}
		rows = append(rows, item)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"catalog":      rows,
		"installed":    installed,
		"architecture": runtime.GOARCH,
		"port_min":     PortMin,
		"port_max":     PortMax,
	})
}

// Install — POST /system/host-apps (AdminOnly).
//
// The row and the port are taken before the response, so a second request
// cannot start the same install; the download then runs on its own context and
// the screen follows it through the application's state.
func (h *Handlers) Install(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	entry, err := CatalogEntry(r.Context(), h.DB, body.Code)
	if err != nil {
		h.fail(w, err, "the catalog could not be read")
		return
	}
	if !entry.Enabled {
		writeRefusal(w, http.StatusConflict, ReasonDisabled,
			"this application is not offered on this server")
		return
	}
	// The catalog row is validated here as well as where it is written. It can
	// be edited between the two, and every field in it reaches a URL, a file
	// path or a systemd unit.
	if field, err := ValidEntry(entry); err != nil {
		writeRefusal(w, http.StatusConflict, ReasonOf(err), field+": "+err.Error())
		return
	}
	if _, _, err := Download(entry); err != nil {
		h.fail(w, err, "this application cannot be installed here")
		return
	}

	app, err := Reserve(r.Context(), h.DB, entry, actorOf(r))
	if err != nil {
		h.fail(w, err, "the application could not be recorded")
		return
	}
	jobID, err := startJob(r.Context(), h.DB, &app.ID, entry.Code, "install", actorOf(r))
	if err != nil {
		complain("start job: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database write failed")
		return
	}
	// The request context is deliberately NOT carried into the install. The
	// download and unpack outlive the request that asked for them, and a browser
	// tab closed mid-download would otherwise cancel a half-written installation
	// and leave an account, a directory and a unit behind.
	// #nosec G118 -- the operation is asynchronous by design; Install applies its own deadline.
	go Install(h.DB, entry, app, jobID)

	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"id": app.ID, "code": app.Code, "port": app.Port, "state": app.State,
	})
}

// Remove — DELETE /system/host-apps/{id} (AdminOnly).
func (h *Handlers) Remove(w http.ResponseWriter, r *http.Request) {
	app, ok := h.load(w, r)
	if !ok {
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE host_apps SET state='removing' WHERE id=?`, app.ID); err != nil {
		complain("mark removing: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database write failed")
		return
	}
	jobID, err := startJob(r.Context(), h.DB, &app.ID, app.Code, "remove", actorOf(r))
	if err != nil {
		complain("start job: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database write failed")
		return
	}
	// Same as the install path: the removal archives the data directory first and
	// must not be cancelled halfway by the request that asked for it.
	// #nosec G118 -- the operation is asynchronous by design; Remove applies its own deadline.
	go Remove(h.DB, app, jobID)
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"id": app.ID, "state": "removing"})
}

// Action — POST /system/host-apps/{id}/action (AdminOnly).
func (h *Handlers) Action(w http.ResponseWriter, r *http.Request) {
	app, ok := h.load(w, r)
	if !ok {
		return
	}
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var err error
	switch body.Action {
	case "start":
		err = Enable(app.Code)
	case "stop":
		err = Disable(app.Code)
	case "restart":
		err = Restart(app.Code)
	default:
		httpx.WriteError(w, http.StatusBadRequest, "unknown action")
		return
	}

	jobID, jobErr := startJob(r.Context(), h.DB, &app.ID, app.Code, body.Action, actorOf(r))
	if jobErr == nil {
		finishJob(r.Context(), h.DB, jobID, err)
	}
	if err != nil {
		h.fail(w, err, "the application did not respond to that")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": UnitStatus(app.Code)})
}

// Firewall — PUT /system/host-apps/{id}/firewall (AdminOnly).
func (h *Handlers) Firewall(w http.ResponseWriter, r *http.Request) {
	app, ok := h.load(w, r)
	if !ok {
		return
	}
	var body struct {
		Open bool `json:"open"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := SetFirewall(r.Context(), h.DB, app.ID, body.Open); err != nil {
		h.fail(w, err, "the firewall rule could not be changed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"port": app.Port, "firewall_open": body.Open})
}

// Logs — GET /system/host-apps/{id}/logs (AdminOnly).
func (h *Handlers) Logs(w http.ResponseWriter, r *http.Request) {
	app, ok := h.load(w, r)
	if !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"log": LogTail(app.Code)})
}

// Jobs — GET /system/host-apps/jobs (AdminOnly).
func (h *Handlers) Jobs(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, COALESCE(app_id,0), code, action, state, last_error, created_at
		   FROM host_app_jobs ORDER BY id DESC LIMIT 50`)
	if err != nil {
		complain("jobs: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer func() { _ = rows.Close() }()

	type entry struct {
		ID        int64  `json:"id"`
		AppID     int64  `json:"app_id"`
		Code      string `json:"code"`
		Action    string `json:"action"`
		State     string `json:"state"`
		LastError string `json:"last_error,omitempty"`
		CreatedAt string `json:"created_at"`
	}
	out := []entry{}
	for rows.Next() {
		var item entry
		var created time.Time
		if err := rows.Scan(&item.ID, &item.AppID, &item.Code, &item.Action,
			&item.State, &item.LastError, &created); err != nil {
			complain("jobs scan: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
			return
		}
		item.CreatedAt = created.UTC().Format(time.RFC3339)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		complain("jobs rows: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"jobs": out})
}

func (h *Handlers) load(w http.ResponseWriter, r *http.Request) (App, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid application id")
		return App{}, false
	}
	app, err := AppByID(r.Context(), h.DB, id)
	if err != nil {
		if ReasonOf(err) != "" {
			writeRefusal(w, http.StatusNotFound, ReasonOf(err), err.Error())
			return App{}, false
		}
		complain("load application: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return App{}, false
	}
	return app, true
}
