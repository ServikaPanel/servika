//go:build windows

package main

// The local panel's routes and its listener.
//
// It shares the agent API's process and its certificate, so an operator sees
// ONE identity on both ports and approves one exception.

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"servika/internal/platform"
)

// defaultPanelListen is the local panel's address. SERVIKA_PANEL_LISTEN
// overrides it.
const defaultPanelListen = "0.0.0.0:8443"

// sessions is the local panel's session table.
var sessions = newSessionStore(filepath.Join(dataDir, "sessions.json"))

// plans is the plan store, kept beside the settings.
var plans = platform.PlanStore{Path: filepath.Join(dataDir, "plans.json")}

// panelServer builds the local panel. serve starts it listening.
func panelServer(cert tls.Certificate) *http.Server {
	address := os.Getenv("SERVIKA_PANEL_LISTEN")
	if address == "" {
		address = defaultPanelListen
	}
	sessions.load()
	go sessions.flushPeriodically()

	mux := http.NewServeMux()
	registerPanelRoutes(mux)
	return &http.Server{
		Addr:    address,
		Handler: mux,
		TLSConfig: &tls.Config{
			// The same floor as the agent API.
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
	}
}

// guarded puts an endpoint behind the session.
func guarded(h http.HandlerFunc) http.HandlerFunc { return sessionGuard(sessions, h) }

// changing puts a state-changing endpoint behind the session AND the audit and
// CSRF wrapper.
func changing(name string, h http.HandlerFunc) http.HandlerFunc {
	return sessionGuard(sessions, audited(name, h))
}

// panelHashFromDisk reads the stored password hash for each login attempt, so a
// reset takes effect without a service restart.
func panelHashFromDisk() string {
	current, err := readSettings(dataDir)
	if err != nil {
		return ""
	}
	return current.PanelPasswordHash
}

// registerPanelRoutes wires every local route.
func registerPanelRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/local/login", loginHandler(sessions, panelHashFromDisk))
	mux.HandleFunc("/api/local/logout", logoutHandler(sessions))
	mux.HandleFunc("/api/local/summary", guarded(summaryEndpoint))
	mux.HandleFunc("/api/local/sites", changing("sites", sitesEndpoint))
	mux.HandleFunc("/api/local/events", guarded(eventsHandler))
	mux.HandleFunc("/api/local/tasks", guarded(tasksHandler))
	mux.HandleFunc("/api/local/catalog", guarded(catalogEndpoint))
	mux.HandleFunc("/api/local/catalog/install", changing("catalog-install", catalogInstallEndpoint))
	mux.HandleFunc("/api/local/catalog/job", guarded(catalogJobEndpoint))
	// The stream is a READ, so it is not wrapped by the audit: a connection held
	// open for half an hour would log a misleading "took=1800000ms" line.
	mux.HandleFunc("/api/local/catalog/job-stream", guarded(catalogStreamEndpoint))
	registerOpsRoutes(mux)
	registerDatabaseRoutes(mux)
	registerPlanRoutes(mux)
	registerSettingsRoutes(mux)

	mountInterface(mux)
}

// summaryEndpoint answers GET /api/local/summary with the panel's header data.
// The field names line up with the agent API's /health.
func summaryEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodFailure(w, r)
		return
	}
	host, _ := os.Hostname() // an error leaves it empty; the summary still answers
	caps := platform.Active().Capabilities()
	panelJSON(w, http.StatusOK, map[string]any{
		"hostname":     host,
		"version":      platform.Version,
		"channel":      platform.Channel,
		"capabilities": uint32(caps),
		"selftested":   caps.Has(platform.CapSite),
	})
}

// sitesEndpoint lists, creates and deletes IIS sites.
func sitesEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		listSites(w, r)
	case http.MethodPost:
		createPanelSite(w, r)
	case http.MethodDelete:
		deletePanelSite(w, r)
	default:
		methodFailure(w, r)
	}
}

func listSites(w http.ResponseWriter, r *http.Request) {
	list, err := platform.SiteList()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, err)
		return
	}
	panelJSON(w, http.StatusOK, map[string]any{"sites": list})
}

func createPanelSite(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Domain string `json:"domain"`
	}
	if !readRequest(w, r, &request) {
		return
	}
	// The selftest seal gate lives inside the platform, so an unproven host is
	// refused there rather than being checked again here.
	result, err := platform.Active().CreateSite(platform.SiteRequest{Domain: request.Domain})
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	log.Printf("local panel: site created: %s (%s)", request.Domain, result.SystemUser)
	panelJSON(w, http.StatusOK, result)
}

func deletePanelSite(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeEnvelope(w, r, http.StatusBadRequest, CodeInvalidRequest, "the domain parameter is required", false)
		return
	}
	// SystemUser is left empty on purpose: the platform derives it from the
	// domain, and that derivation is the one place it is defined.
	if err := platform.Active().DeleteSite(platform.SiteID{Domain: domain}); err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	log.Printf("local panel: site deleted: %s", domain)
	_ = plans.Forget(domain) // drop the now orphaned plan assignment
	panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// catalogEndpoint answers GET /api/local/catalog.
func catalogEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodFailure(w, r)
		return
	}
	panelJSON(w, http.StatusOK, map[string]any{"items": platform.CatalogStatus()})
}

// catalogInstallEndpoint starts an installation and answers 202 with its job id.
func catalogInstallEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodFailure(w, r)
		return
	}
	var request struct {
		Key string `json:"key"`
	}
	if !readRequest(w, r, &request) {
		return
	}
	id, err := installer.Start(request.Key)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, err)
		return
	}
	log.Printf("local panel: installation started: %s (job %s)", request.Key, id)
	panelJSON(w, http.StatusAccepted, map[string]string{"job_id": id})
}

// catalogJobEndpoint answers GET /api/local/catalog/job?id=X with the job's
// state and its whole log. It is the fallback for a client that cannot stream.
func catalogJobEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodFailure(w, r)
		return
	}
	view, found := installer.JobStatus(r.URL.Query().Get("id"))
	if !found {
		panelJSON(w, http.StatusNotFound, map[string]string{"error": "no such job"})
		return
	}
	panelJSON(w, http.StatusOK, jobAnswer(view))
}

// jobAnswer is the shape both the poll and the stream send.
func jobAnswer(view platform.JobView) map[string]any {
	return map[string]any{
		"state": view.State, "finished": view.Finished,
		"log": view.Log, "progress": view.Progress, "secret": view.Secret,
	}
}

// catalogStreamEndpoint streams a job's state as Server-Sent Events.
//
// The interface prefers this and falls back to the poll endpoint when the
// browser cannot stream. There is no WriteTimeout on this server, so a long
// stream is safe.
func catalogStreamEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodFailure(w, r)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		panelJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming is not supported"})
		return
	}
	id := r.URL.Query().Get("id")
	if _, found := installer.JobStatus(id); !found {
		panelJSON(w, http.StatusNotFound, map[string]string{"error": "no such job"})
		return
	}
	writeStreamHeaders(w)
	streamJob(w, r, flusher, id)
}

// writeStreamHeaders opens the event stream.
func writeStreamHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // stop a proxy in between buffering it
	w.WriteHeader(http.StatusOK)
}

// streamJob sends a snapshot twice a second until the job settles or the client
// goes away.
func streamJob(w http.ResponseWriter, r *http.Request, flusher http.Flusher, id string) {
	if sendJobEvent(w, flusher, id) {
		return // already finished: one event and close
	}
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return // the client closed the connection
		case <-tick.C:
			if sendJobEvent(w, flusher, id) {
				return
			}
		}
	}
}

// sendJobEvent writes one snapshot and reports whether the stream should close.
func sendJobEvent(w http.ResponseWriter, flusher http.Flusher, id string) bool {
	view, found := installer.JobStatus(id)
	if !found {
		return true // the job vanished, which should not happen
	}
	b, err := json.Marshal(jobAnswer(view))
	if err != nil {
		return true
	}
	if _, err := w.Write([]byte("data: " + string(b) + "\n\n")); err != nil {
		return true // the client went away
	}
	flusher.Flush()
	return view.Finished
}
