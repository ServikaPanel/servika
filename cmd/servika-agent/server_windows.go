//go:build windows

package main

// The routes the panel talks to, and the two listeners.
//
// Every route is behind the shared token in the X-Servika-Token header. That
// header name, and the paths below, are the contract internal/winagent speaks;
// changing one without the other breaks the pairing.

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"servika/internal/platform"
)

// serve builds both listeners and blocks on the agent API.
//
// servers[0] is the agent API and servers[1] is the local panel. The service
// side closes both. Running both from ONE function means the foreground and
// service modes take exactly the same path: two modes that behave differently
// produce failures nobody can reproduce.
func serve(servers *[2]*http.Server) error {
	current, err := loadSettings(dataDir)
	if err != nil {
		return err
	}
	provider := platform.Active()
	if err := provider.Verify(); err != nil {
		// A broken environment still comes up, but /health says so plainly: the
		// panel has to tell "unreachable" apart from "not ready".
		log.Printf("WARNING - environment check: %v", err)
	}
	// A previous installation cut short by an agent restart is picked up from
	// disk, and new installations are refused until an operator clears it.
	installer.LoadPending()
	if pending, key := installer.Pending(); pending {
		log.Printf("WARNING - the previous installation (%s) was LEFT HALF-FINISHED; installations are refused until it is cleared", key)
	}

	cert, err := loadCertificate(dataDir)
	if err != nil {
		return fmt.Errorf("the TLS certificate could not be prepared: %w", err)
	}
	api := &http.Server{
		Addr:    current.Listen,
		Handler: agentRoutes(provider, current.Token),
		TLSConfig: &tls.Config{
			// TLS 1.2 is the floor: no negotiating down to an older protocol.
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
	}
	if servers != nil {
		servers[0] = api
	}
	log.Printf("servika-agent %s (%s) is listening over TLS on %s", platform.Version, platform.Channel, current.Listen)
	log.Printf("certificate SHA-256 fingerprint: %s", fingerprintOf(cert))
	// The certificate comes from TLSConfig, so the file arguments are empty.
	return api.ListenAndServeTLS("", "")
}

// agentRoutes builds the API handler.
func agentRoutes(provider platform.Provider, token string) http.Handler {
	mux := http.NewServeMux()
	guard := func(h http.HandlerFunc) http.HandlerFunc { return authorized(token, h) }
	mux.HandleFunc("/health", guard(healthHandler(provider)))
	mux.HandleFunc("/site", guard(siteHandler(provider)))
	mux.HandleFunc("/events", guard(eventsHandler))
	mux.HandleFunc("/tasks", guard(tasksHandler))
	return mux
}

// siteHandler creates and deletes a site.
func siteHandler(provider platform.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			createSite(provider, w, r)
		case http.MethodDelete:
			deleteSite(provider, w, r)
		default:
			writeFailure(w, http.StatusMethodNotAllowed, "that method is not supported")
		}
	}
}

// createSite opens a site for one domain.
func createSite(provider platform.Provider, w http.ResponseWriter, r *http.Request) {
	var request struct {
		Domain     string `json:"domain"`
		PHPVersion string `json:"php_version"`
	}
	if !readRequest(w, r, &request) {
		return
	}
	result, err := provider.CreateSite(platform.SiteRequest{Domain: request.Domain, PHPVersion: request.PHPVersion})
	if err != nil {
		writeFailure(w, statusFor(err), err.Error())
		return
	}
	log.Printf("site created: %s (%s)", request.Domain, result.SystemUser)
	writeJSON(w, http.StatusOK, result)
}

// deleteSite removes a site.
func deleteSite(provider platform.Provider, w http.ResponseWriter, r *http.Request) {
	var request struct {
		Domain     string `json:"domain"`
		SystemUser string `json:"system_user"`
	}
	if !readRequest(w, r, &request) {
		return
	}
	if err := provider.DeleteSite(platform.SiteID{Domain: request.Domain, SystemUser: request.SystemUser}); err != nil {
		writeFailure(w, statusFor(err), err.Error())
		return
	}
	log.Printf("site deleted: %s", request.Domain)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// eventsHandler reads the Windows event log. It is read-only.
//
// The log name allowlist and the count bound live in platform.ReadEvents. They
// are NOT repeated here: one place to change means one place that can be wrong.
func eventsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeFailure(w, http.StatusMethodNotAllowed, "that method is not supported")
		return
	}
	count := 50
	if v := r.URL.Query().Get("count"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeFailure(w, http.StatusBadRequest, "count must be a number")
			return
		}
		count = n
	}
	events, err := platform.ReadEvents(r.URL.Query().Get("log"), count)
	if err != nil {
		writeFailure(w, statusFor(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

// tasksHandler lists the scheduled tasks. all=1 includes the operating system's
// own tasks under \Microsoft\.
func tasksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeFailure(w, http.StatusMethodNotAllowed, "that method is not supported")
		return
	}
	tasks, err := platform.ReadTasks(r.URL.Query().Get("all") == "1")
	if err != nil {
		writeFailure(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": tasks})
}
