package main

// The shape of the agent API: the token guard, the JSON helpers, the status
// mapping and the health answer.
//
// This file carries no build tag. None of it is Windows-specific, and the
// health answer is the contract internal/winagent on the panel side depends on,
// so it is measured on every build rather than only on the host it runs on.

import (
	"encoding/json"
	"net/http"

	"servika/internal/platform"
)

// tokenHeader is what the panel sends. It must match internal/winagent.
const tokenHeader = "X-Servika-Token"

// requestLimit bounds a request body. Every request this API takes is a small
// JSON object, so anything larger is a mistake or an attack.
const requestLimit = 4 << 10

// authorized refuses a request whose token does not match, comparing in
// constant time so the answer does not leak how much was guessed.
func authorized(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tokenMatches(r.Header.Get(tokenHeader), token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// writeJSON writes one JSON answer.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// readRequest decodes a bounded JSON body.
func readRequest(w http.ResponseWriter, r *http.Request, into any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, requestLimit)).Decode(into); err != nil {
		bodyFailure(w, r)
		return false
	}
	return true
}

// healthHandler answers what this host is and what it can do.
//
// The field names are the panel's contract. env_error carries the environment
// failure as text rather than hiding it, so the panel can show "reachable but
// not ready" instead of one undifferentiated failure.
func healthHandler(provider platform.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		envError := ""
		if err := provider.Verify(); err != nil {
			envError = err.Error()
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"platform":     provider.Name(),
			"version":      platform.Version,
			"channel":      platform.Channel,
			"capabilities": uint32(provider.Capabilities()),
			"env_error":    envError,
			"selftested":   provider.Capabilities().Has(platform.CapSite),
		})
	}
}
