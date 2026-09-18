package main

// The shape of the agent API: the token guard, the JSON helpers, the status
// mapping and the health answer.
//
// This file carries no build tag. None of it is Windows-specific, and the
// health answer is the contract internal/winagent on the panel side depends on,
// so it is measured on every build rather than only on the host it runs on.

import (
	"encoding/json"
	"errors"
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

// writeFailure writes an error answer in the same shape.
func writeFailure(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// readRequest decodes a bounded JSON body.
func readRequest(w http.ResponseWriter, r *http.Request, into any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, requestLimit)).Decode(into); err != nil {
		writeFailure(w, http.StatusBadRequest, "the request body could not be read")
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

// statusFor maps a platform failure onto a status code.
//
// A bad request and an unsupported operation are the caller's problem; anything
// else is this host's, and reporting them the same way would send the panel
// looking in the wrong place.
func statusFor(err error) int {
	switch {
	case errors.Is(err, platform.ErrInvalidRequest):
		return http.StatusBadRequest
	case errors.Is(err, platform.ErrUnsupported):
		return http.StatusUnprocessableEntity
	}
	return http.StatusInternalServerError
}
