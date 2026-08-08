package geoip

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"servika/internal/httpx"
	"servika/internal/secret"
)

// Handlers serves the operator's MaxMind credentials and the download control.
type Handlers struct{ DB *sql.DB }

// Status reports the state of the country database.
//
// The license key is NEVER returned, in any shape. Only whether one is stored,
// which is all a screen needs to decide between offering the form and offering
// the controls behind it.
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	status, err := ReadStatus(r.Context(), h.DB)
	if err != nil {
		log.Printf("geoip: read the status: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the country database status could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, status)
}

// SaveCredentials stores the MaxMind account.
//
// Both halves are required together. The endpoint authenticates the account id
// as the user and the key as the password, so storing one without the other
// would leave the panel unable to download while reporting itself configured.
func (h *Handlers) SaveCredentials(w http.ResponseWriter, r *http.Request) {
	var request struct {
		AccountID  string `json:"account_id"`
		LicenseKey string `json:"license_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	accountID := strings.TrimSpace(request.AccountID)
	licenseKey := strings.TrimSpace(request.LicenseKey)

	if accountID == "" && licenseKey == "" {
		// Clearing is a legitimate action: it turns the feature off without
		// touching the country rules already stored, which then render nothing
		// and are reported as unenforced rather than silently dropped.
		if _, err := h.DB.ExecContext(r.Context(),
			`UPDATE panel_settings SET maxmind_account_id='', maxmind_license_key=NULL,
			        geoip_last_error='' WHERE id=1`); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "the credentials could not be cleared")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if accountID == "" || licenseKey == "" {
		httpx.WriteError(w, http.StatusBadRequest, "both the account id and the license key are required")
		return
	}
	if !isAccountID(accountID) {
		httpx.WriteError(w, http.StatusBadRequest, "the account id is a number")
		return
	}
	if strings.ContainsAny(licenseKey, " \t\r\n") {
		httpx.WriteError(w, http.StatusBadRequest, "the license key contains whitespace")
		return
	}

	sealed, err := secret.Encrypt(licenseKey)
	if err != nil {
		log.Printf("geoip: seal the license key: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the credentials could not be stored")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE panel_settings SET maxmind_account_id=?, maxmind_license_key=?, geoip_last_error='' WHERE id=1`,
		accountID, sealed); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the credentials could not be stored")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Update downloads the country database now.
//
// It runs on a context of its own rather than the request's: the download
// outlasts a browser tab, and an operator who navigates away must not leave the
// data half written.
func (h *Handlers) Update(w http.ResponseWriter, r *http.Request) {
	if _, err := Credentials(r.Context(), h.DB); err != nil {
		httpx.WriteJSON(w, http.StatusConflict, map[string]string{
			"error": "no MaxMind account is configured", "reason": ReasonUnavailable})
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 20*time.Minute)
	defer cancel()

	if err := Download(ctx, h.DB); err != nil {
		if errors.Is(err, ErrNoCredentials) {
			httpx.WriteJSON(w, http.StatusConflict, map[string]string{
				"error": "no MaxMind account is configured", "reason": ReasonUnavailable})
			return
		}
		// The reason is already stored on panel_settings, so the screen shows it
		// with the rest of the state instead of only in this one response.
		log.Printf("geoip: download the country database: %v", err)
		httpx.WriteError(w, http.StatusBadGateway, "the country database could not be downloaded")
		return
	}
	status, err := ReadStatus(ctx, h.DB)
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, status)
}

// isAccountID reports whether the value is shaped like a MaxMind account id,
// which is a decimal number.
func isAccountID(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}
