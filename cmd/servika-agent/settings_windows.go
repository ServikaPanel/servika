//go:build windows

package main

// The local panel's settings endpoint: changing the admin password.
//
// The new hash is written to the settings file, and the login handler reads the
// hash from disk on EVERY attempt, so the change takes effect with no service
// restart.

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	"servika/internal/platform"
)

const (
	minPanelPassword = 8
	maxPanelPassword = 200
)

// registerSettingsRoutes wires the settings endpoints.
func registerSettingsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/local/change-password", changing("change-password", changePasswordEndpoint))
}

// changePasswordEndpoint answers POST /api/local/change-password
// {old_password, new_password}.
func changePasswordEndpoint(w http.ResponseWriter, r *http.Request) {
	if !wantMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if !readRequest(w, r, &request) {
		return
	}
	if n := len(request.NewPassword); n < minPanelPassword || n > maxPanelPassword {
		writeError(w, r, http.StatusUnprocessableEntity,
			fmt.Errorf("the new password must be %d to %d characters: %w", minPanelPassword, maxPanelPassword, platform.ErrInvalidRequest))
		return
	}
	// The file is read DIRECTLY rather than through loadSettings, because
	// loadSettings applies the environment overrides and writing those back
	// would corrupt the installed configuration.
	current, err := readSettings(dataDir)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, err)
		return
	}
	if !currentPasswordHolds(current.PanelPasswordHash, request.OldPassword) {
		// A FIXED delay, the same as a failed login, so a brute force is slowed
		// the same way here.
		time.Sleep(failedLoginDelay)
		// 422 rather than 401 ON PURPOSE: the interface treats a 401 outside the
		// login endpoint as "the session ended" and drops the operator back to
		// the login page, so a mistyped current password would quietly log them
		// out. ErrInvalidRequest is deliberately not wrapped either, so this
		// stays a 422 rather than turning into a 400.
		writeError(w, r, http.StatusUnprocessableEntity, fmt.Errorf("the current password is wrong"))
		return
	}
	if current.PanelPasswordHash, err = hashPanelPassword(request.NewPassword); err != nil {
		writeError(w, r, http.StatusInternalServerError, err)
		return
	}
	if err := saveSettingsAtomically(current); err != nil {
		writeError(w, r, http.StatusInternalServerError, err)
		return
	}
	log.Printf("local panel: the admin password was changed (%s)", r.RemoteAddr)
	panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// currentPasswordHolds verifies the password already in force.
func currentPasswordHolds(hash, password string) bool {
	if hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// saveSettingsAtomically writes through a temporary file and a rename.
//
// A plain write interrupted part way would corrupt the settings file, taking
// the REGISTRATION TOKEN with it, and the agent would then refuse to start with
// "there is no token". The temporary file inherits the directory's ACL.
func saveSettingsAtomically(current settings) error {
	temp := settingsPath(dataDir) + ".new"
	b, err := marshalSettings(current)
	if err != nil {
		return err
	}
	if err := os.WriteFile(temp, b, 0o600); err != nil {
		return fmt.Errorf("the settings could not be written: %w", err)
	}
	if err := os.Rename(temp, settingsPath(dataDir)); err != nil {
		_ = os.Remove(temp)
		return fmt.Errorf("the settings could not be replaced: %w", err)
	}
	return nil
}
