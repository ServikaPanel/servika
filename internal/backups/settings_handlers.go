// System-wide backup settings API (all AdminOnly; wired in main.go):
//
//	GET  /api/v1/admin/backups/settings       -> current settings + live disk measurements
//	PUT  /api/v1/admin/backups/settings       -> save (empty remote_password keeps the stored one)
//	POST /api/v1/admin/backups/settings/test  -> connection test without saving
package backups

import (
	"encoding/json"
	"net/http"
	"strings"

	"servika/internal/httpx"
)

// validGlobalRemoteType restricts the system-wide destination to the lftp
// transports, because the date-subdirectory layout is expressed as a remote
// directory path, which object storage does not have.
func validGlobalRemoteType(t string) bool { return t == "ftp" || t == "sftp" }

// BackupSettingsGet returns the current settings plus the live free space and
// store usage. The password is write-only and never returned.
func (h *Handlers) BackupSettingsGet(w http.ResponseWriter, r *http.Request) {
	s := readBackupSettings(r.Context(), h.DB)
	s.RemotePassword = ""
	s.RemoteHostKey = ""
	if free, err := diskFreeGB(backupRoot()); err == nil {
		s.FreeGB = free
	}
	s.StoreGB = storeUsageGB()
	httpx.WriteJSON(w, http.StatusOK, s)
}

// validateBackupSettings enforces the input bounds and returns an error message,
// or "" when the input is valid.
func validateBackupSettings(s *BackupSettings) string {
	if s.MinFreeGB < 0 || s.MinFreeGB > 10000 {
		return "min_free_gb must be between 0 and 10000"
	}
	if s.MaxStoreGB < 0 || s.MaxStoreGB > 1000000 {
		return "max_store_gb must be between 0 and 1000000"
	}
	if !s.RemoteEnabled {
		return ""
	}
	if !validGlobalRemoteType(s.RemoteType) {
		return "remote_type must be ftp or sftp"
	}
	if strings.TrimSpace(s.RemoteHost) == "" {
		return "remote_host cannot be empty"
	}
	if s.RemotePort < 1 || s.RemotePort > 65535 {
		return "remote_port must be between 1 and 65535"
	}
	if strings.TrimSpace(s.RemoteUsername) == "" {
		return "remote_username cannot be empty"
	}
	// A control character is a command-line injection risk for lftp/ssh; refuse it
	// on the way in, exactly as the per-domain destination does.
	for _, v := range []string{s.RemoteHost, s.RemoteUsername, s.RemotePassword, s.RemoteDir} {
		if strings.ContainsAny(v, "\r\n\x00") {
			return "the fields cannot contain a line break or control character"
		}
	}
	return ""
}

// applyRemoteDefaults fills the type, port and directory defaults so a partial
// form body is stored consistently.
func applyRemoteDefaults(s *BackupSettings) {
	if s.RemoteType == "" {
		s.RemoteType = "sftp"
	}
	if s.RemotePort == 0 {
		if s.RemoteType == "ftp" {
			s.RemotePort = 21
		} else {
			s.RemotePort = 22
		}
	}
	if strings.TrimSpace(s.RemoteDir) == "" {
		s.RemoteDir = "/"
	}
}

// BackupSettingsSet saves the settings. An empty remote_password keeps the
// stored one.
func (h *Handlers) BackupSettingsSet(w http.ResponseWriter, r *http.Request) {
	var s BackupSettings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&s); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	applyRemoteDefaults(&s)
	if msg := validateBackupSettings(&s); msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	if err := writeBackupSettings(r.Context(), h.DB, &s); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the settings could not be saved")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// BackupSettingsTest tries the remote destination without saving. An empty
// remote_password uses the stored one, because the UI never reads the password
// back and must not have to retype it to test.
func (h *Handlers) BackupSettingsTest(w http.ResponseWriter, r *http.Request) {
	var s BackupSettings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&s); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	s.RemoteEnabled = true // a test always validates the remote fields
	applyRemoteDefaults(&s)
	if s.RemotePassword == "" {
		s.RemotePassword = readBackupSettings(r.Context(), h.DB).RemotePassword
	}
	if msg := validateBackupSettings(&s); msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	// Pin the host key on a successful scan, so a later upload verifies against it.
	if err := ensureGlobalHostKey(r.Context(), h.DB, &s); err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := testConnection(r.Context(), h.DB, s.destination()); err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
