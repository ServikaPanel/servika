package panelsettings

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"
	"servika/internal/provisioner"
)

const (
	panelCertPath       = "/etc/ssl/servika/panel.crt"
	panelKeyPath        = "/etc/ssl/servika/panel.key"
	panelCertBackupPath = "/etc/ssl/servika/panel.crt.selfsigned-bak"
	panelKeyBackupPath  = "/etc/ssl/servika/panel.key.selfsigned-bak"
	acmeWebroot         = "/var/www/_acme"
)

type Handlers struct {
	DB         *sql.DB
	ServerIPv4 string
}

type statusResponse struct {
	CustomDomain string `json:"custom_domain"`
	SSLStatus    string `json:"ssl_status"`
	SSLError     string `json:"ssl_error,omitempty"`
	SSLExpires   string `json:"ssl_expires,omitempty"`
	ServerIPv4   string `json:"server_ipv4"`
}

type saveRequest struct {
	Domain string `json:"domain"`
}

func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	settings, err := h.readSettings(r)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "panel settings could not be read")
		return
	}
	settings.ServerIPv4 = h.serverIPv4()
	httpx.WriteJSON(w, http.StatusOK, settings)
}

func (h *Handlers) Save(w http.ResponseWriter, r *http.Request) {
	var req saveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if err := provisioner.ValidateDomain(domain); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid domain name")
		return
	}
	serverIP := h.serverIPv4()
	if serverIP == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "server IPv4 address could not be detected")
		return
	}
	ips, err := net.LookupHost(domain)
	if err != nil || !containsIP(ips, serverIP) {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "domain A record must point to this server before certificate issuance")
		return
	}

	sslStatus, sslError, sslExpires := "active", "", ""
	if err := issuePanelCertificate(domain); err != nil {
		sslStatus = "failed"
		sslError = "certificate issuance failed"
		restorePanelSelfSigned()
	} else if expires, ok := certificateExpiry(panelCertPath, panelKeyPath); ok {
		sslExpires = expires.Format("2006-01-02")
	}

	if _, err := h.DB.ExecContext(r.Context(), `UPDATE panel_settings SET custom_domain=?, ssl_status=?, ssl_error=?, ssl_expires=? WHERE id=1`, nullable(domain), sslStatus, nullable(sslError), nullable(sslExpires)); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "panel settings could not be saved")
		return
	}
	response := map[string]any{"ok": true, "custom_domain": domain, "ssl_status": sslStatus}
	if sslStatus != "active" {
		removePortlessPanelVhost()
		response["warning"] = "The domain was saved, but Let's Encrypt certificate issuance failed. The panel remains available with the existing certificate."
	} else if err := writePortlessPanelVhost(domain); err != nil {
		response["warning"] = "The certificate was installed, but portless panel access could not be configured. The panel remains available on port 8443."
	}
	httpx.WriteJSON(w, http.StatusOK, response)
}

func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	restorePanelSelfSigned()
	removePortlessPanelVhost()
	if _, err := h.DB.ExecContext(r.Context(), `UPDATE panel_settings SET custom_domain=NULL, ssl_status='none', ssl_error=NULL, ssl_expires=NULL WHERE id=1`); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "panel settings could not be reset")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handlers) readSettings(r *http.Request) (statusResponse, error) {
	var resp statusResponse
	var domain, sslError, sslExpires sql.NullString
	err := h.DB.QueryRowContext(r.Context(), `SELECT custom_domain, ssl_status, ssl_error, COALESCE(DATE_FORMAT(ssl_expires,'%Y-%m-%d'),'') FROM panel_settings WHERE id=1`).Scan(&domain, &resp.SSLStatus, &sslError, &sslExpires)
	if errors.Is(err, sql.ErrNoRows) {
		return statusResponse{SSLStatus: "none"}, nil
	}
	if err != nil {
		return statusResponse{}, err
	}
	resp.CustomDomain = domain.String
	resp.SSLError = sslError.String
	resp.SSLExpires = sslExpires.String
	return resp, nil
}

func (h *Handlers) serverIPv4() string {
	if h.ServerIPv4 != "" {
		return h.ServerIPv4
	}
	return config.PublicIPv4()
}

func issuePanelCertificate(domain string) error {
	if err := backupPanelSelfSigned(); err != nil {
		return err
	}
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(acmeWebroot, 0o755); err != nil {
		return fmt.Errorf("prepare ACME webroot: %w", err)
	}
	_, _ = exec.Command("restorecon", "-R", acmeWebroot).CombinedOutput()
	// RunACMEIssue also recovers from an invalidContact account lock-out, which otherwise
	// blocks certificate issuance for every domain on the host, including this panel domain.
	if out, err := provisioner.RunACMEIssue("--issue", "--webroot", acmeWebroot, "-d", domain, "--keylength", "2048"); err != nil {
		if !provisioner.IsACMERenewSkip(err) {
			return fmt.Errorf("acme issue failed: %s", strings.TrimSpace(string(out)))
		}
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	install := exec.Command(config.ACMEBin(), "--install-cert", "-d", domain, "--cert-file", panelCertPath, "--key-file", panelKeyPath, "--fullchain-file", panelCertPath, "--reloadcmd", "systemctl reload nginx")
	install.Env = acmeEnv()
	if out, err := install.CombinedOutput(); err != nil {
		return fmt.Errorf("acme install failed: %s", strings.TrimSpace(string(out)))
	}
	if err := os.Chmod(panelKeyPath, 0o600); err != nil {
		return fmt.Errorf("set panel private key permissions: %w", err)
	}
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	if err := os.Chmod(panelCertPath, 0o644); err != nil {
		return fmt.Errorf("set panel certificate permissions: %w", err)
	}
	return nil
}

func acmeEnv() []string {
	return []string{
		"HOME=" + config.ACMEHome(),
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
}

func backupPanelSelfSigned() error {
	if _, err := os.Stat(panelCertBackupPath); os.IsNotExist(err) {
		if err := copyFile(panelCertPath, panelCertBackupPath, 0o644); err != nil {
			return err
		}
	}
	if _, err := os.Stat(panelKeyBackupPath); os.IsNotExist(err) {
		if err := copyFile(panelKeyPath, panelKeyBackupPath, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func restorePanelSelfSigned() {
	if _, err := os.Stat(panelCertBackupPath); err == nil {
		_ = copyFile(panelCertBackupPath, panelCertPath, 0o644)
	}
	if _, err := os.Stat(panelKeyBackupPath); err == nil {
		_ = copyFile(panelKeyBackupPath, panelKeyPath, 0o600)
	}
	_ = exec.Command("systemctl", "reload", "nginx").Run()
}

func copyFile(src, dst string, mode os.FileMode) error {
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read certificate file: %w", err)
	}
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("prepare certificate directory: %w", err)
	}
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if err := os.WriteFile(dst, data, mode); err != nil {
		return fmt.Errorf("write certificate file: %w", err)
	}
	return nil
}

func certificateExpiry(certPath, keyPath string) (time.Time, bool) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil || len(pair.Certificate) == 0 {
		return time.Time{}, false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return time.Time{}, false
	}
	return leaf.NotAfter, true
}

func containsIP(values []string, expected string) bool {
	return slices.Contains(values, expected)
}

func nullable(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
