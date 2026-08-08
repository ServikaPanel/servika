package subdomain

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"servika/internal/httpx"
	"servika/internal/provisioner"

	"github.com/go-chi/chi/v5"
)

var managedUserPattern = regexp.MustCompile(`^c_[a-z0-9_]{1,26}$`)

func sslDirectory(systemUser string) string {
	return filepath.Join("/home", systemUser, "ssl")
}

func certificatePaths(systemUser, fqdn string) (string, string) {
	directory := sslDirectory(systemUser)
	return filepath.Join(directory, fqdn+".crt"), filepath.Join(directory, fqdn+".key")
}

func (h *Handlers) subInfo(r *http.Request, domainID int64, parentDomain string) (int64, string, string, string, bool) {
	subdomainID, err := strconv.ParseInt(chi.URLParam(r, "sid"), 10, 64)
	if err != nil || subdomainID <= 0 {
		return 0, "", "", "", false
	}
	var name, fqdn, phpVersion string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT subdomain, fqdn, COALESCE(php_version,'8.3') FROM subdomains WHERE id=? AND domain_id=?`,
		subdomainID, domainID).Scan(&name, &fqdn, &phpVersion); err != nil {
		return 0, "", "", "", false
	}
	if !subdomainPattern.MatchString(name) || fqdn != name+"."+parentDomain || provisioner.ValidateDomain(fqdn) != nil {
		return 0, "", "", "", false
	}
	return subdomainID, name, fqdn, phpVersion, true
}

func validSSLType(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "self-signed", true
	}
	return value, value == "self-signed" || value == "letsencrypt"
}

// SSLStatus reports whether a subdomain has certificate files and an HTTPS vhost.
func (h *Handlers) SSLStatus(w http.ResponseWriter, r *http.Request) {
	domainID, systemUser, parentDomain, _, _, ok := h.parent(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !managedUserPattern.MatchString(systemUser) {
		httpx.WriteError(w, http.StatusInternalServerError, "invalid domain configuration")
		return
	}
	_, name, fqdn, _, ok := h.subInfo(r, domainID, parentDomain)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "subdomain not found")
		return
	}
	// Through the shared helper so this endpoint and the lists cannot disagree
	// about whether the same subdomain is serving HTTPS.
	active, source := sslState(systemUser, name, fqdn)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"active": active, "source": source})
}

// SSLIssue installs a self-signed or Let's Encrypt certificate for a subdomain.
func (h *Handlers) SSLIssue(w http.ResponseWriter, r *http.Request) {
	domainID, systemUser, parentDomain, _, demo, ok := h.parent(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "not available for demo subscriptions")
		return
	}
	if !managedUserPattern.MatchString(systemUser) {
		httpx.WriteError(w, http.StatusInternalServerError, "invalid domain configuration")
		return
	}
	subdomainID, name, fqdn, phpVersion, ok := h.subInfo(r, domainID, parentDomain)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "subdomain not found")
		return
	}
	var request struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	certificateType, valid := validSSLType(request.Type)
	if !valid {
		httpx.WriteError(w, http.StatusBadRequest, "type must be self-signed or letsencrypt")
		return
	}
	socket, err := provisioner.PHPSocketFor(systemUser, phpVersion)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "PHP version is not installed on the server")
		return
	}
	certPath, keyPath := certificatePaths(systemUser, fqdn)
	if err := os.MkdirAll(sslDirectory(systemUser), 0o750); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not prepare certificate directory")
		return
	}

	if certificateType == "letsencrypt" {
		err = issueLetsEncrypt(fqdn, certPath, keyPath)
	} else {
		err = issueSelfSigned(fqdn, certPath, keyPath)
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "SSL installation failed")
		return
	}
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	_ = os.Chmod(keyPath, 0o640)
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_ = exec.Command("chown", "-R", systemUser+":"+systemUser, sslDirectory(systemUser)).Run()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_ = exec.Command("restorecon", "-R", sslDirectory(systemUser)).Run()

	protected := provisioner.ProtectedBlocks(h.DB, domainID, subdomainID, socket)
	web := loadWebRender(r.Context(), h.DB, domainID, subdomainID, fqdn, true)
	config := vhostSSL(fqdn, docrootOf(systemUser, fqdn), socket, certPath, keyPath, protected, web)
	if err := applyVhost(confPath(systemUser, name), config); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "SSL installation failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "fqdn": fqdn, "type": certificateType})
}

// SSLRemove removes a subdomain certificate and restores its HTTP-only vhost.
func (h *Handlers) SSLRemove(w http.ResponseWriter, r *http.Request) {
	domainID, systemUser, parentDomain, _, demo, ok := h.parent(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "not available for demo subscriptions")
		return
	}
	if !managedUserPattern.MatchString(systemUser) {
		httpx.WriteError(w, http.StatusInternalServerError, "invalid domain configuration")
		return
	}
	subdomainID, name, fqdn, phpVersion, ok := h.subInfo(r, domainID, parentDomain)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "subdomain not found")
		return
	}
	socket, err := provisioner.PHPSocketFor(systemUser, phpVersion)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "PHP version is not installed on the server")
		return
	}
	protected := provisioner.ProtectedBlocks(h.DB, domainID, subdomainID, socket)
	web := loadWebRender(r.Context(), h.DB, domainID, subdomainID, fqdn, false)
	if err := applyVhost(confPath(systemUser, name), vhost(fqdn, docrootOf(systemUser, fqdn), socket, protected, web)); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not disable SSL")
		return
	}
	certPath, keyPath := certificatePaths(systemUser, fqdn)
	_ = os.Remove(certPath)
	_ = os.Remove(keyPath)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func issueSelfSigned(fqdn, certPath, keyPath string) error {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	return exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365",
		"-keyout", keyPath, "-out", certPath, "-subj", "/CN="+fqdn, "-addext", "subjectAltName=DNS:"+fqdn).Run()
}

func issueLetsEncrypt(fqdn, certPath, keyPath string) error {
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll("/var/www/_acme", 0o755); err != nil {
		return err
	}
	_ = exec.Command("restorecon", "-R", "/var/www/_acme").Run()
	// RunACMEIssue also recovers from an invalidContact account lock-out and sets HOME so
	// acme.sh finds its own store. RENEW_SKIP means the store already holds a valid
	// certificate, so installation must continue instead of reporting a failure; without
	// this a second issuance for the same subdomain fails with a good certificate on disk.
	if _, err := provisioner.RunACMEIssue("--issue", "--webroot", "/var/www/_acme",
		"-d", fqdn, "--keylength", "ec-256"); err != nil && !provisioner.IsACMERenewSkip(err) {
		return err
	}
	return provisioner.RunACMECommand("--install-cert", "-d", fqdn, "--ecc",
		"--key-file", keyPath, "--fullchain-file", certPath)
}

func applyVhost(path, config string) error {
	// #nosec G703 G304 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	previous, readErr := os.ReadFile(path)
	// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		return err
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_ = exec.Command("restorecon", path).Run()
	rollback := func() {
		if readErr == nil {
			// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
			_ = os.WriteFile(path, previous, 0o644)
		} else {
			// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
			_ = os.Remove(path)
		}
	}
	if err := exec.Command("nginx", "-t").Run(); err != nil {
		rollback()
		return err
	}
	if err := exec.Command("systemctl", "reload", "nginx").Run(); err != nil {
		rollback()
		_ = exec.Command("systemctl", "reload", "nginx").Run()
		return err
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// vhostSSL renders the HTTPS server block. protected carries the auth_basic blocks
// for this subdomain's protected directories and is empty when none exist. The acme
// challenge location stays exempt so certificate issuance and renewal keep working.
func vhostSSL(fqdn, docroot, socket, certPath, keyPath, protected string, web webRender) string {
	return fmt.Sprintf(`server {
    listen 80;
`+provisioner.ListenIPv6("80")+`    server_name %[1]s;
    location /.well-known/acme-challenge/ { auth_basic off; root /var/www/_acme; try_files $uri =404; }
    location / { return 301 https://$host$request_uri; }
}
server {
    listen 443 ssl;
`+provisioner.ListenIPv6("443 ssl")+`    http2 on;
    server_name %[1]s;

    ssl_certificate     %[3]s;
    ssl_certificate_key %[4]s;
    ssl_protocols TLSv1.2 TLSv1.3;

    root %[2]s;
    index index.php index.html index.htm;
    access_log /var/log/nginx/%[1]s.access.log;
    error_log  /var/log/nginx/%[1]s.error.log warn;
%[6]s
%[5]s
    location /.well-known/acme-challenge/ { auth_basic off; root /var/www/_acme; try_files $uri =404; }

%[7]s
%[8]s
    location ~ /\.(?!well-known) { deny all; }

%[9]s}
`, fqdn, docroot, certPath, keyPath, protected, web.Headers,
		backendBlock(socket, web, true), web.BrowserCache, web.Extra)
}
