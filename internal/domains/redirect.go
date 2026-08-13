package domains

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"servika/internal/httpx"
	"servika/internal/provisioner"

	"github.com/go-chi/chi/v5"
)

type domainRedirect struct {
	TargetURL  string `json:"target_url"`
	StatusCode int    `json:"status_code"`
}

func (h *Handlers) RedirectStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var redirect domainRedirect
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT target_url, status_code FROM domain_redirects WHERE domain_id=?`, id).
		Scan(&redirect.TargetURL, &redirect.StatusCode)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "redirect settings could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"active": true, "target_url": redirect.TargetURL, "status_code": redirect.StatusCode})
}

func (h *Handlers) SetRedirect(w http.ResponseWriter, r *http.Request) {
	id, systemUser, phpVersion, demo, ok := h.redirectDomainInfo(w, r)
	if !ok {
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "redirects cannot be changed on demo subscriptions")
		return
	}
	var req domainRedirect
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	targetURL, err := cleanRedirectTarget(req.TargetURL)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid target URL")
		return
	}
	if req.StatusCode != 301 && req.StatusCode != 302 {
		httpx.WriteError(w, http.StatusBadRequest, "status_code must be 301 or 302")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO domain_redirects(domain_id, target_url, status_code) VALUES(?,?,?)
		 ON DUPLICATE KEY UPDATE target_url=VALUES(target_url), status_code=VALUES(status_code)`,
		id, targetURL, req.StatusCode); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "redirect settings could not be saved")
		return
	}
	if err := h.applyRedirectVhost(id, systemUser, phpVersion); err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("redirect vhost render warn (domain_id=%d): %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "virtual host update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handlers) DeleteRedirect(w http.ResponseWriter, r *http.Request) {
	id, systemUser, phpVersion, demo, ok := h.redirectDomainInfo(w, r)
	if !ok {
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "redirects cannot be changed on demo subscriptions")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM domain_redirects WHERE domain_id=?`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "redirect settings could not be deleted")
		return
	}
	if err := h.applyRedirectVhost(id, systemUser, phpVersion); err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("redirect vhost render warn (domain_id=%d): %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "virtual host update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handlers) redirectDomainInfo(w http.ResponseWriter, r *http.Request) (int64, string, string, bool, bool) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var systemUser, phpVersion string
	var demo int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, COALESCE(php_version,'8.3'), COALESCE(is_demo,0) FROM domains WHERE id=?`, id).
		Scan(&systemUser, &phpVersion, &demo)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return 0, "", "", false, false
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return 0, "", "", false, false
	}
	return id, systemUser, phpVersion, demo == 1, true
}

func (h *Handlers) applyRedirectVhost(id int64, systemUser, phpVersion string) error {
	socket, err := provisioner.PHPSocketFor(systemUser, phpVersion)
	if err != nil {
		socket = "/run/php-fpm/" + systemUser + ".sock"
	}
	return provisioner.ApplyVhostForDomain(h.DB, id, socket, phpVersion)
}

func cleanRedirectTarget(raw string) (string, error) {
	target := strings.TrimSpace(raw)
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("invalid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("unsupported URL scheme")
	}
	if strings.ContainsAny(target, "\r\n\t ;{}\\\"") {
		return "", errors.New("unsafe URL")
	}
	return target, nil
}

// wwwRedirectModes are the accepted values of domains.www_redirect.
var wwwRedirectModes = map[string]bool{"off": true, "to_www": true, "to_apex": true}

// WWWRedirectStatus — GET /domains/{id}/www-redirect.
func (h *Handlers) WWWRedirectStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var mode, domainName, certPath, keyPath string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(www_redirect,'off'), domain_name, COALESCE(cert_path,''), COALESCE(key_path,'')
		   FROM domains WHERE id=?`, id).
		Scan(&mode, &domainName, &certPath, &keyPath)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "redirect settings could not be read")
		return
	}
	// The stored mode is not the mode in force. It is vetted against the
	// certificate once, when it is stored, and SSL installation is asynchronous,
	// so a redirect set during domain creation was checked when cert_path was
	// still empty. Every later render asks again through
	// withCertifiableCanonicalRedirect and silently drops it when the certificate
	// that eventually arrived does not name the target. Reporting only the stored
	// value showed the redirect as active on a site where nobody was redirected.
	reason := provisioner.CanonicalRedirectDropReasonFor(mode, domainName, certPath, keyPath)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"mode":  mode,
		"modes": []string{"off", "to_www", "to_apex"},
		// Reported so the page can explain why to_www is refused before it is tried.
		"www_resolves_to_apex": provisioner.WWWResolvesToApex(domainName),
		"applied":              mode != "off" && reason == "",
		"reason":               reason,
	})
}

// SetWWWRedirect — PUT /domains/{id}/www-redirect makes one hostname canonical and
// answers the other with a 301.
func (h *Handlers) SetWWWRedirect(w http.ResponseWriter, r *http.Request) {
	id, systemUser, phpVersion, demo, ok := h.redirectDomainInfo(w, r)
	if !ok {
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "redirects cannot be changed on demo subscriptions")
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !wwwRedirectModes[req.Mode] {
		httpx.WriteError(w, http.StatusBadRequest, "mode must be off, to_www or to_apex")
		return
	}

	var domainName, certPath, keyPath string
	var parent sql.NullInt64
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, COALESCE(cert_path,''), COALESCE(key_path,''), parent_domain_id FROM domains WHERE id=?`, id).
		Scan(&domainName, &certPath, &keyPath, &parent); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	// Only a root domain has an apex/www pair of its own; an addon or parked domain
	// is rendered from its parent's vhost path.
	if parent.Valid {
		httpx.WriteError(w, http.StatusBadRequest, "only a root domain has a canonical hostname setting")
		return
	}
	if strings.HasPrefix(strings.ToLower(domainName), "www.") && req.Mode != "off" {
		httpx.WriteError(w, http.StatusBadRequest, "the domain is already a www hostname")
		return
	}

	if err := h.checkCanonicalTargetReachable(req.Mode, domainName, certPath, keyPath); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET www_redirect=? WHERE id=?`, req.Mode, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "redirect settings could not be saved")
		return
	}
	if err := h.applyRedirectVhost(id, systemUser, phpVersion); err != nil {
		// Roll the stored value back so the record never claims a redirect nginx refused.
		if _, rollbackErr := h.DB.ExecContext(r.Context(),
			`UPDATE domains SET www_redirect='off' WHERE id=?`, id); rollbackErr != nil {
			// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
			log.Printf("www redirect rollback failed (domain_id=%d): %v", id, rollbackErr)
		}
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("www redirect vhost render warn (domain_id=%d): %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "virtual host update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": req.Mode})
}

// checkCanonicalTargetReachable refuses a redirect that would take the site down.
// Sending every visitor to a hostname DNS does not point at this server, or to one
// the certificate does not name, replaces a working site with an error page, so
// both are checked before the setting is stored rather than discovered afterwards.
func (h *Handlers) checkCanonicalTargetReachable(mode, domainName, certPath, keyPath string) error {
	if mode == "off" {
		return nil
	}
	target := domainName
	if mode == "to_www" {
		target = "www." + domainName
		if !provisioner.WWWResolvesToApex(domainName) {
			return errors.New("www." + domainName + " does not resolve to this server; point it here first")
		}
	}
	if certPath != "" && keyPath != "" && !provisioner.CertificateCoversHost(certPath, keyPath, target) {
		return errors.New("the installed certificate does not cover " + target + "; reissue it first")
	}
	return nil
}
