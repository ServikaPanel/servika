// Package nginxset manages per-domain nginx security headers, caching, and custom directives.
package nginxset

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"servika/internal/httpx"
	"servika/internal/middleware"
	"servika/internal/provisioner"

	"github.com/go-chi/chi/v5"
)

// Settings contains per-domain nginx configuration.
type Settings struct {
	HdrXContentType bool `json:"hdr_x_content_type"`
	HdrXXSS         bool `json:"hdr_x_xss"`
	HdrReferrer     bool `json:"hdr_referrer"`
	HdrPermissions  bool `json:"hdr_permissions"`
	HdrCSPUpgrade   bool `json:"hdr_csp_upgrade"`
	HdrHSTS         bool `json:"hdr_hsts"`
	HSTSMaxAge      int  `json:"hsts_max_age"`
	HSTSSubdomains  bool `json:"hsts_subdomains"`
	HSTSPreload     bool `json:"hsts_preload"`

	// Performance caching.
	FastCgiCache        bool `json:"fastcgi_cache"`
	FastCgiCacheMinutes int  `json:"fastcgi_cache_minutes"`
	BrowserCache        bool `json:"browser_cache"`
	BrowserCacheDays    int  `json:"browser_cache_days"`

	ExtraDirectives string `json:"extra_directives"`

	// ClientMaxBody is the plan's request-body ceiling as a raw nginx size
	// string ("8192m"), empty when the plan states none.
	//
	// It is an ENTITLEMENT, not a setting: it is served so the screen can show
	// what the plan allows, and the save path overwrites whatever arrives in it
	// with the value already stored. It lived inside ExtraDirectives before,
	// which is the column the customer's own text replaces wholesale, so the
	// tier's limit held only until somebody sent one request.
	ClientMaxBody string `json:"client_max_body"`
}

// Defaults returns the default nginx settings.
func Defaults() Settings {
	return Settings{
		HdrXContentType: true, HdrXXSS: true, HdrReferrer: true,
		HdrPermissions: true, HdrCSPUpgrade: true, HdrHSTS: true,
		HSTSMaxAge: 31536000, HSTSSubdomains: true, HSTSPreload: false,
		FastCgiCache: false, FastCgiCacheMinutes: 60,
		BrowserCache: true, BrowserCacheDays: 30,
		ExtraDirectives: "",
		ClientMaxBody:   "",
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Get returns nginx settings for a domain.
func Get(ctx context.Context, db *sql.DB, domainID, subdomainID int64) (Settings, error) {
	s := Defaults()
	var b1, b2, b3, b4, b5, b6, b7, b8, bFC, bBC int
	err := db.QueryRowContext(ctx,
		`SELECT hdr_x_content_type, hdr_x_xss, hdr_referrer, hdr_permissions,
		        hdr_csp_upgrade, hdr_hsts, hsts_max_age, hsts_subdomains, hsts_preload,
		        extra_directives, fastcgi_cache, fastcgi_cache_minutes,
		        browser_cache, browser_cache_days, client_max_body
		 FROM nginx_settings WHERE domain_id=? AND subdomain_id=?`, domainID, subdomainID).
		Scan(&b1, &b2, &b3, &b4, &b5, &b6, &s.HSTSMaxAge, &b7, &b8,
			&s.ExtraDirectives, &bFC, &s.FastCgiCacheMinutes, &bBC, &s.BrowserCacheDays,
			&s.ClientMaxBody)
	if errors.Is(err, sql.ErrNoRows) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	s.HdrXContentType = b1 == 1
	s.HdrXXSS = b2 == 1
	s.HdrReferrer = b3 == 1
	s.HdrPermissions = b4 == 1
	s.HdrCSPUpgrade = b5 == 1
	s.HdrHSTS = b6 == 1
	s.HSTSSubdomains = b7 == 1
	s.HSTSPreload = b8 == 1
	s.FastCgiCache = bFC == 1
	s.BrowserCache = bBC == 1
	return s, nil
}

// GetScoped returns the settings a scope renders with. A subdomain that has never
// been configured has no row of its own, and bare defaults would drop it below the
// parent: the plan's client_max_body_size is seeded into the DOMAIN row's
// extra_directives at domain creation, so a subdomain falling back to Defaults()
// would reject uploads the parent accepts. Inherit the domain row until the
// subdomain is saved for the first time.
func GetScoped(ctx context.Context, db *sql.DB, domainID, subdomainID int64) (Settings, error) {
	if subdomainID <= 0 {
		return Get(ctx, db, domainID, 0)
	}
	var exists int
	err := db.QueryRowContext(ctx,
		`SELECT 1 FROM nginx_settings WHERE domain_id=? AND subdomain_id=?`, domainID, subdomainID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return Get(ctx, db, domainID, 0)
	}
	if err != nil {
		return Defaults(), err
	}
	return Get(ctx, db, domainID, subdomainID)
}

// Save persists nginx settings for a domain (subdomainID 0) or one of its subdomains.
func Save(ctx context.Context, db *sql.DB, domainID, subdomainID int64, s Settings) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO nginx_settings(domain_id, subdomain_id, hdr_x_content_type, hdr_x_xss, hdr_referrer,
		    hdr_permissions, hdr_csp_upgrade, hdr_hsts, hsts_max_age, hsts_subdomains, hsts_preload,
		    extra_directives, fastcgi_cache, fastcgi_cache_minutes, browser_cache, browser_cache_days,
		    client_max_body)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE
		    hdr_x_content_type=VALUES(hdr_x_content_type),
		    hdr_x_xss=VALUES(hdr_x_xss),
		    hdr_referrer=VALUES(hdr_referrer),
		    hdr_permissions=VALUES(hdr_permissions),
		    hdr_csp_upgrade=VALUES(hdr_csp_upgrade),
		    hdr_hsts=VALUES(hdr_hsts),
		    hsts_max_age=VALUES(hsts_max_age),
		    hsts_subdomains=VALUES(hsts_subdomains),
		    hsts_preload=VALUES(hsts_preload),
		    extra_directives=VALUES(extra_directives),
		    fastcgi_cache=VALUES(fastcgi_cache),
		    fastcgi_cache_minutes=VALUES(fastcgi_cache_minutes),
		    browser_cache=VALUES(browser_cache),
		    browser_cache_days=VALUES(browser_cache_days),
		    client_max_body=VALUES(client_max_body)`,
		domainID, subdomainID, b2i(s.HdrXContentType), b2i(s.HdrXXSS), b2i(s.HdrReferrer),
		b2i(s.HdrPermissions), b2i(s.HdrCSPUpgrade), b2i(s.HdrHSTS),
		s.HSTSMaxAge, b2i(s.HSTSSubdomains), b2i(s.HSTSPreload),
		s.ExtraDirectives, b2i(s.FastCgiCache), s.FastCgiCacheMinutes,
		b2i(s.BrowserCache), s.BrowserCacheDays, s.ClientMaxBody)
	return err
}

// Handlers provides HTTP handlers for nginx settings.
type Handlers struct {
	DB *sql.DB
	// RerenderSubdomain publishes a subdomain's vhost after its settings change.
	// It is injected rather than called directly because internal/subdomain imports
	// this package for the settings type, so the reverse edge would be a cycle.
	RerenderSubdomain func(db *sql.DB, subdomainID int64) error
}

type customVhostResponse struct {
	Enabled    bool   `json:"enabled"`
	Content    string `json:"content"`
	DomainName string `json:"domain_name"`
}

type setCustomVhostRequest struct {
	Enabled bool   `json:"enabled"`
	Content string `json:"content"`
}

// ShowCustomVhost returns the raw custom vhost settings for a domain.
func (h *Handlers) ShowCustomVhost(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var domainName string
	var enabled int
	var content string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, COALESCE(custom_vhost_enabled,0), COALESCE(custom_vhost_content,'') FROM domains WHERE id=?`, id).
		Scan(&domainName, &enabled, &content)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load custom vhost")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, customVhostResponse{
		Enabled:    enabled == 1,
		Content:    content,
		DomainName: domainName,
	})
}

// SaveCustomVhost persists and applies the raw custom vhost for a domain.
func (h *Handlers) SaveCustomVhost(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var req setCustomVhostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var previousEnabled int
	var previousContent, domainName, systemUser, phpVersion string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, system_user, php_version, COALESCE(custom_vhost_enabled,0), COALESCE(custom_vhost_content,'') FROM domains WHERE id=?`, id).
		Scan(&domainName, &systemUser, &phpVersion, &previousEnabled, &previousContent)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load domain")
		return
	}

	if req.Enabled {
		if err := provisioner.ValidateCustomVhost(req.Content); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid custom vhost: "+err.Error())
			return
		}
	}

	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET custom_vhost_enabled=?, custom_vhost_content=? WHERE id=?`,
		b2i(req.Enabled), req.Content, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to save custom vhost")
		return
	}

	socket, err := provisioner.PHPSocketFor(systemUser, phpVersion)
	if err != nil {
		socket = "/run/php-fpm/" + systemUser + ".sock"
	}
	if err := provisioner.ApplyVhostForDomain(h.DB, id, socket, phpVersion); err != nil {
		if _, rollbackErr := h.DB.ExecContext(r.Context(),
			`UPDATE domains SET custom_vhost_enabled=?, custom_vhost_content=? WHERE id=?`,
			previousEnabled, previousContent, id); rollbackErr != nil {
			log.Printf("custom vhost rollback failed for domain %d: %v", id, rollbackErr)
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to apply custom vhost")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, customVhostResponse{
		Enabled:    req.Enabled,
		Content:    req.Content,
		DomainName: domainName,
	})
}

// scope resolves the target of a settings request from the optional {sid} route
// param, so the same handlers serve a domain and any of its subdomains. The
// subdomain lookup is bound to the URL domain, so a tenant cannot reach another
// domain's settings by guessing a subdomain id.
func (h *Handlers) scope(r *http.Request) (domainID, subdomainID int64, displayName string, ok bool) {
	domainID, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name FROM domains WHERE id=?`, domainID).Scan(&displayName); err != nil {
		return domainID, 0, "", false
	}
	sid, _ := strconv.ParseInt(chi.URLParam(r, "sid"), 10, 64)
	if sid <= 0 {
		return domainID, 0, displayName, true
	}
	var fqdn string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT fqdn FROM subdomains WHERE id=? AND domain_id=?`, sid, domainID).Scan(&fqdn); err != nil {
		return domainID, 0, "", false
	}
	return domainID, sid, fqdn, true
}

// Show returns nginx settings for a domain.
func (h *Handlers) Show(w http.ResponseWriter, r *http.Request) {
	id, sid, displayName, ok := h.scope(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	s, err := GetScoped(r.Context(), h.DB, id, sid)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load nginx settings")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"domain_name":  displayName,
		"subdomain_id": sid,
		"settings":     s,
	})
}

// Save persists and applies nginx settings for a domain.
func (h *Handlers) Save(w http.ResponseWriter, r *http.Request) {
	id, sid, _, ok := h.scope(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	// This write turns the security headers off, changes the FastCGI cache and
	// injects free-text extra_directives before re-rendering the live vhost.
	// CustomerScope enforces ownership and suspension, never is_demo.
	if !middleware.EnforceDomainNotDemo(w, r, id, "the nginx settings") {
		return
	}
	var req struct {
		Settings Settings `json:"settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var phpVersion, systemUser string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT php_version, system_user FROM domains WHERE id=?`, id).
		Scan(&phpVersion, &systemUser); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	// The plan's request-body ceiling is an entitlement, not a setting. It is
	// re-read from the scope's own state and written back, so the customer's
	// payload can neither raise it nor drop it.
	//
	// Reading it here rather than leaving the column out of the write is
	// deliberate: GetScoped inherits the domain's value only while a subdomain
	// has NO row of its own, so the FIRST save of a subdomain would otherwise
	// insert the column's empty default and silently lose the ceiling it was
	// inheriting.
	current, err := GetScoped(r.Context(), h.DB, id, sid)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load nginx settings")
		return
	}
	req.Settings.ClientMaxBody = current.ClientMaxBody

	if directive := provisioner.DangerousNginxDirective(req.Settings.ExtraDirectives); directive != "" {
		httpx.WriteError(w, http.StatusBadRequest, "nginx directive is not allowed")
		return
	}
	if err := provisioner.ValidateNginxDirectives(req.Settings.ExtraDirectives); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid nginx directives")
		return
	}
	// nginx refuses to load a config naming an undefined keys_zone, so the shared
	// zone has to exist before a vhost referencing it is written.
	if req.Settings.FastCgiCache {
		if err := provisioner.EnsureCacheZone(); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to prepare the cache zone")
			return
		}
	}
	if err := Save(r.Context(), h.DB, id, sid, req.Settings); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to save nginx settings")
		return
	}
	if sid > 0 {
		if h.RerenderSubdomain == nil {
			httpx.WriteError(w, http.StatusInternalServerError, "subdomain rendering is not wired")
			return
		}
		if err := h.RerenderSubdomain(h.DB, sid); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to apply nginx virtual host")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	socket, err := provisioner.PHPSocketFor(systemUser, phpVersion)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to resolve PHP socket")
		return
	}
	if err := provisioner.ApplyVhostForDomain(h.DB, id, socket, phpVersion); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to apply nginx virtual host")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
