package subdomain

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"servika/internal/httpx"
	"servika/internal/nginxset"
	"servika/internal/phpdefaults"
	"servika/internal/provisioner"

	"github.com/go-chi/chi/v5"
)

// webRender carries everything the two vhost renderers need from nginx_settings,
// already turned into the nginx fragments they splice in. Building the fragments here
// keeps the renderers free of settings logic and keeps a subdomain byte-identical to
// the domain vhost for the parts they share.
type webRender struct {
	Headers      string // add_header block, already indented
	SkipCacheMap string // set $skip_cache rules, empty when FastCGI caching is off
	FastCgiCache string // fastcgi_cache_* directives inside the php location
	BrowserCache string // static-asset location block, empty when browser caching is off
	Extra        string // operator-provided directives
	// Static reports that the subdomain serves files only, so the vhost must not
	// pass anything to PHP-FPM.
	Static bool
	// AppBlocks are the `location ^~` proxies for applications attached to this
	// subdomain, and AppOwnsRoot is set when one of them holds "/". They ride on
	// webRender rather than on the renderers' signatures because this struct is
	// already computed once and threaded through every call site.
	AppBlocks   string
	AppOwnsRoot bool
	// MaxExecutionTime is this scope's php_settings value, in seconds, RAW. The
	// renderer puts it through provisioner.FastCgiReadTimeout, so a webRender
	// built by hand keeps the timeout the vhost has always carried. Storing the
	// clamped value here instead would add the margin a second time on the way
	// out.
	MaxExecutionTime int
}

// loadWebRender reads the subdomain's nginx settings and renders them. Defaults apply
// when the row is missing, which is the normal state for a subdomain that has never
// had its settings edited.
func loadWebRender(ctx context.Context, db *sql.DB, domainID, subdomainID int64, fqdn string, https bool) webRender {
	settings := nginxset.Defaults()
	backend := "php-fpm"
	if db != nil {
		if loaded, err := nginxset.GetScoped(ctx, db, domainID, subdomainID); err == nil {
			settings = loaded
		}
		if subdomainID > 0 {
			_ = db.QueryRowContext(ctx,
				`SELECT COALESCE(web_backend,'php-fpm') FROM subdomains WHERE id=? AND domain_id=?`,
				subdomainID, domainID).Scan(&backend)
		}
	}
	// The FastCGI read timeout follows this scope's own max_execution_time. A
	// scope with no php_settings row gets the same default the panel shows it.
	maxExecutionTime := phpdefaults.MaxExecutionTime
	if db != nil {
		var stored int
		if err := db.QueryRowContext(ctx,
			`SELECT max_execution_time FROM php_settings WHERE domain_id=? AND subdomain_id=?`,
			domainID, subdomainID).Scan(&stored); err == nil && stored > 0 {
			maxExecutionTime = stored
		}
	}
	out := renderWebSettings(settings, fqdn, https)
	out.MaxExecutionTime = maxExecutionTime
	out.Static = backend == "static"
	if db != nil && subdomainID > 0 {
		out.AppBlocks, out.AppOwnsRoot = provisioner.AppProxyBlocks(db, domainID, subdomainID)
	}
	return out
}

func renderWebSettings(s nginxset.Settings, fqdn string, https bool) webRender {
	opts := provisioner.VhostOpts{
		DomainName:      fqdn,
		HdrXContentType: s.HdrXContentType,
		HdrXXSS:         s.HdrXXSS,
		HdrReferrer:     s.HdrReferrer,
		HdrPermissions:  s.HdrPermissions,
		HdrCSPUpgrade:   s.HdrCSPUpgrade,
		HdrHSTS:         s.HdrHSTS,
		HSTSMaxAge:      s.HSTSMaxAge,
		HSTSSubdomains:  s.HSTSSubdomains,
		HSTSPreload:     s.HSTSPreload,
	}
	if https {
		// SSL() is derived from the certificate paths, and HSTS plus the CSP upgrade
		// directive are only emitted for an HTTPS server block.
		opts.CertPath, opts.KeyPath = "ssl", "ssl"
	}
	out := webRender{Headers: provisioner.SecurityHeaderBlock(opts)}

	if s.FastCgiCache {
		out.SkipCacheMap = `    set $skip_cache 0;
    if ($request_method = POST) { set $skip_cache 1; }
    if ($query_string != "") { set $skip_cache 1; }
    if ($request_uri ~* "/wp-admin/|/wp-login.php|/cart/|/checkout/|/my-account/|preview=true|sitemap.*\.xml") { set $skip_cache 1; }
    if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in") { set $skip_cache 1; }
`
		minutes := s.FastCgiCacheMinutes
		if minutes <= 0 {
			minutes = 60
		}
		out.FastCgiCache = fmt.Sprintf(`        fastcgi_cache %[1]s;
        fastcgi_cache_valid 200 301 302 %[2]dm;
        fastcgi_cache_valid 404 1m;
        fastcgi_cache_bypass $skip_cache;
        fastcgi_no_cache $skip_cache;
        fastcgi_cache_use_stale error timeout invalid_header updating http_500 http_503;
        fastcgi_cache_background_update on;
        fastcgi_cache_lock on;
        add_header X-Cache-Status $upstream_cache_status always;
        access_log /var/log/nginx/%[3]s.cache.log servika_cache_status buffer=32k flush=5m;
`, provisioner.CacheZoneName, minutes, fqdn)
	}

	if s.BrowserCache {
		days := s.BrowserCacheDays
		if days <= 0 {
			days = 30
		}
		out.BrowserCache = fmt.Sprintf(`    location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff2?|svg|webp|avif|mp4|webm|pdf|zip|gz)$ {
        expires %dd;
        access_log off;
        add_header Cache-Control "public" always;
        # Repeat headers because this location defines add_header.
%s    }
`, days, out.Headers)
	}

	if directives := strings.TrimSpace(s.ExtraDirectives); directives != "" {
		out.Extra = "    # ---- Additional directives (user-provided) ----\n    " + directives + "\n"
	}
	return out
}

// GET /domains/{id}/subdomain/{sid}/web-backend reports the subdomain's backend.
func (h *Handlers) GetWebBackend(w http.ResponseWriter, r *http.Request) {
	id, _, _, _, _, ok := h.parent(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	sid, _ := strconv.ParseInt(chi.URLParam(r, "sid"), 10, 64)
	var backend string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(web_backend,'php-fpm') FROM subdomains WHERE id=? AND domain_id=?`, sid, id).
		Scan(&backend); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "subdomain not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"backend": backend,
		// A subdomain has no Apache vhost of its own, so the Apache backend the
		// parent domain offers is not selectable here.
		"available": []string{"php-fpm", "static"},
	})
}

// PUT /domains/{id}/subdomain/{sid}/web-backend switches the subdomain between
// serving PHP and serving static files only.
func (h *Handlers) SetWebBackend(w http.ResponseWriter, r *http.Request) {
	id, systemUser, _, _, demo, ok := h.parent(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "not available on a demo subscription")
		return
	}
	if !strings.HasPrefix(systemUser, "c_") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid system user")
		return
	}
	var req struct {
		Backend string `json:"backend"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Backend != "php-fpm" && req.Backend != "static" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid backend (php-fpm|static)")
		return
	}
	sid, _ := strconv.ParseInt(chi.URLParam(r, "sid"), 10, 64)
	var previous string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(web_backend,'php-fpm') FROM subdomains WHERE id=? AND domain_id=?`, sid, id).
		Scan(&previous); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "subdomain not found")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE subdomains SET web_backend=? WHERE id=? AND domain_id=?`, req.Backend, sid, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update the record")
		return
	}
	// Roll the stored value back when nginx rejects the result, so the record never
	// reports a backend that is not being served.
	if err := ReRender(h.DB, sid); err != nil {
		if _, rollbackErr := h.DB.ExecContext(r.Context(),
			`UPDATE subdomains SET web_backend=? WHERE id=? AND domain_id=?`, previous, sid, id); rollbackErr != nil {
			log.Printf("subdomain %d web backend rollback failed: %v", sid, rollbackErr)
		}
		httpx.WriteError(w, http.StatusInternalServerError, "nginx rejected the configuration")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "backend": req.Backend})
}
