// Package subdomain manages subdomains under the parent domain's user and PHP pool.
// Each subdomain receives a separate document root, nginx server block, and DNS A record.
package subdomain

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"servika/internal/dns"
	"servika/internal/domainblock"
	"servika/internal/files"
	"servika/internal/httpx"
	"servika/internal/provisioner"

	"github.com/go-chi/chi/v5"
)

type Handlers struct {
	DB   *sql.DB
	IPv4 string
}

var subdomainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

type Sub struct {
	ID         int64  `json:"id"`
	Subdomain  string `json:"subdomain"`
	FQDN       string `json:"fqdn"`
	PHPVersion string `json:"php_version"`
	DocRoot    string `json:"docroot"`
	CreatedAt  string `json:"created_at"`
	// PHPLocked is true when this subdomain cannot be moved off its parent
	// domain's PHP version. It rides on the list so the interface can disable the
	// picker and say why, rather than letting a tenant choose a version and
	// collect a refusal.
	PHPLocked bool `json:"php_locked"`
	// SSL and SSLSource carry the same three-state answer the domain rows carry:
	// no certificate, a self-signed one a browser refuses, or one it accepts. An
	// empty source with SSL set means trusted with an unrecorded origin.
	SSL       bool   `json:"ssl"`
	SSLSource string `json:"ssl_source"`
}

func (h *Handlers) parent(r *http.Request) (id int64, systemUser, domainName, phpVersion string, demo, ok bool) {
	id, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var isDemo int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, domain_name, COALESCE(php_version,'8.3'), COALESCE(is_demo,0) FROM domains WHERE id=?`, id).
		Scan(&systemUser, &domainName, &phpVersion, &isDemo); err != nil {
		return id, "", "", "", false, false
	}
	return id, systemUser, domainName, phpVersion, isDemo == 1, true
}

func docrootOf(systemUser, fqdn string) string { return "/home/" + systemUser + "/subdomains/" + fqdn }

// Scope describes the document root a request targets. Tools that operate on a
// site's files (WordPress, Composer) and on its nginx logs use it so a subdomain
// is acted on in its own root instead of the parent domain's public_html.
type Scope struct {
	SubdomainID int64
	FQDN        string
	DocRoot     string
	PHPVersion  string
	// HasTLS reports whether the subdomain's certificate pair is installed, so callers
	// can build a site URL with the scheme nginx actually serves.
	HasTLS bool
}

// ResolveScope loads the scope for a subdomain that belongs to domainID. It returns
// ok=false when the subdomain does not exist or belongs to another domain, so a
// tenant cannot reach another domain's files by guessing an id.
func ResolveScope(ctx context.Context, db *sql.DB, domainID, subdomainID int64) (Scope, bool) {
	if subdomainID <= 0 {
		return Scope{}, false
	}
	var systemUser, name, fqdn, phpVersion string
	if err := db.QueryRowContext(ctx,
		`SELECT d.system_user, s.subdomain, s.fqdn, COALESCE(s.php_version,'8.3')
		   FROM subdomains s JOIN domains d ON d.id = s.domain_id
		  WHERE s.id=? AND s.domain_id=?`, subdomainID, domainID).
		Scan(&systemUser, &name, &fqdn, &phpVersion); err != nil {
		return Scope{}, false
	}
	// Re-validate the stored values before they reach a filesystem path.
	if !subdomainPattern.MatchString(name) || provisioner.ValidateDomain(fqdn) != nil {
		return Scope{}, false
	}
	certPath, keyPath := certificatePaths(systemUser, fqdn)
	return Scope{
		SubdomainID: subdomainID,
		FQDN:        fqdn,
		DocRoot:     docrootOf(systemUser, fqdn),
		PHPVersion:  phpVersion,
		HasTLS:      fileExists(certPath) && fileExists(keyPath),
	}, true
}
func confPath(systemUser, subdomainName string) string {
	return "/etc/nginx/conf.d/sub_" + systemUser + "_" + subdomainName + ".conf"
}

// GET /domains/{id}/subdomain lists subdomains.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	id, systemUser, _, _, _, ok := h.parent(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, subdomain, fqdn, php_version, DATE_FORMAT(created_at,'%Y-%m-%d %H:%i') FROM subdomains WHERE domain_id=? ORDER BY subdomain`, id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list records")
		return
	}
	defer func() { _ = rows.Close() }()
	// Read once per request: the answer is a property of the TENANT, not of any
	// one subdomain, and it reaches the filesystem.
	phpLocked := provisioner.TenantFPMActive(systemUser)
	out := []Sub{}
	for rows.Next() {
		var s Sub
		if err := rows.Scan(&s.ID, &s.Subdomain, &s.FQDN, &s.PHPVersion, &s.CreatedAt); err == nil {
			s.DocRoot = docrootOf(systemUser, s.FQDN)
			s.PHPLocked = phpLocked
			s.SSL, s.SSLSource = sslState(systemUser, s.Subdomain, s.FQDN)
			out = append(out, s)
		}
	}
	_ = rows.Err()
	httpx.WriteJSON(w, http.StatusOK, out)
}

// POST /domains/{id}/subdomain creates a subdomain from {subdomain, php_version?}.
func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	id, systemUser, domainName, parentPHP, demo, ok := h.parent(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "not available for demo subscriptions")
		return
	}
	if !strings.HasPrefix(systemUser, "c_") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user")
		return
	}
	var req struct {
		Subdomain  string `json:"subdomain"`
		PHPVersion string `json:"php_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	subdomainName := strings.ToLower(strings.TrimSpace(req.Subdomain))
	if !subdomainPattern.MatchString(subdomainName) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid subdomain (lowercase letters, digits, and hyphens only)")
		return
	}
	phpVersion := strings.TrimSpace(req.PHPVersion)
	if phpVersion == "" {
		phpVersion = parentPHP
	}
	fqdn := subdomainName + "." + domainName
	if err := provisioner.ValidateDomain(fqdn); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid domain name")
		return
	}
	if domainblock.RefuseIfBlocked(w, r, h.DB, fqdn) {
		return
	}
	// Reject conflicts with existing domains or subdomains.
	var n int
	_ = h.DB.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE fqdn=?`, fqdn).Scan(&n)
	if n == 0 {
		_ = h.DB.QueryRow(`SELECT COUNT(*) FROM domains WHERE domain_name=?`, fqdn).Scan(&n)
	}
	if n > 0 {
		httpx.WriteError(w, http.StatusConflict, "this domain name is already in use")
		return
	}
	// Refused rather than quietly downgraded to the parent's version. PHPSocketFor
	// answers a per-tenant FPM account with its one socket whatever version is
	// asked for, so accepting this would record a version the server never serves.
	if phpVersionLocked(provisioner.TenantFPMActive(systemUser), parentPHP, phpVersion) {
		httpx.WriteError(w, http.StatusConflict, reasonPHPVersionLocked)
		return
	}
	socket, err := provisioner.PHPSocketFor(systemUser, phpVersion)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "PHP version is not installed on the server: "+phpVersion)
		return
	}
	docroot := docrootOf(systemUser, fqdn)
	// The tenant owns this home and can replace ~/subdomains with a symlink, and
	// os.MkdirAll follows one, so root would create the document root outside the
	// jail. openat2(RESOLVE_BENEATH|NO_SYMLINKS) refuses that, and chowns each
	// directory it creates through that directory's own fd.
	if err := files.MkdirAllBeneath("/home/"+systemUser, "subdomains/"+fqdn, systemUser); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create document root")
		return
	}
	// Create the initial landing page.
	// #nosec G703 -- docroot derives from a validated systemUser/subdomain path, not raw tenant input.
	if _, e := os.Stat(filepath.Join(docroot, "index.html")); e != nil {
		// #nosec G306 G703 -- root-owned welcome page under a validated tenant docroot that nginx must read; no secret and no raw tenant path input.
		_ = os.WriteFile(filepath.Join(docroot, "index.html"),
			[]byte(provisioner.WelcomeHTML(fqdn)), 0o644)
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_ = exec.Command("chown", "-R", systemUser+":"+systemUser, "/home/"+systemUser+"/subdomains").Run()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_ = exec.Command("chcon", "-R", "-t", "httpd_sys_content_t", docroot).Run()

	// Write the nginx server block.
	conf := confPath(systemUser, subdomainName)
	// A newly created subdomain has no protected directories or settings row yet, so
	// it renders with the domain-level defaults until its own row exists.
	web := loadWebRender(r.Context(), h.DB, id, 0, fqdn, false)
	// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(conf, []byte(vhost(fqdn, docroot, socket, "", web)), 0o644); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not write virtual host configuration")
		return
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_ = exec.Command("restorecon", conf).Run()
	if _, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		_ = os.Remove(conf) // Remove the invalid configuration so the running nginx instance remains unaffected.
		_ = exec.Command("nginx", "-t").Run()
		httpx.WriteError(w, http.StatusInternalServerError, "operation failed")
		return
	}
	if out, err := exec.Command("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
		// Config validated with `nginx -t` above but reload failed: the vhost is on
		// disk yet not live. Remove it and report failure rather than a false success.
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		_ = os.Remove(conf)
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("nginx reload after subdomain create %s: %v: %s", fqdn, err, strings.TrimSpace(string(out)))
		httpx.WriteError(w, http.StatusInternalServerError, "subdomain configured but nginx reload failed")
		return
	}

	result, err := h.DB.Exec(`INSERT INTO subdomains (domain_id, subdomain, fqdn, php_version) VALUES (?,?,?,?)`,
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
		id, subdomainName, fqdn, phpVersion)
	if err != nil {
		// #nosec G703 -- path built from a validated identifier / fixed system path / server-internal temp path; tenant paths use safeio (openat2).
		_ = os.Remove(conf)
		_ = exec.Command("systemctl", "reload", "nginx").Run()
		httpx.WriteError(w, http.StatusInternalServerError, "could not add record")
		return
	}
	// The pool is keyed by the subdomain id, which only exists after the insert, so the
	// vhost written above still points at the parent socket. Install the dedicated pool
	// now and re-render. A failure here is not fatal: the subdomain already serves PHP
	// through the parent pool, so log the loss of its own pool instead of deleting a
	// working subdomain.
	if sid, idErr := result.LastInsertId(); idErr == nil && sid > 0 {
		if _, fpmErr := provisioner.ApplySubdomainFPM(h.DB, id, sid, systemUser, docroot, phpVersion); fpmErr != nil {
			// #nosec G706 -- fqdn passed provisioner.ValidateDomain above, so it carries no CR/LF; the error value is command output, not raw tenant input.
			log.Printf("subdomain %s dedicated PHP-FPM pool: %v", fqdn, fpmErr)
		} else if rerr := ReRender(h.DB, sid); rerr != nil {
			// #nosec G706 -- fqdn passed provisioner.ValidateDomain above, so it carries no CR/LF; the error value is command output, not raw tenant input.
			log.Printf("subdomain %s vhost re-render after pool install: %v", fqdn, rerr)
		}
	}
	// Add the DNS A record to the parent zone and rewrite the zone file.
	if h.IPv4 != "" {
		_, _ = h.DB.Exec(`INSERT INTO dns_records (domain_id, name, type, value, ttl, priority, enabled) VALUES (?,?,?,?,?,?,1)`,
			id, subdomainName, "A", h.IPv4, 3600, 0)
		_ = dns.WriteZone(r.Context(), h.DB, id)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "fqdn": fqdn, "docroot": docroot})
}

// DELETE /domains/{id}/subdomain/{sid} removes a subdomain.
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, systemUser, _, _, demo, ok := h.parent(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "not available for demo subscriptions")
		return
	}
	if !strings.HasPrefix(systemUser, "c_") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user")
		return
	}
	sid, _ := strconv.ParseInt(chi.URLParam(r, "sid"), 10, 64)
	var subdomainName, fqdn string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT subdomain, fqdn FROM subdomains WHERE id=? AND domain_id=?`, sid, id).Scan(&subdomainName, &fqdn); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "subdomain not found")
		return
	}
	// Delete the DB rows FIRST so a DB failure aborts before the filesystem is
	// touched; otherwise a swallowed delete leaves a dangling record pointing at a
	// removed vhost.
	if _, err := h.DB.Exec(`DELETE FROM subdomains WHERE id=? AND domain_id=?`, sid, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete subdomain")
		return
	}
	// php_settings/nginx_settings use subdomain_id=0 for the domain's own row, so a
	// foreign key cannot clean these up; remove them explicitly or the ids would be
	// reused by a later subdomain and silently inherit the deleted one's settings.
	if _, err := h.DB.Exec(`DELETE FROM php_settings WHERE domain_id=? AND subdomain_id=?`, id, sid); err != nil {
		log.Printf("delete subdomain PHP settings %d: %v", sid, err)
	}
	if _, err := h.DB.Exec(`DELETE FROM nginx_settings WHERE domain_id=? AND subdomain_id=?`, id, sid); err != nil {
		log.Printf("delete subdomain nginx settings %d: %v", sid, err)
	}
	provisioner.RemoveSubdomainFPM(systemUser, sid)
	if _, err := h.DB.Exec(`DELETE FROM dns_records WHERE domain_id=? AND name=? AND type='A'`, id, subdomainName); err != nil {
		log.Printf("delete subdomain DNS record %s: %v", subdomainName, err)
		// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	}
	// #nosec G703 -- path built from a validated identifier / fixed system path / server-internal temp path; tenant paths use safeio (openat2).
	_ = os.Remove(confPath(systemUser, subdomainName))
	_ = exec.Command("systemctl", "reload", "nginx").Run()
	// Remove the document root the same way it was created, through openat2.
	//
	// The guard here used to be a string prefix on the path, which cannot see
	// what the path RESOLVES to. The panel runs as root and ~/subdomains belongs
	// to the tenant: replace it with a symlink and os.RemoveAll follows it out of
	// the jail while the string still reads /home/<user>/subdomains/... The mkdir
	// a few lines up already refuses that; the removal did not.
	if err := files.RemoveAllBeneath("/home/"+systemUser, "subdomains/"+fqdn); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("delete subdomain document root %s: %v", fqdn, err)
	}
	// The certificate goes with it. Left behind, ~/ssl/<fqdn>.crt and .key
	// outlive everything that referred to them, and creating the same name again
	// finds them: SSLStatus reads the files, so the new subdomain would come up
	// reporting a certificate that was issued for a site somebody deleted.
	//
	// Same removal as above, for the same reason: ~/ssl is the tenant's too.
	for _, extension := range []string{".crt", ".key"} {
		if err := files.RemoveAllBeneath("/home/"+systemUser, "ssl/"+fqdn+extension); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("delete subdomain certificate %s%s: %v", fqdn, extension, err)
		}
	}
	if err := dns.WriteZone(r.Context(), h.DB, id); err != nil {
		log.Printf("write DNS zone after subdomain delete %s: %v", subdomainName, err)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// vhost renders the plain HTTP server block. protected carries the auth_basic
// blocks for this subdomain's protected directories and is empty when none exist.
// web carries the rendered nginx_settings fragments for this subdomain.
func vhost(fqdn, docroot, socket, protected string, web webRender) string {
	return fmt.Sprintf(`server {
    listen 80;
`+provisioner.ListenIPv6("80")+`    server_name %[1]s;

    root %[2]s;
    index index.php index.html index.htm;

    access_log /var/log/nginx/%[1]s.access.log;
    error_log  /var/log/nginx/%[1]s.error.log warn;

%[4]s
%[3]s
    location /.well-known/acme-challenge/ {
        auth_basic off;
        root /var/www/_acme;
        try_files $uri =404;
    }

    error_page 404 /_srv_404.html;
    location = /_srv_404.html {
        root /usr/share/servika/errors;
        internal;
        access_log off;
    }
    location ^~ /_srv/ {
        alias /usr/share/servika/errors/;
        access_log off;
        expires 7d;
        gzip on;
        gzip_types application/json application/javascript;
    }

%[5]s
%[6]s
    location ~ /\.(?!well-known) { deny all; }

%[7]s    # Servika subdomain — %[1]s
}
`, fqdn, docroot, protected, web.Headers,
		backendBlock(socket, web, false), web.BrowserCache, web.Extra)
}

// backendBlock renders the request-serving locations for a scope. A static backend
// gets no fastcgi_pass at all, so it cannot keep pointing at a pool that may no
// longer exist; the PHP backend mirrors the domain vhost's own structure.
func backendBlock(socket string, web webRender, https bool) string {
	// An application mounted at "/" replaces the scope's own root location, so
	// the two cannot both be emitted: nginx refuses a duplicate prefix.
	rootLocation := ""
	if web.Static {
		if !web.AppOwnsRoot {
			rootLocation = "    location / { try_files $uri $uri/ =404; }\n"
		}
		return web.AppBlocks + "    # ---- Backend: static files only ----\n" + rootLocation
	}
	httpsParam := ""
	if https {
		httpsParam = "        fastcgi_param HTTPS on;\n"
	}
	if !web.AppOwnsRoot {
		rootLocation = "    location / { try_files $uri $uri/ /index.php?$query_string; }\n"
	}
	return web.AppBlocks + fmt.Sprintf(`%[6]s
%[2]s    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:%[1]s;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
%[5]s        fastcgi_read_timeout %[7]ds;
        # Repeat headers because this location may define add_header below.
%[3]s%[4]s    }
`, socket, web.SkipCacheMap, web.Headers, web.FastCgiCache, httpsParam, rootLocation,
		provisioner.FastCgiReadTimeout(web.MaxExecutionTime))
}
