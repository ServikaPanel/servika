package subdomain

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"servika/internal/diskusage"
	"servika/internal/httpx"
	"servika/internal/provisioner"

	"github.com/go-chi/chi/v5"
)

// GET /domains/{id}/subdomain/{sid} returns a single subdomain with the data its
// management page needs. The lookup is scoped to the parent domain so a tenant
// cannot read a subdomain that belongs to another domain.
func (h *Handlers) Detail(w http.ResponseWriter, r *http.Request) {
	id, systemUser, domainName, _, ok := h.parent(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	sid, _ := strconv.ParseInt(chi.URLParam(r, "sid"), 10, 64)
	var s Sub
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, subdomain, fqdn, php_version, DATE_FORMAT(created_at,'%Y-%m-%d %H:%i')
		   FROM subdomains WHERE id=? AND domain_id=?`, sid, id).
		Scan(&s.ID, &s.Subdomain, &s.FQDN, &s.PHPVersion, &s.CreatedAt); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "subdomain not found")
		return
	}
	s.DocRoot = docrootOf(systemUser, s.FQDN)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id":          s.ID,
		"subdomain":   s.Subdomain,
		"fqdn":        s.FQDN,
		"php_version": s.PHPVersion,
		"php_locked":  tenantFPMActive(systemUser),
		"docroot":     s.DocRoot,
		"created_at":  s.CreatedAt,
		"parent_id":   id,
		"parent_name": domainName,
		"disk_kb":     docrootDiskKB(r.Context(), s.DocRoot),
		"ipv4":        h.IPv4,
	})
}

// PUT /domains/{id}/subdomain/{sid}/php switches the subdomain's PHP-FPM pool
// from {php_version}. The vhost is rewritten with the new socket and validated
// before the record is updated, so a rejected configuration leaves both nginx and
// the database untouched. The rewrite is TLS-aware: an existing certificate keeps
// the HTTPS vhost, so switching PHP never drops the site to plain HTTP.
func (h *Handlers) SetPHP(w http.ResponseWriter, r *http.Request) {
	id, systemUser, _, parentPHP, ok := h.parent(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if !strings.HasPrefix(systemUser, "c_") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid system user")
		return
	}
	var req struct {
		PHPVersion string `json:"php_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	phpVersion := strings.TrimSpace(req.PHPVersion)
	// The vhost would be rewritten and the record updated, and neither would
	// change what runs: ApplySubdomainFPM falls back to PHPSocketFor, which hands
	// a per-tenant FPM account its one socket regardless of the version. Saying
	// so is the only honest answer; the parent domain's version is the lever that
	// works.
	if phpVersionLocked(tenantFPMActive(systemUser), parentPHP, phpVersion) {
		httpx.WriteError(w, http.StatusConflict, reasonPHPVersionLocked)
		return
	}
	sid, _ := strconv.ParseInt(chi.URLParam(r, "sid"), 10, 64)
	var subdomainName, fqdn string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT subdomain, fqdn FROM subdomains WHERE id=? AND domain_id=?`, sid, id).
		Scan(&subdomainName, &fqdn); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "subdomain not found")
		return
	}
	docroot := docrootOf(systemUser, fqdn)
	// The pool lives inside the parent tenant's own FPM unit whenever it can, so the
	// subdomain stays in the tenant mount namespace and slice; ApplySubdomainFPM
	// falls back to the shared master and reports the socket either way.
	socket, err := applySubdomainFPM(h.DB, id, sid, systemUser, docroot, phpVersion)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "PHP version is not installed on the server")
		return
	}
	protected := protectedBlocks(h.DB, id, sid, socket)
	certPath, keyPath := certificatePaths(systemUser, fqdn)
	https := fileExists(certPath) && fileExists(keyPath)
	web := loadWebRender(r.Context(), h.DB, id, sid, fqdn, https)
	config := vhost(fqdn, docroot, socket, protected, web)
	if https {
		config = vhostSSL(fqdn, docroot, socket, certPath, keyPath, protected, web)
	}
	if err := applyVhost(confPath(systemUser, subdomainName), config); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "nginx rejected the configuration")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE subdomains SET php_version=? WHERE id=? AND domain_id=?`, phpVersion, sid, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update the record")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "php_version": phpVersion})
}

// ReRender rewrites one subdomain's vhost from its current database state,
// including its own auth_basic blocks. It is TLS-aware, so an existing certificate
// keeps the HTTPS vhost. Callers that change a subdomain's protected directories
// use this to publish the change without duplicating the nginx apply sequence.
func ReRender(db *sql.DB, subdomainID int64) error {
	var domainID int64
	var systemUser, subdomainName, fqdn, phpVersion string
	if err := db.QueryRow(
		`SELECT s.domain_id, d.system_user, s.subdomain, s.fqdn, s.php_version
		   FROM subdomains s JOIN domains d ON d.id = s.domain_id WHERE s.id=?`, subdomainID).
		Scan(&domainID, &systemUser, &subdomainName, &fqdn, &phpVersion); err != nil {
		return err
	}
	socket, err := provisioner.SubdomainFPMSocket(db, systemUser, domainID, subdomainID, phpVersion)
	if err != nil {
		return err
	}
	docroot := docrootOf(systemUser, fqdn)
	protected := protectedBlocks(db, domainID, subdomainID, socket)
	certPath, keyPath := certificatePaths(systemUser, fqdn)
	https := fileExists(certPath) && fileExists(keyPath)
	web := loadWebRender(context.Background(), db, domainID, subdomainID, fqdn, https)
	config := vhost(fqdn, docroot, socket, protected, web)
	if https {
		config = vhostSSL(fqdn, docroot, socket, certPath, keyPath, protected, web)
	}
	return applyVhost(confPath(systemUser, subdomainName), config)
}

// docrootDiskKB reports the document root size in kilobytes. It is best effort:
// a missing directory or a measurement failure reports 0 rather than failing the
// request. The measurement goes through internal/diskusage so a customer cannot
// turn repeated views into unbounded root-privileged disk I/O.
func docrootDiskKB(ctx context.Context, docroot string) int64 {
	size, err := diskusage.Bytes(ctx, docroot)
	if err != nil {
		return 0
	}
	return size / 1024
}
