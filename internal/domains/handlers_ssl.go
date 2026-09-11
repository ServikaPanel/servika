package domains

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"servika/internal/httpx"
	"servika/internal/provisioner"

	"github.com/go-chi/chi/v5"
)

type sslIssueReq struct {
	Type string `json:"type"` // "self-signed" | "letsencrypt"
	// MailSSL also orders a certificate for the domain's mail hostnames and
	// serves it to mail clients through SNI. Only meaningful with letsencrypt: a
	// self-signed mail certificate warns exactly as the shared one already does.
	MailSSL bool `json:"mail_ssl,omitempty"`
}

type sslStatusResp struct {
	Enabled   bool   `json:"active"`
	Source    string `json:"source"`
	ExpiresAt string `json:"expires_at,omitempty"`
	CertPath  string `json:"cert_path,omitempty"`
	KeyPath   string `json:"key_path,omitempty"`
}

func (h *Handlers) SSLStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var enabled int
	var source, certPath, keyPath, expiresAt string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT ssl_enabled, ssl_source, cert_path, key_path,
		   COALESCE(DATE_FORMAT(ssl_expiry,'%Y-%m-%dT%H:%i:%sZ'),'')
		 FROM domains WHERE id=?`, id).
		Scan(&enabled, &source, &certPath, &keyPath, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sslStatusResp{
		Enabled:   enabled == 1,
		Source:    source,
		ExpiresAt: expiresAt,
		CertPath:  certPath,
		KeyPath:   keyPath,
	})
}

func (h *Handlers) SSLIssue(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var req sslIssueReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Type == "" {
		req.Type = "self-signed"
	}
	if req.Type != "self-signed" && req.Type != "letsencrypt" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid type (self-signed|letsencrypt)")
		return
	}
	var domainName, systemUser, phpVersion, backend string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, system_user, php_version, COALESCE(web_backend,'php-fpm') FROM domains WHERE id=?`, id).
		Scan(&domainName, &systemUser, &phpVersion, &backend)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	// Any other Scan error has to stop the request here. It cannot be checked
	// further down because the switch below assigns to err, which would discard
	// it; and continuing means calling the provisioner with an empty domain name
	// and system user.
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if domainName == "" || systemUser == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "domain record is incomplete")
		return
	}

	// The installation runs on a context of its own from here.
	//
	// An ACME order measures every SAN name before asking the CA for it, and the
	// mail certificate is a second order on top, so this takes minutes. Held on
	// the request, the browser gave up before the work did and closing the tab
	// cancelled it mid-install. The caller polls SSLProgress instead.
	job, started := claimSSLJob(id, domainName)
	if !started {
		// A second order for the same name would spend the CA's per-domain
		// allowance and could overwrite the first one's files while it runs.
		httpx.WriteError(w, http.StatusConflict, "an SSL installation is already running for this domain")
		return
	}
	// #nosec G118 -- outliving the request is the point: the work must finish even when the tab is closed, and it carries its own bounded context.
	go h.runSSLInstall(job, id, req, domainName, systemUser, phpVersion, backend)

	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"ok":    true,
		"id":    id,
		"state": sslJobRunning,
	})
}

func (h *Handlers) SSLDisable(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var domainName, systemUser, phpVersion, backend string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, system_user, php_version, COALESCE(web_backend,'php-fpm') FROM domains WHERE id=?`, id).
		Scan(&domainName, &systemUser, &phpVersion, &backend)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	// Same class as SSLIssue: a swallowed Scan error would take DisableSSL an
	// empty domain name, and would leave the demo guard below reading 0.
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if domainName == "" || systemUser == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "domain record is incomplete")
		return
	}
	if err := provisioner.DisableSSL(domainName, systemUser, phpVersion, backend); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "SSL disable failed")
		return
	}
	// Detached for the same reason as the issue path: the vhost has already been
	// rewritten and nginx reloaded, so a lost write would leave the panel
	// claiming SSL is on for a site now serving plain HTTP.
	writeCtx, cancelWrite := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelWrite()
	if _, err := h.DB.ExecContext(writeCtx,
		`UPDATE domains SET ssl_enabled=0, ssl_source='', cert_path='', key_path='', ssl_expiry=NULL
		 WHERE id=?`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
