package addondomains

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"servika/internal/credentials"
	"servika/internal/dns"
	"servika/internal/domainblock"
	"servika/internal/files"
	"servika/internal/httpx"
	"servika/internal/provisioner"
	"servika/internal/quota"

	"github.com/go-chi/chi/v5"
)

type Handlers struct {
	DB   *sql.DB
	IPv4 string
}

type AddonDomain struct {
	ID         int64  `json:"id"`
	DomainName string `json:"domain_name"`
	Parked     bool   `json:"parked"`
	DocRoot    string `json:"docroot"`
	PHPVersion string `json:"php_version"`
	SSL        bool   `json:"ssl"`
	CreatedAt  string `json:"created_at"`
}

type createReq struct {
	DomainName string `json:"domain_name"`
	Parked     bool   `json:"parked"`
}

type parentDomain struct {
	ID         int64
	DomainName string
	SystemUser string
	PHPVersion string
	WebRoot    string
	CustomerID *int64
	PlanID     *int64
	Demo       bool
}

func scanAddon(rs interface{ Scan(...any) error }) (AddonDomain, error) {
	var item AddonDomain
	var parked, ssl int
	err := rs.Scan(&item.ID, &item.DomainName, &parked, &item.DocRoot, &item.PHPVersion, &ssl, &item.CreatedAt)
	item.Parked = parked == 1
	item.SSL = ssl == 1
	return item, err
}

func (h *Handlers) parent(ctx context.Context, id int64) (parentDomain, error) {
	var p parentDomain
	var customerID, planID sql.NullInt64
	var demo int
	err := h.DB.QueryRowContext(ctx,
		`SELECT id, domain_name, system_user, COALESCE(php_version,'8.3'), COALESCE(web_root,''), customer_id, plan_id, COALESCE(is_demo,0)
		 FROM domains WHERE id=? AND parent_domain_id IS NULL`, id).
		Scan(&p.ID, &p.DomainName, &p.SystemUser, &p.PHPVersion, &p.WebRoot, &customerID, &planID, &demo)
	if err != nil {
		return p, err
	}
	if customerID.Valid {
		v := customerID.Int64
		p.CustomerID = &v
	}
	if planID.Valid {
		v := planID.Int64
		p.PlanID = &v
	}
	p.Demo = demo == 1
	return p, nil
}

func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	parentID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if _, err := h.parent(r.Context(), parentID); errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	} else if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, domain_name, COALESCE(parked,0), COALESCE(web_root,''), COALESCE(php_version,'8.3'), ssl_enabled,
		        DATE_FORMAT(created_at,'%Y-%m-%d %H:%i')
		 FROM domains WHERE parent_domain_id=? ORDER BY id DESC`, parentID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer func() { _ = rows.Close() }()
	out := make([]AddonDomain, 0)
	for rows.Next() {
		item, err := scanAddon(rows)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
			return
		}
		out = append(out, item)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	parentID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	parent, err := h.parent(r.Context(), parentID)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if parent.Demo {
		httpx.WriteError(w, http.StatusForbidden, "addon domains cannot be added to demo subscriptions")
		return
	}

	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.DomainName = strings.ToLower(strings.TrimSpace(req.DomainName))
	if err := provisioner.ValidateDomain(req.DomainName); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid domain name")
		return
	}
	if domainblock.RefuseIfBlocked(w, r, h.DB, req.DomainName) {
		return
	}
	if req.DomainName == parent.DomainName {
		httpx.WriteError(w, http.StatusConflict, "addon domain cannot match the parent domain")
		return
	}
	if err := quota.CheckDomainAllowed(r.Context(), h.DB, parent.CustomerID); err != nil {
		var le *quota.LimitError
		if errors.As(err, &le) {
			httpx.WriteError(w, http.StatusForbidden, le.Message)
			return
		}
		log.Printf("addon domain quota check failed: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify plan limit")
		return
	}
	var existing int64
	if err := h.DB.QueryRowContext(r.Context(), `SELECT id FROM domains WHERE domain_name=?`, req.DomainName).Scan(&existing); err == nil {
		httpx.WriteError(w, http.StatusConflict, "this domain name is already registered")
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if err := h.DB.QueryRowContext(r.Context(), `SELECT id FROM subdomains WHERE fqdn=?`, req.DomainName).Scan(&existing); err == nil {
		httpx.WriteError(w, http.StatusConflict, "this domain name is already registered as a subdomain")
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}

	docroot := provisioner.SafeWebRoot(parent.SystemUser, parent.WebRoot)
	if !req.Parked {
		docroot = provisioner.AddonWebRoot(parent.SystemUser, req.DomainName)
		if err := prepareDocRoot(docroot, parent.SystemUser, req.DomainName); err != nil {
			log.Printf("addon domain docroot prepare %q: %v", req.DomainName, err)
			httpx.WriteError(w, http.StatusInternalServerError, "document root creation failed")
			return
		}
	}

	res, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO domains(domain_name, system_user, php_version, ssl_enabled, status, ipv4,
		   ftp_host, ftp_user, db_host, db_user, db_name, web_root, is_demo, customer_id, plan_id, parent_domain_id, parked)
		 VALUES(?,?,?,0,'active',?,?,?, 'localhost','','',?,0,?,?,?,?)`,
		req.DomainName, parent.SystemUser, parent.PHPVersion, h.IPv4,
		h.IPv4, parent.SystemUser, docroot, parent.CustomerID, parent.PlanID, parent.ID, boolInt(req.Parked))
	if err != nil {
		log.Printf("addon domain insert %q: %v", req.DomainName, err)
		httpx.WriteError(w, http.StatusInternalServerError, "addon domain record creation failed")
		return
	}
	addonID, _ := res.LastInsertId()

	if err := provisioner.RerenderVhost(h.DB, addonID); err != nil {
		log.Printf("addon domain vhost render %q: %v", req.DomainName, err)
		_, _ = Cleanup(r.Context(), h.DB, addonID)
		httpx.WriteError(w, http.StatusInternalServerError, "virtual host update failed")
		return
	}
	if _, err := dns.SeedDefaults(r.Context(), h.DB, addonID, req.DomainName, h.IPv4); err != nil {
		log.Printf("DNS SeedDefaults %q error: %v", req.DomainName, err)
	}
	if err := dns.WriteZone(r.Context(), h.DB, addonID); err != nil {
		log.Printf("DNS WriteZone %q error: %v", req.DomainName, err)
	}

	row := h.DB.QueryRowContext(r.Context(),
		`SELECT id, domain_name, COALESCE(parked,0), COALESCE(web_root,''), COALESCE(php_version,'8.3'), ssl_enabled,
		        DATE_FORMAT(created_at,'%Y-%m-%d %H:%i')
		 FROM domains WHERE id=?`, addonID)
	item, _ := scanAddon(row)
	httpx.WriteJSON(w, http.StatusCreated, item)
}

func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	addonID, _ := strconv.ParseInt(chi.URLParam(r, "addonID"), 10, 64)
	parentID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var actualParentID int64
	err := h.DB.QueryRowContext(r.Context(), `SELECT COALESCE(parent_domain_id,0) FROM domains WHERE id=?`, addonID).Scan(&actualParentID)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "addon domain not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	if actualParentID != parentID {
		httpx.WriteError(w, http.StatusNotFound, "addon domain not found")
		return
	}
	deleted, err := Cleanup(r.Context(), h.DB, addonID)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "addon domain not found")
		return
	}
	if err != nil {
		log.Printf("addon domain delete %d: %v", addonID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "addon domain deletion failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": deleted})
}

func Cleanup(ctx context.Context, db *sql.DB, addonID int64) (string, error) {
	var domainName, systemUser, webRoot string
	var parentID, demo, parked int
	err := db.QueryRowContext(ctx,
		`SELECT domain_name, system_user, COALESCE(web_root,''), COALESCE(parent_domain_id,0), COALESCE(is_demo,0), COALESCE(parked,0)
		 FROM domains WHERE id=?`, addonID).
		Scan(&domainName, &systemUser, &webRoot, &parentID, &demo, &parked)
	if err != nil {
		return "", err
	}
	if parentID == 0 {
		return "", errors.New("domain is not an addon domain")
	}
	if demo == 0 {
		_ = credentials.MySQLDropAllForDomain(db, addonID)
		if err := provisioner.DeprovisionAddonDomain(domainName, systemUser); err != nil {
			log.Printf("addon domain deprovision warn (%s): %v", domainName, err)
		}
		// The document root is removed HERE, beside prepareDocRoot, so the two
		// halves of the same path cannot drift apart again: the mkdir has always
		// gone through openat2 while the removal was a string check inside the
		// provisioner, which cannot import internal/files.
		if parked == 0 {
			removeDocRoot(systemUser, domainName, webRoot)
		}
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM domain_traffic WHERE domain_id=?`, addonID); err != nil {
		log.Printf("addon domain traffic cleanup warn (%d): %v", addonID, err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM domain_traffic_cursor WHERE domain_id=?`, addonID); err != nil {
		log.Printf("addon domain traffic cursor cleanup warn (%d): %v", addonID, err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM domains WHERE id=?`, addonID); err != nil {
		return "", err
	}
	if demo == 0 {
		if err := dns.DeleteZone(ctx, db, domainName); err != nil {
			log.Printf("DNS DeleteZone warn (%s): %v", domainName, err)
		}
	}
	return domainName, nil
}

// removeDocRoot deletes an addon domain's document root through openat2.
//
// It mirrors prepareDocRoot exactly, and for the same reason: the panel runs as
// root, ~/domains belongs to the tenant, and a component swapped for a symlink
// sends the removal outside the jail while the path still reads like one inside
// it. The stored web root is honoured only when it is under ~/domains, which is
// what the vhost renderer accepts, and the base itself is never the target.
//
// Best effort: the domain row is being deleted either way, and a document root
// left on disk is a leak to report, not a reason to abandon the deletion.
func removeDocRoot(systemUser, domainName, webRoot string) {
	home := "/home/" + systemUser
	base := filepath.Join(home, "domains")
	docroot := filepath.Clean(strings.TrimSpace(webRoot))
	if docroot == "" || docroot == "." || !strings.HasPrefix(docroot, base+string(os.PathSeparator)) {
		docroot = provisioner.AddonWebRoot(systemUser, domainName)
	}
	rel, ok := strings.CutPrefix(filepath.Clean(docroot), home+"/")
	if !ok || rel == "domains" {
		return
	}
	if err := files.RemoveAllBeneath(home, rel); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("addon domain document root %s: %v", domainName, err)
	}
}

func prepareDocRoot(docroot, systemUser, domainName string) error {
	// os.MkdirAll follows a symlink at any component, and the tenant owns this
	// home, so root could be made to build the document root outside the jail.
	// Resolve every component with openat2(RESOLVE_BENEATH|NO_SYMLINKS) instead.
	home := "/home/" + systemUser
	rel, ok := strings.CutPrefix(docroot, home+"/")
	if !ok {
		return fmt.Errorf("document root is outside the tenant home")
	}
	if err := files.MkdirAllBeneath(home, rel, systemUser); err != nil {
		return fmt.Errorf("document root is not safe: %w", err)
	}
	index := filepath.Join(docroot, "index.html")
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(index, []byte(addonWelcomeHTML(domainName)), 0644); err != nil {
		return err
	}
	uid, gid := uidGidOf(systemUser)
	if uid > 0 && gid > 0 {
		_ = filepath.Walk(docroot, func(path string, _ os.FileInfo, _ error) error {
			// #nosec G122 -- operator provisioning of a freshly created docroot, not tenant input; best-effort ownership fix.
			_ = os.Chown(path, uid, gid)
			return nil
		})
	}
	return nil
}

func addonWelcomeHTML(domain string) string {
	safeDomain := html.EscapeString(domain)
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>` + safeDomain + `</title></head><body><h1>` + safeDomain + `</h1><p>Addon domain managed by Servika.</p></body></html>`
}

func uidGidOf(name string) (int, int) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, 0
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	return uid, gid
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
