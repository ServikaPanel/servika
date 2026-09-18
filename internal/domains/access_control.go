package domains

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"servika/internal/httpx"
	"servika/internal/provisioner"

	"github.com/go-chi/chi/v5"
)

var hotlinkAllowedDomainPattern = regexp.MustCompile(`^\*?\.?[a-zA-Z0-9.-]+$`)

type hotlinkSettings struct {
	Active  bool     `json:"active"`
	Allowed []string `json:"allowed"`
}

type ipRule struct {
	ID        int64  `json:"id"`
	IPCIDR    string `json:"ip_cidr"`
	CreatedAt string `json:"created_at"`
}

var validIPAccessModes = map[string]bool{
	"off":   true,
	"block": true,
	"allow": true,
}

func (h *Handlers) HotlinkStatus(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.accessControlDomainInfo(w, r)
	if !ok {
		return
	}
	var active int
	var allowed string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(hotlink_enabled,0), COALESCE(hotlink_allowed,'') FROM domains WHERE id=?`, id).
		Scan(&active, &allowed); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "hotlink settings could not be read")
		return
	}
	response := hotlinkSettings{Active: active == 1, Allowed: make([]string, 0)}
	for domain := range strings.SplitSeq(allowed, ",") {
		domain = strings.TrimSpace(domain)
		if domain != "" {
			response.Allowed = append(response.Allowed, domain)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, response)
}

func (h *Handlers) SetHotlink(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.accessControlDomainInfo(w, r)
	if !ok {
		return
	}
	var req hotlinkSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	allowed := make([]string, 0, len(req.Allowed))
	for _, domain := range req.Allowed {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		if !hotlinkAllowedDomainPattern.MatchString(domain) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid allowed domain")
			return
		}
		allowed = append(allowed, domain)
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET hotlink_enabled=?, hotlink_allowed=? WHERE id=?`, req.Active, strings.Join(allowed, ","), id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "hotlink settings could not be saved")
		return
	}
	if err := provisioner.RerenderVhost(h.DB, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "virtual host update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handlers) ListIPRules(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.ipScope(w, r)
	if !ok {
		return
	}
	id := scope.id()
	mode, err := scope.readMode(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "IP rules could not be read")
		return
	}
	// #nosec G701 -- listQuery returns one of two compile-time constants; the scope decides WHICH table is read, never what the statement says, and the id is a placeholder.
	rows, err := h.DB.QueryContext(r.Context(), scope.listQuery(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "IP rules could not be read")
		return
	}
	defer func() { _ = rows.Close() }()
	rules := make([]ipRule, 0)
	for rows.Next() {
		var rule ipRule
		if err := rows.Scan(&rule.ID, &rule.IPCIDR, &rule.CreatedAt); err != nil {
			// A dropped rule is one the operator saved and can no longer see, so
			// they cannot remove it either.
			// #nosec G706 -- id is an int64; %d cannot carry a line break into the log.
			httpx.WarnR(r, "ip rules: skipping an unreadable rule for domain %d: %v", id, err)
			continue
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "ip rules read failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"mode": mode, "rules": rules})
}

func (h *Handlers) SetIPRulesMode(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.ipScope(w, r)
	if !ok {
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validIPAccessModes[req.Mode] {
		httpx.WriteError(w, http.StatusBadRequest, "invalid mode")
		return
	}
	if err := scope.saveMode(r.Context(), h.DB, req.Mode); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "IP access mode could not be saved")
		return
	}
	if !h.republish(w, scope) {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handlers) AddIPRule(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.ipScope(w, r)
	if !ok {
		return
	}
	var req struct {
		IPCIDR string `json:"ip_cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ipCIDR, err := cleanIPCIDR(req.IPCIDR)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid IP or CIDR")
		return
	}
	// #nosec G701 -- insertQuery returns one of two compile-time constants; both write only through placeholders, and ipCIDR has already passed net.ParseIP/ParseCIDR.
	if _, err := h.DB.ExecContext(r.Context(), scope.insertQuery(), scope.id(), ipCIDR); err != nil {
		httpx.WriteError(w, http.StatusConflict, "IP rule could not be added")
		return
	}
	if !h.republish(w, scope) {
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"ok": true})
}

func (h *Handlers) DeleteIPRule(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.ipScope(w, r)
	if !ok {
		return
	}
	ruleID, _ := strconv.ParseInt(chi.URLParam(r, "ruleID"), 10, 64)
	// #nosec G701 -- deleteQuery returns one of two compile-time constants; both delete only through placeholders, and ruleID is an int64.
	if _, err := h.DB.ExecContext(r.Context(), scope.deleteQuery(), ruleID, scope.id()); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "IP rule could not be deleted")
		return
	}
	if !h.republish(w, scope) {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ipAccessScope names the site one IP access request acts on: the domain
// itself, or one of its subdomains. A subdomain keeps its own mode and its own
// rules, because a customer who restricts the main site does not thereby
// restrict an API host that must stay open to a payment provider.
type ipAccessScope struct {
	domainID    int64
	subdomainID int64 // 0 means the domain itself
}

// id returns the key every query in this file is parameterised by.
func (s ipAccessScope) id() int64 {
	if s.subdomainID > 0 {
		return s.subdomainID
	}
	return s.domainID
}

func (s ipAccessScope) listQuery() string {
	if s.subdomainID > 0 {
		return `SELECT id, ip_cidr, DATE_FORMAT(created_at,'%Y-%m-%d %H:%i')
		          FROM subdomain_ip_rules WHERE subdomain_id=? ORDER BY id`
	}
	return `SELECT id, ip_cidr, DATE_FORMAT(created_at,'%Y-%m-%d %H:%i')
	          FROM domain_ip_rules WHERE domain_id=? ORDER BY id`
}

func (s ipAccessScope) insertQuery() string {
	if s.subdomainID > 0 {
		return `INSERT INTO subdomain_ip_rules(subdomain_id, ip_cidr) VALUES(?,?)`
	}
	return `INSERT INTO domain_ip_rules(domain_id, ip_cidr) VALUES(?,?)`
}

func (s ipAccessScope) deleteQuery() string {
	if s.subdomainID > 0 {
		return `DELETE FROM subdomain_ip_rules WHERE id=? AND subdomain_id=?`
	}
	return `DELETE FROM domain_ip_rules WHERE id=? AND domain_id=?`
}

// readMode returns the stored mode. A subdomain that has never been restricted
// has no row at all, which is `off`.
func (s ipAccessScope) readMode(ctx context.Context, db *sql.DB) (string, error) {
	var mode string
	if s.subdomainID > 0 {
		err := db.QueryRowContext(ctx,
			`SELECT ip_access_mode FROM subdomain_ip_access WHERE subdomain_id=?`, s.subdomainID).Scan(&mode)
		if errors.Is(err, sql.ErrNoRows) {
			return "off", nil
		}
		return mode, err
	}
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(ip_access_mode,'off') FROM domains WHERE id=?`, s.domainID).Scan(&mode)
	return mode, err
}

func (s ipAccessScope) saveMode(ctx context.Context, db *sql.DB, mode string) error {
	if s.subdomainID > 0 {
		_, err := db.ExecContext(ctx,
			`INSERT INTO subdomain_ip_access(subdomain_id, ip_access_mode) VALUES(?,?)
			 ON DUPLICATE KEY UPDATE ip_access_mode=VALUES(ip_access_mode)`, s.subdomainID, mode)
		return err
	}
	_, err := db.ExecContext(ctx, `UPDATE domains SET ip_access_mode=? WHERE id=?`, mode, s.domainID)
	return err
}

// ipScope resolves the request onto a scope and proves the caller owns it. A
// {sid} that names a subdomain of another domain is a 404, so the URL cannot be
// used to read or change a site the caller's domain scope does not cover.
func (h *Handlers) ipScope(w http.ResponseWriter, r *http.Request) (ipAccessScope, bool) {
	id, _, _, ok := h.accessControlDomainInfo(w, r)
	if !ok {
		return ipAccessScope{}, false
	}
	raw := chi.URLParam(r, "sid")
	if raw == "" {
		return ipAccessScope{domainID: id}, true
	}
	sid, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid subdomain")
		return ipAccessScope{}, false
	}
	var found int64
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT id FROM subdomains WHERE id=? AND domain_id=?`, sid, id).Scan(&found); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "subdomain not found")
		return ipAccessScope{}, false
	}
	return ipAccessScope{domainID: id, subdomainID: found}, true
}

// republish rewrites the vhost the change belongs to and answers the caller when
// it fails. A saved rule that never reached nginx is a restriction the operator
// believes is in force and is not.
func (h *Handlers) republish(w http.ResponseWriter, scope ipAccessScope) bool {
	if scope.subdomainID > 0 {
		if h.RerenderSubdomain == nil {
			httpx.WriteError(w, http.StatusInternalServerError, "virtual host update failed")
			return false
		}
		if err := h.RerenderSubdomain(h.DB, scope.subdomainID); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "virtual host update failed")
			return false
		}
		return true
	}
	if err := provisioner.RerenderVhost(h.DB, scope.domainID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "virtual host update failed")
		return false
	}
	return true
}

func (h *Handlers) accessControlDomainInfo(w http.ResponseWriter, r *http.Request) (int64, string, string, bool) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var systemUser, phpVersion string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, COALESCE(php_version,'8.3') FROM domains WHERE id=?`, id).
		Scan(&systemUser, &phpVersion)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return 0, "", "", false
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return 0, "", "", false
	}
	return id, systemUser, phpVersion, true
}

func cleanIPCIDR(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("empty IP")
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		return "", err
	}
	if ip.To4() != nil {
		return network.String(), nil
	}
	return network.String(), nil
}
