package domains

import (
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
	id, _, _, ok := h.accessControlDomainInfo(w, r)
	if !ok {
		return
	}
	var mode string
	if err := h.DB.QueryRowContext(r.Context(), `SELECT COALESCE(ip_access_mode,'off') FROM domains WHERE id=?`, id).Scan(&mode); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "IP rules could not be read")
		return
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, ip_cidr, DATE_FORMAT(created_at,'%Y-%m-%d %H:%i') FROM domain_ip_rules WHERE domain_id=? ORDER BY id`, id)
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
			httpx.LogR(r, "ip rules: skipping an unreadable rule for domain %d: %v", id, err)
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
	id, _, _, ok := h.accessControlDomainInfo(w, r)
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
	if _, err := h.DB.ExecContext(r.Context(), `UPDATE domains SET ip_access_mode=? WHERE id=?`, req.Mode, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "IP access mode could not be saved")
		return
	}
	if err := provisioner.RerenderVhost(h.DB, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "virtual host update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handlers) AddIPRule(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.accessControlDomainInfo(w, r)
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
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO domain_ip_rules(domain_id, ip_cidr) VALUES(?,?)`, id, ipCIDR); err != nil {
		httpx.WriteError(w, http.StatusConflict, "IP rule could not be added")
		return
	}
	if err := provisioner.RerenderVhost(h.DB, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "virtual host update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"ok": true})
}

func (h *Handlers) DeleteIPRule(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.accessControlDomainInfo(w, r)
	if !ok {
		return
	}
	ruleID, _ := strconv.ParseInt(chi.URLParam(r, "ruleID"), 10, 64)
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM domain_ip_rules WHERE id=? AND domain_id=?`, ruleID, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "IP rule could not be deleted")
		return
	}
	if err := provisioner.RerenderVhost(h.DB, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "virtual host update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
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
