// Package firewall provides a panel-managed nftables firewall (inet servika_fw).
//
// Security design:
//   - The table policy is ACCEPT, so no traffic is blocked when no rule exists.
//   - "ct state established,related accept" comes first, so active sessions, including SSH,
//     are never interrupted. Rules affect only new connections and avoid immediate lockout.
//   - Critical ports for SSH, web, panel, and DNS cannot be closed.
//   - "nft -c" validates rules before applying them, following the nginx -t pattern.
//   - Rules persist in /etc/nftables/servika_fw.nft and Reapply runs at panel startup.
package firewall

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"

	"servika/internal/httpx"
	"servika/internal/system"

	"github.com/go-chi/chi/v5"
)

const (
	tableName = "servika_fw"
	rulesFile = "/etc/nftables/servika_fw.nft"
	// The range internal/apps allocates tenant application ports from. It is
	// repeated here rather than imported so the firewall does not depend on the
	// application package; internal/apps.PortMin/PortMax must match.
	appPortMin = 30000
	appPortMax = 30999
)

// Protected ports cannot be closed without disrupting the server, panel, or hosted sites.
// SSH is deliberately NOT listed here: the port it serves is read from sshd, so
// that an administrator who moves it keeps the guard on the port in use and can
// close 22, which is exactly what the panel's own warning asks them to do.
var protectedPorts = map[int]bool{
	80:   true, // Customer sites over HTTP.
	443:  true, // Customer sites over HTTPS.
	8080: true, // Panel API.
	8443: true, // Panel UI.
	53:   true, // DNS through named.
}

// sshPorts is a package variable so tests can stand in for the host probe.
// It falls back to port 22 when sshd cannot be asked, so a failed detection
// keeps the old guard rather than dropping it.
var sshPorts = system.SSHPorts

// isProtectedPort reports whether closing this port would cut off the server, the
// panel, hosted sites, or the administrator's own SSH session.
func isProtectedPort(port int) bool {
	return protectedPorts[port] || slices.Contains(sshPorts(), port)
}

// protectedPortList is what the firewall screen greys out.
func protectedPortList() []int {
	ports := make([]int, 0, len(protectedPorts)+1)
	for port := range protectedPorts {
		ports = append(ports, port)
	}
	for _, port := range sshPorts() {
		if !protectedPorts[port] {
			ports = append(ports, port)
		}
	}
	slices.Sort(ports)
	return ports
}

// firewallTemplates contains ready-to-use rule sets that close commonly exposed ports.
// Templates must never include critical ports from protectedPorts.
type templateRule struct {
	Type, Protocol, Description string
	Port                        int
}

var firewallTemplates = map[string][]templateRule{
	"close_mysql": {
		{"close", "tcp", "Template: MySQL closed to external access", 3306},
	},
	"close_ftp": {
		{"close", "tcp", "Template: FTP closed to external access", 21},
	},
	"close_mail": {
		{"close", "tcp", "Template: SMTP closed", 25},
		{"close", "tcp", "Template: SMTPS closed", 465},
		{"close", "tcp", "Template: Submission closed", 587},
		{"close", "tcp", "Template: POP3 closed", 110},
		{"close", "tcp", "Template: IMAP closed", 143},
	},
	"close_rpc": {
		{"close", "tcp", "Template: rpcbind closed", 111},
		{"close", "tcp", "Template: NFS closed", 2049},
	},
}

// Handlers provides HTTP handlers for firewall rule operations.
type Handlers struct{ DB *sql.DB }

// Rule describes a persisted firewall rule.
type Rule struct {
	ID          int64  `json:"id"`
	Type        string `json:"type"`
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at"`
}

// GET /firewall returns rules and protected ports.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, type, ip, port, protocol, description, enabled, DATE_FORMAT(created_at,'%Y-%m-%d %H:%i')
		 FROM firewall_rules ORDER BY id DESC`)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "rules could not be listed")
		return
	}
	defer func() { _ = rows.Close() }()
	out := []Rule{}
	for rows.Next() {
		var rule Rule
		var enabled int
		if err := rows.Scan(&rule.ID, &rule.Type, &rule.IP, &rule.Port, &rule.Protocol, &rule.Description, &enabled, &rule.CreatedAt); err == nil {
			rule.Enabled = enabled == 1
			out = append(out, rule)
		}
	}
	_ = rows.Err()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"rules": out, "protected_ports": protectedPortList()})
}

// POST /firewall  {type, ip, port, protocol, description}
func (h *Handlers) Add(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type        string `json:"type"`
		IP          string `json:"ip"`
		Port        int    `json:"port"`
		Protocol    string `json:"protocol"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	req.IP = strings.TrimSpace(req.IP)
	req.Protocol = strings.ToLower(strings.TrimSpace(req.Protocol))
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	if req.Protocol != "tcp" && req.Protocol != "udp" {
		httpx.WriteError(w, http.StatusBadRequest, "protocol must be tcp or udp")
		return
	}
	if req.Port < 0 || req.Port > 65535 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid port (0-65535)")
		return
	}

	switch req.Type {
	case "banned", "whitelist":
		if !validIP(req.IP) {
			httpx.WriteError(w, http.StatusBadRequest, "enter a valid IP address or CIDR (for example, 1.2.3.4 or 1.2.3.0/24)")
			return
		}
	case "close":
		if req.Port == 0 {
			httpx.WriteError(w, http.StatusBadRequest, "specify a port to close")
			return
		}
		if isProtectedPort(req.Port) {
			httpx.WriteError(w, http.StatusBadRequest,
				fmt.Sprintf("port %d is critical for SSH, web, panel, or DNS access and cannot be closed", req.Port))
			return
		}
		req.IP = "" // Closing a port blocks everyone.
	default:
		httpx.WriteError(w, http.StatusBadRequest, "type must be banned, whitelist, or closed")
		return
	}
	// A banned may block one IP from a critical port to stop an attacker. Active sessions
	// remain protected by established-accept. Combining all ports with a critical management IP
	// is risky, so the UI warns. A port-zero banned does not override an earlier whitelist rule.

	res, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO firewall_rules (type, ip, port, protocol, description, enabled) VALUES (?,?,?,?,?,1)`,
		req.Type, req.IP, req.Port, req.Protocol, req.Description)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "rule could not be added")
		return
	}
	nid, _ := res.LastInsertId()

	if err := h.rebuild(); err != nil {
		// Roll back the record when applying the rules fails.
		_, _ = h.DB.Exec(`DELETE FROM firewall_rules WHERE id=?`, nid)
		_ = h.rebuild()
		httpx.WriteError(w, http.StatusInternalServerError, "firewall rules could not be applied")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"ok": true, "id": nid})
}

// POST /firewall/template applies a predefined rule set idempotently.
func (h *Handlers) Template(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Template string `json:"template"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	rules, ok := firewallTemplates[req.Template]
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "unknown template")
		return
	}
	added := 0
	for _, rule := range rules {
		if isProtectedPort(rule.Port) { // Skip critical ports even though templates must not contain them.
			continue
		}
		var count int
		_ = h.DB.QueryRow(`SELECT COUNT(*) FROM firewall_rules WHERE type=? AND port=? AND protocol=? AND ip=''`,
			rule.Type, rule.Port, rule.Protocol).Scan(&count)
		if count > 0 { // Skip existing rules to preserve idempotency.
			continue
		}
		if _, err := h.DB.ExecContext(r.Context(),
			`INSERT INTO firewall_rules (type, ip, port, protocol, description, enabled) VALUES (?,'',?,?,?,1)`,
			rule.Type, rule.Port, rule.Protocol, rule.Description); err == nil {
			added++
		}
	}
	if err := h.rebuild(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "firewall rules could not be applied")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "added": added})
}

// DELETE /firewall/{id}
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM firewall_rules WHERE id=?`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "rule could not be deleted")
		return
	}
	if err := h.rebuild(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "firewall rules could not be updated")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /firewall/{id}/status updates the active state.
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	enabled := 0
	if req.Enabled {
		enabled = 1
	}
	if _, err := h.DB.ExecContext(r.Context(), `UPDATE firewall_rules SET enabled=? WHERE id=?`, enabled, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "rule could not be updated")
		return
	}
	if err := h.rebuild(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "firewall rules could not be updated")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// rebuild generates an nft ruleset from active rules, validates it, applies it, and persists it.
func (h *Handlers) rebuild() error {
	rows, err := h.DB.Query(`SELECT type, ip, port, protocol FROM firewall_rules WHERE enabled=1 ORDER BY
		FIELD(type,'whitelist','close','banned'), id`)
	if err != nil {
		return err
	}
	var allowlisted, closed, banned []string
	// A port-specific whitelist rule puts that port into allowlist mode.
	// A "proto dport P drop" rule follows the corresponding "ip saddr X dport P accept" rules,
	// allowing only listed IP addresses to access that port.
	// Sort "proto/port" keys for deterministic output.
	restrictedPorts := map[string]bool{}
	for rows.Next() {
		var ruleType, ip, proto string
		var port int
		if err := rows.Scan(&ruleType, &ip, &port, &proto); err != nil {
			continue
		}
		switch ruleType {
		case "whitelist":
			allowlisted = append(allowlisted, "\t\t"+saddr(ip)+dport(proto, port)+"accept")
			if port > 0 { // A port-specific permission enables allowlist mode for that port.
				restrictedPorts[proto+"/"+strconv.Itoa(port)] = true
			}
		case "close":
			closed = append(closed, "\t\t"+proto+" dport "+strconv.Itoa(port)+" drop")
		case "banned":
			banned = append(banned, "\t\t"+saddr(ip)+dport(proto, port)+"drop")
		}
	}
	_ = rows.Err()
	_ = rows.Close()

	// Allowlist drops come after permitted IP accepts and before close or banned rules.
	// Since established,related and lo come first, active sessions and SSH are not interrupted.
	restrictedKeys := make([]string, 0, len(restrictedPorts))
	for key := range restrictedPorts {
		restrictedKeys = append(restrictedKeys, key)
	}
	sort.Strings(restrictedKeys)
	var restricted []string
	for _, key := range restrictedKeys {
		if i := strings.IndexByte(key, '/'); i > 0 {
			restricted = append(restricted, "\t\t"+key[:i]+" dport "+key[i+1:]+" drop")
		}
	}

	// The element file is regenerated first: nft validates the include as part
	// of the document below, so a stale file would be what gets checked.
	if err := writeGeoSets(context.Background(), h.DB); err != nil {
		return err
	}

	remote, err := h.remoteAccess()
	if err != nil {
		return err
	}

	ruleset := buildRuleset(allowlisted, restricted, closed, banned, remote)

	// 1. Validate so an invalid ruleset is never applied.
	if out, err := nftCheck(ruleset); err != nil {
		return fmt.Errorf("nft validation failed: %s", strings.TrimSpace(out))
	}
	// 2. Apply the ruleset.
	if out, err := nftApply(ruleset); err != nil {
		return fmt.Errorf("nft apply failed: %s", strings.TrimSpace(out))
	}
	// 3. Persist the ruleset so panel startup can reload it after reboot.
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	_ = os.MkdirAll("/etc/nftables", 0o755)
	_ = os.WriteFile(rulesFile, ruleset, 0o600)
	return nil
}

// buildRuleset renders the nft ruleset text.
//
// It is a pure function so the ORDER of the base rules can be asserted: the
// chain is `policy accept`, so every restriction here is an explicit drop, and a
// drop placed before the loopback accept above it would cut nginx off from the
// service it is meant to reach.
// remoteAccess reads the per-account remote MySQL allowlist.
//
// It fails CLOSED in the sense that matters: a read error aborts the whole
// rebuild rather than producing a ruleset with the port open and no accepts,
// which would be a listener exposed to everybody.
func (h *Handlers) remoteAccess() (remoteAccess, error) {
	var enabled int
	err := h.DB.QueryRow(`SELECT COALESCE(db_remote_enabled,0) FROM panel_settings WHERE id=1`).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return remoteAccess{}, nil
	}
	if err != nil {
		return remoteAccess{}, fmt.Errorf("remote database switch: %w", err)
	}
	if enabled != 1 {
		return remoteAccess{}, nil
	}

	rows, err := h.DB.Query(`SELECT DISTINCT host_cidr FROM db_remote_hosts ORDER BY host_cidr`)
	if err != nil {
		return remoteAccess{}, fmt.Errorf("remote database hosts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	access := remoteAccess{enabled: true}
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return remoteAccess{}, err
		}
		// A stored value that is not an address is dropped rather than rendered:
		// nft would refuse the whole document, which takes every other rule down
		// with it, including the drop this block depends on.
		if !validIP(host) {
			log.Printf("firewall: ignoring unusable remote database host %q", host)
			continue
		}
		access.accepts = append(access.accepts, "\t\t"+saddr(host)+"tcp dport 3306 accept")
	}
	if err := rows.Err(); err != nil {
		return remoteAccess{}, err
	}
	return access, nil
}

// remoteAccess is the per-account remote MySQL allowlist, rendered as its own
// block rather than as `firewall_rules` rows.
//
// It is derived state owned by internal/dbremote: an operator deleting a row
// from the firewall screen would silently break a customer's access, and the
// next rebuild would put it back, so the two never share a table.
type remoteAccess struct {
	// enabled mirrors panel_settings.db_remote_enabled. The drop comes with the
	// LISTENER: while the switch is off MariaDB binds loopback and there is
	// nothing to drop, and emitting the rule anyway would cut off an operator who
	// configured their own remote MariaDB outside the panel.
	enabled bool
	// accepts are the rendered `<family> saddr <addr> tcp dport 3306 accept`
	// lines, one per allowed source.
	accepts []string
}

func buildRuleset(allowlisted, restricted, closed, banned []string, remote remoteAccess) []byte {
	var b bytes.Buffer
	// Replace atomically and idempotently by ensuring, deleting, and rebuilding the table.
	fmt.Fprintf(&b, "table inet %s {}\n", tableName)
	fmt.Fprintf(&b, "delete table inet %s\n", tableName)
	fmt.Fprintf(&b, "table inet %s {\n", tableName)
	// The country element lists are included rather than inlined: one country
	// is thousands of intervals, and keeping them out of this function is what
	// leaves the base-rule ORDER above assertable in a unit test.
	fmt.Fprintf(&b, "\tinclude \"%s\"\n", geoIncludeFile)
	b.WriteString("\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority filter; policy accept;\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tiif \"lo\" accept\n")
	// Tenant applications listen on a loopback port, but nothing FORCES them to:
	// the address a Node or Python process binds is the application's own choice.
	// This chain is policy accept, so an application binding 0.0.0.0 would be
	// reachable straight from the internet, past nginx, TLS, the WAF and the
	// per-domain IP rules. The drop comes after the loopback accept above, so
	// nginx still reaches the application.
	fmt.Fprintf(&b, "\t\ttcp dport %d-%d drop\n", appPortMin, appPortMax)
	// Country blocks drop BEFORE the whitelist accepts below, so a per-IP
	// permission cannot reopen a country the operator closed. That is the
	// stricter reading and the one the screen states: an operator who wants one
	// address back from a blocked country has to unblock the country.
	fmt.Fprintf(&b, "\t\tip saddr @%s drop\n", geoSetV4)
	fmt.Fprintf(&b, "\t\tip6 saddr @%s drop\n", geoSetV6)
	// Ordering matters: whitelist accepts, allowlist drops, closed-port drops, then banned drops.
	for _, r := range allowlisted {
		fmt.Fprintf(&b, "%s\n", r)
	}
	for _, r := range restricted {
		fmt.Fprintf(&b, "%s\n", r)
	}
	for _, r := range closed {
		fmt.Fprintf(&b, "%s\n", r)
	}
	for _, r := range banned {
		fmt.Fprintf(&b, "%s\n", r)
	}
	// The remote database allowlist comes LAST, after the country drops, the
	// operator's own rules and the bans. The chain is `policy accept`, so the
	// first matching rule wins: an address the operator blocked by country or by
	// ban must not get back in because a customer allowed it to their database.
	//
	// The drop is emitted whenever the switch is on, even with an empty
	// allowlist. Without it the port that has just been opened is reachable by
	// the whole internet, so this single line is the entire boundary.
	if remote.enabled {
		for _, r := range remote.accepts {
			fmt.Fprintf(&b, "%s\n", r)
		}
		b.WriteString("\t\ttcp dport 3306 drop\n")
	}
	b.WriteString("\t}\n}\n")
	return b.Bytes()
}

// Reapply restores rules from the database when the panel starts after a reboot.
func Reapply(db *sql.DB) error {
	h := &Handlers{DB: db}
	return h.rebuild()
}

// TakeOverFirewalld disables the default AlmaLinux/RHEL firewalld service.
// Servika manages its own nftables table, and firewalld can install terminal
// drop rules that conflict with panel-managed accepts for web, DNS, FTP, and panel ports.
func TakeOverFirewalld() {
	if exec.Command("systemctl", "cat", "firewalld.service").Run() != nil {
		return
	}
	if output, _ := exec.Command("systemctl", "is-enabled", "firewalld").Output(); strings.TrimSpace(string(output)) == "masked" {
		return
	}
	_ = exec.Command("systemctl", "disable", "--now", "firewalld").Run()
	_ = exec.Command("systemctl", "mask", "firewalld").Run()
	log.Printf("firewall: firewalld stopped and masked; Servika nftables is the active firewall")
}

// --- Helpers ---

func validIP(s string) bool {
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// saddr returns an IPv4 or IPv6 source-address expression for an IP or CIDR.
func saddr(ip string) string {
	fam := "ip"
	host := ip
	if before, _, found := strings.Cut(ip, "/"); found {
		host = before
	}
	if p := net.ParseIP(host); p != nil && p.To4() == nil {
		fam = "ip6"
	}
	return fam + " saddr " + ip + " "
}

// dport returns a destination-port expression for a positive port, or empty for all ports.
func dport(proto string, port int) string {
	if port <= 0 {
		return ""
	}
	return proto + " dport " + strconv.Itoa(port) + " "
}

func nftCheck(ruleset []byte) (string, error) {
	cmd := exec.Command("nft", "-c", "-f", "-")
	cmd.Stdin = bytes.NewReader(ruleset)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func nftApply(ruleset []byte) (string, error) {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewReader(ruleset)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
