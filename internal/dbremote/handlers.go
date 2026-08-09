package dbremote

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"servika/internal/credentials"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// Stable reason codes. The API is English and the panel renders twelve
// languages, so a screen maps the CODE to a sentence rather than showing the
// message.
const (
	reasonServerDisabled   = "db_remote_server_disabled"
	reasonHostInvalid      = "db_remote_host_invalid"
	reasonIPv6Range        = "db_remote_ipv6_range_unsupported"
	reasonHostTooBroad     = "db_remote_host_too_broad"
	reasonPortRuleConflict = "db_remote_port_rule_conflict"
	reasonDuplicate        = "db_remote_duplicate"
	reasonApplyFailed      = "db_remote_apply_failed"
	reasonUnknownUser      = "db_remote_unknown_user"
)

// applyTimeout bounds a switch flip. It is generous because it covers a MariaDB
// restart plus the verification that follows it.
const applyTimeout = 3 * time.Minute

// Handlers serves the remote database access surface.
type Handlers struct {
	DB *sql.DB
	// RebuildFirewall re-renders the nftables ruleset. It is a function rather
	// than an import so this package does not depend on internal/firewall, which
	// reads this package's table.
	RebuildFirewall func() error
}

// Host is one allowed source address as a screen reads it.
type Host struct {
	ID        int64  `json:"id"`
	DomainID  int64  `json:"domain_id"`
	Domain    string `json:"domain_name,omitempty"`
	DBUser    string `json:"db_user"`
	Host      string `json:"host"`
	Label     string `json:"label"`
	CreatedAt string `json:"created_at"`
}

// ServerStatus describes the feature itself, so a screen can explain why adding
// an address is refused instead of just failing.
type ServerStatus struct {
	Enabled bool `json:"enabled"`
	// Port is fixed but travels in the response so the screen never hardcodes it
	// into a connection string it shows a customer.
	Port int `json:"port"`
	// PortRuleConflict names the firewall rule that would defeat the feature, so
	// an admin is told what to remove rather than watching the switch refuse.
	PortRuleConflict bool   `json:"port_rule_conflict"`
	LastError        string `json:"last_error,omitempty"`
	AppliedAt        string `json:"applied_at,omitempty"`
	Hosts            []Host `json:"hosts"`
}

// mysqlPort is the only port this feature opens. It is a constant rather than a
// setting because the firewall rule, the grant and the connection string a
// screen shows all have to agree, and nothing about a second port is supported.
const mysqlPort = 3306

// ServerGet answers the admin view: the switch, what would defeat it, and every
// address allowed anywhere on the server.
func (h *Handlers) ServerGet(w http.ResponseWriter, r *http.Request) {
	status, err := h.serverStatus(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the remote access settings")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, status)
}

type switchRequest struct {
	Enabled *bool `json:"enabled"`
}

// ServerSet flips the switch, which rewrites the bind and restarts MariaDB.
//
// Admin only, and deliberately so: this restart drops every site's open database
// connections, which is not something a single customer's checkbox may cause.
func (h *Handlers) ServerSet(w http.ResponseWriter, r *http.Request) {
	var request switchRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if request.Enabled == nil {
		httpx.WriteError(w, http.StatusBadRequest, "enabled is required")
		return
	}

	// A manual rule on the database port is refused on the WRITE path, not only
	// where the screen draws the switch. Such a rule is rendered ABOVE this
	// feature's block, so it would win silently and leave the screen saying
	// remote access is on while every connection was dropped.
	if *request.Enabled {
		conflict, err := h.portRuleConflict(r.Context())
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not check the firewall rules")
			return
		}
		if conflict {
			writeReason(w, http.StatusConflict,
				"a firewall rule already targets port 3306; remove it before opening remote access",
				reasonPortRuleConflict)
			return
		}
	}

	// Detached from the request: the restart outlasts a client that hangs up,
	// and abandoning it half way is what leaves the bind and the switch
	// disagreeing.
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()

	if err := Apply(ctx, h.DB, *request.Enabled); err != nil {
		h.recordError(r.Context(), err.Error())
		writeReason(w, http.StatusInternalServerError,
			"MariaDB could not be restarted with the new setting, so nothing was changed",
			reasonApplyFailed)
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE panel_settings
		    SET db_remote_enabled=?, db_remote_last_error='', db_remote_applied_at=NOW()
		  WHERE id=1`, boolToInt(*request.Enabled)); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save the remote access setting")
		return
	}
	// The firewall follows the switch: turning it on without the drop leaves the
	// port open to everybody, and leaving the drop behind after turning it off
	// blocks nothing but is still wrong state.
	if err := h.rebuild(); err != nil {
		log.Printf("remote db: firewall rebuild after the switch: %v", err)
	}
	h.ServerGet(w, r)
}

// DomainList answers one domain's view.
func (h *Handlers) DomainList(w http.ResponseWriter, r *http.Request) {
	domainID, ok := domainParam(w, r)
	if !ok {
		return
	}
	hosts, err := h.hosts(r.Context(), domainID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the remote access list")
		return
	}
	enabled, err := readSwitch(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the remote access settings")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, ServerStatus{Enabled: enabled, Port: mysqlPort, Hosts: hosts})
}

type addRequest struct {
	DBUser string `json:"db_user"`
	Host   string `json:"host"`
	Label  string `json:"label"`
}

// DomainAdd allows one address to reach one database account.
//
// The order is deliberate: validate, then grant, then record, then open the
// port. A row written before the grant would show a customer an access that does
// not exist, and a port opened before the grant would be open for nothing.
func (h *Handlers) DomainAdd(w http.ResponseWriter, r *http.Request) {
	domainID, ok := domainParam(w, r)
	if !ok {
		return
	}
	var request addRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	enabled, err := readSwitch(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the remote access settings")
		return
	}
	if !enabled {
		writeReason(w, http.StatusConflict,
			"remote database access is switched off for this server", reasonServerDisabled)
		return
	}

	cidr, mysqlHost, err := ParseHost(request.Host)
	if err != nil {
		writeReason(w, http.StatusBadRequest, hostMessage(err), hostReason(err))
		return
	}

	// The account must belong to THIS domain. The route is CustomerScope, so the
	// caller owns the domain in the URL; without this check they could still name
	// a neighbour's database user and open it to an address of their choosing.
	password, databases, err := h.accountFor(r.Context(), domainID, request.DBUser)
	if errors.Is(err, sql.ErrNoRows) {
		writeReason(w, http.StatusBadRequest,
			"that database user does not belong to this domain", reasonUnknownUser)
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the database account")
		return
	}

	if err := credentials.MySQLGrantRemote(request.DBUser, mysqlHost, password, databases); err != nil {
		log.Printf("remote db: grant %s@%s: %v", request.DBUser, mysqlHost, err)
		writeReason(w, http.StatusInternalServerError,
			"MariaDB did not accept the remote account", reasonApplyFailed)
		return
	}

	_, err = h.DB.ExecContext(r.Context(),
		`INSERT INTO db_remote_hosts (domain_id, db_user, host_cidr, mysql_host, label)
		 VALUES (?,?,?,?,?)`,
		domainID, request.DBUser, cidr, mysqlHost, trimLabel(request.Label))
	if err != nil {
		// The grant is undone rather than left behind: an account reachable from
		// an address the panel has no record of is a credential nobody can find.
		if revokeErr := credentials.MySQLRevokeRemote(request.DBUser, mysqlHost); revokeErr != nil {
			log.Printf("remote db: could not undo the grant for %s@%s: %v", request.DBUser, mysqlHost, revokeErr)
		}
		if isDuplicate(err) {
			writeReason(w, http.StatusConflict, "that address is already allowed", reasonDuplicate)
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "could not save the remote access entry")
		return
	}

	if err := h.rebuild(); err != nil {
		log.Printf("remote db: firewall rebuild after an add: %v", err)
		writeReason(w, http.StatusInternalServerError,
			"the firewall could not be updated, so the address was not opened", reasonApplyFailed)
		return
	}
	h.DomainList(w, r)
}

// DomainDelete withdraws one address.
//
// The order is the reverse of adding: close the port first, then remove the
// account, then the row. Anything else leaves a window in which the credential
// still works from an address the panel says is gone.
func (h *Handlers) DomainDelete(w http.ResponseWriter, r *http.Request) {
	domainID, ok := domainParam(w, r)
	if !ok {
		return
	}
	hostID, err := strconv.ParseInt(chi.URLParam(r, "hid"), 10, 64)
	if err != nil || hostID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid host id")
		return
	}

	var dbUser, mysqlHost string
	err = h.DB.QueryRowContext(r.Context(),
		`SELECT db_user, mysql_host FROM db_remote_hosts WHERE id=? AND domain_id=?`,
		hostID, domainID).Scan(&dbUser, &mysqlHost)
	if errors.Is(err, sql.ErrNoRows) {
		httpx.WriteError(w, http.StatusNotFound, "remote access entry not found")
		return
	}
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the remote access entry")
		return
	}

	if _, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM db_remote_hosts WHERE id=? AND domain_id=?`, hostID, domainID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not remove the remote access entry")
		return
	}
	// The port closes first, from the row set that no longer carries this
	// address.
	if err := h.rebuild(); err != nil {
		log.Printf("remote db: firewall rebuild after a delete: %v", err)
	}
	// The stored mysql_host is used verbatim: deriving it again here would fail
	// to drop an account written under an earlier conversion.
	if err := credentials.MySQLRevokeRemote(dbUser, mysqlHost); err != nil {
		log.Printf("remote db: could not drop %s@%s: %v", dbUser, mysqlHost, err)
		writeReason(w, http.StatusInternalServerError,
			"the address was removed but MariaDB still holds the account", reasonApplyFailed)
		return
	}
	h.DomainList(w, r)
}

// serverStatus reads everything the admin screen shows.
func (h *Handlers) serverStatus(ctx context.Context) (ServerStatus, error) {
	status := ServerStatus{Port: mysqlPort, Hosts: []Host{}}

	var enabled int
	var lastError, appliedAt sql.NullString
	err := h.DB.QueryRowContext(ctx,
		`SELECT COALESCE(db_remote_enabled,0), COALESCE(db_remote_last_error,''),
		        DATE_FORMAT(db_remote_applied_at, '%Y-%m-%d %H:%i:%s')
		   FROM panel_settings WHERE id=1`).Scan(&enabled, &lastError, &appliedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return status, err
	}
	status.Enabled = enabled == 1
	status.LastError = lastError.String
	status.AppliedAt = appliedAt.String

	if status.PortRuleConflict, err = h.portRuleConflict(ctx); err != nil {
		return status, err
	}
	hosts, err := h.hosts(ctx, 0)
	if err != nil {
		return status, err
	}
	status.Hosts = hosts
	return status, nil
}

// hosts lists the allowed addresses. domainID 0 means the whole server.
func (h *Handlers) hosts(ctx context.Context, domainID int64) ([]Host, error) {
	statement := `SELECT h.id, h.domain_id, COALESCE(d.domain_name,''), h.db_user, h.host_cidr,
	                     h.label, DATE_FORMAT(h.created_at,'%Y-%m-%d %H:%i')
	                FROM db_remote_hosts h
	                LEFT JOIN domains d ON d.id = h.domain_id`
	var args []any
	if domainID > 0 {
		statement += " WHERE h.domain_id = ?"
		args = append(args, domainID)
	}
	statement += " ORDER BY h.db_user, h.host_cidr"

	rows, err := h.DB.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	hosts := []Host{}
	for rows.Next() {
		var host Host
		if err := rows.Scan(&host.ID, &host.DomainID, &host.Domain, &host.DBUser,
			&host.Host, &host.Label, &host.CreatedAt); err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	return hosts, rows.Err()
}

// accountFor returns the account's password and every schema it owns, but only
// when the account belongs to the domain in the URL.
func (h *Handlers) accountFor(ctx context.Context, domainID int64, dbUser string) (string, []string, error) {
	if !credentials.ValidDBIdentifier(dbUser) {
		return "", nil, sql.ErrNoRows
	}
	rows, err := h.DB.QueryContext(ctx,
		`SELECT db_name, db_pass_plain FROM db_accounts WHERE domain_id=? AND db_user=?`,
		domainID, dbUser)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = rows.Close() }()

	var databases []string
	var stored string
	for rows.Next() {
		var name, pass string
		if err := rows.Scan(&name, &pass); err != nil {
			return "", nil, err
		}
		databases = append(databases, name)
		stored = pass
	}
	if err := rows.Err(); err != nil {
		return "", nil, err
	}
	if len(databases) == 0 {
		return "", nil, sql.ErrNoRows
	}
	password, err := credentials.DecryptDBPass(dbUser, stored)
	if err != nil {
		return "", nil, err
	}
	return password, databases, nil
}

// portRuleConflict reports whether an operator's own firewall rule targets the
// database port. Such a rule is rendered above this feature's block, so it wins.
func (h *Handlers) portRuleConflict(ctx context.Context) (bool, error) {
	var count int
	err := h.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM firewall_rules
		  WHERE enabled=1 AND port=? AND type IN ('close','whitelist')`, mysqlPort).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// recordError stores why the last apply failed, so the screen can say it rather
// than only reporting that something went wrong.
func (h *Handlers) recordError(ctx context.Context, message string) {
	const limit = 255
	if len(message) > limit {
		message = message[:limit]
	}
	if _, err := h.DB.ExecContext(ctx,
		`UPDATE panel_settings SET db_remote_last_error=? WHERE id=1`, message); err != nil {
		log.Printf("remote db: could not record the failure: %v", err)
	}
}

func (h *Handlers) rebuild() error {
	if h.RebuildFirewall == nil {
		return nil
	}
	return h.RebuildFirewall()
}

func domainParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	domainID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || domainID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid domain id")
		return 0, false
	}
	return domainID, true
}

// hostReason maps a parse failure to the code a screen renders. The IPv6 range
// gets its own: the input is a valid range and the refusal is a MariaDB
// limitation, so telling the customer it is invalid sends them looking for a
// typo that is not there.
func hostReason(err error) string {
	switch {
	case errors.Is(err, ErrIPv6RangeUnsupported):
		return reasonIPv6Range
	case errors.Is(err, ErrHostTooBroad):
		return reasonHostTooBroad
	default:
		return reasonHostInvalid
	}
}

func hostMessage(err error) string {
	switch {
	case errors.Is(err, ErrIPv6RangeUnsupported):
		return "MariaDB cannot match an IPv6 range; enter a single IPv6 address"
	case errors.Is(err, ErrHostTooBroad):
		return "that range is too broad to be an allowlist entry"
	default:
		return "enter an IP address or a CIDR range"
	}
}

// isDuplicate reports whether the insert hit the UNIQUE key.
//
// The driver's error is matched by TEXT because the repository carries no
// driver-specific error type, and the alternative, a SELECT before the insert,
// races two customers adding the same address.
func isDuplicate(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Duplicate entry")
}

func trimLabel(label string) string {
	const limit = 64
	if len(label) > limit {
		return label[:limit]
	}
	return label
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// writeReason answers with the panel's error shape plus a stable reason CODE.
func writeReason(w http.ResponseWriter, status int, message, reason string) {
	httpx.WriteJSON(w, status, map[string]string{"error": message, "reason": reason})
}
