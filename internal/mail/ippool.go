package mail

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"servika/internal/config"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// Outbound addresses.
//
// Every domain sent from the same address, so one customer's reputation was
// every customer's reputation: a single spam run put the whole machine on a
// blocklist and there was nowhere to move a complaining customer to.
//
// Two things are measured rather than assumed. Reverse DNS is checked when an
// address is added, because an address whose PTR does not forward-confirm is
// refused by most large providers and adding it silently makes delivery worse,
// not better. Blocklist state is scanned in the background, because a panel
// request must not hang on a slow blocklist.

// PoolAddress is one outbound address as the API speaks it.
type PoolAddress struct {
	ID          int64  `json:"id"`
	IP          string `json:"ip"`
	Enabled     bool   `json:"enabled"`
	Note        string `json:"note,omitempty"`
	PTRName     string `json:"ptr_name,omitempty"`
	PTROK       bool   `json:"ptr_ok"`
	DNSBLListed bool   `json:"dnsbl_listed"`
	DNSBLZones  string `json:"dnsbl_zones,omitempty"`
	LastScanAt  string `json:"last_scan_at,omitempty"`
	// Domains is how many domains send from this address.
	Domains int `json:"domains"`
}

const maxPoolAddresses = 64

// PoolList returns every address. GET /admin/mail/ip-pool
func (h *Handlers) PoolList(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT p.id, p.ip, p.enabled, p.note, p.ptr_name, p.ptr_ok,
		        p.dnsbl_listed, p.dnsbl_zones,
		        COALESCE(DATE_FORMAT(p.last_scan_at,'%Y-%m-%d %H:%i'),''),
		        (SELECT COUNT(*) FROM mail_domains m WHERE m.outbound_ip = p.ip)
		   FROM mail_ip_pool p ORDER BY p.ip`)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the address pool")
		return
	}
	defer func() { _ = rows.Close() }()
	out := make([]PoolAddress, 0)
	for rows.Next() {
		var address PoolAddress
		var enabled, ptrOK, listed int
		if err := rows.Scan(&address.ID, &address.IP, &enabled, &address.Note,
			&address.PTRName, &ptrOK, &listed, &address.DNSBLZones,
			&address.LastScanAt, &address.Domains); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "could not read the address pool")
			return
		}
		address.Enabled = enabled == 1
		address.PTROK = ptrOK == 1
		address.DNSBLListed = listed == 1
		out = append(out, address)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the address pool")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// PoolAdd adds an address. POST /admin/mail/ip-pool
//
// The address must be configured on this machine. Adding one that is not would
// produce a Postfix transport that cannot bind, and every message routed through
// it would fail at delivery time rather than here.
func (h *Handlers) PoolAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP   string `json:"ip"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ip := net.ParseIP(strings.TrimSpace(req.IP))
	if ip == nil {
		httpx.WriteError(w, http.StatusBadRequest, "that is not a valid address")
		return
	}
	value := ip.String()

	var count int
	if err := h.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM mail_ip_pool`).Scan(&count); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the address pool")
		return
	}
	if count >= maxPoolAddresses {
		httpx.WriteError(w, http.StatusBadRequest,
			"the pool already holds "+strconv.Itoa(maxPoolAddresses)+" addresses")
		return
	}
	if !addressIsLocal(value) {
		httpx.WriteError(w, http.StatusBadRequest, "that address is not configured on this server")
		return
	}

	// Reverse DNS is measured now rather than left to be discovered when mail
	// starts bouncing. A failure does not block the add: the operator may be
	// waiting on their provider to set it, and the pool row records the state so
	// the screen can say so.
	ptrName, ptrOK := lookupPTR(r.Context(), value)

	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO mail_ip_pool(ip, note, ptr_name, ptr_ok) VALUES(?,?,?,?)`,
		value, sanitize(req.Note, maxFilterNote), ptrName, boolToInt(ptrOK)); err != nil {
		httpx.WriteError(w, http.StatusConflict, "that address is already in the pool")
		return
	}
	if err := ApplyOutboundRouting(r.Context(), h.DB); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "postfix rejected the routing and it was rolled back")
		return
	}
	h.audit(r, "mail.ip_pool.add", value, true)
	httpx.WriteJSON(w, http.StatusCreated, PoolAddress{IP: value, Enabled: true, PTRName: ptrName, PTROK: ptrOK})
}

// PoolUpdate enables or disables an address. PUT /admin/mail/ip-pool/{pid}
func (h *Handlers) PoolUpdate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "pid"), 10, 64)
	var req struct {
		Enabled bool   `json:"enabled"`
		Note    string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := h.DB.ExecContext(r.Context(),
		`UPDATE mail_ip_pool SET enabled=?, note=? WHERE id=?`,
		boolToInt(req.Enabled), sanitize(req.Note, maxFilterNote), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update the address")
		return
	}
	if affected, err := result.RowsAffected(); err != nil || affected == 0 {
		httpx.WriteError(w, http.StatusNotFound, "address not found")
		return
	}
	if err := ApplyOutboundRouting(r.Context(), h.DB); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "postfix rejected the routing and it was rolled back")
		return
	}
	h.audit(r, "mail.ip_pool.update", strconv.FormatInt(id, 10), true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// PoolDelete removes an address. DELETE /admin/mail/ip-pool/{pid}
//
// Domains still pointing at it are moved back to the server default in the same
// transaction. Leaving them would produce a transport name that no longer exists
// and Postfix would defer every message from those domains.
func (h *Handlers) PoolDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "pid"), 10, 64)

	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete the address")
		return
	}
	defer func() { _ = tx.Rollback() }()

	var value string
	if err := tx.QueryRowContext(r.Context(), `SELECT ip FROM mail_ip_pool WHERE id=?`, id).Scan(&value); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "address not found")
		return
	}
	if _, err := tx.ExecContext(r.Context(),
		`UPDATE mail_domains SET outbound_ip='' WHERE outbound_ip=?`, value); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not release the domains using that address")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM mail_ip_pool WHERE id=?`, id); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete the address")
		return
	}
	if err := tx.Commit(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete the address")
		return
	}

	if err := ApplyOutboundRouting(r.Context(), h.DB); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "postfix rejected the routing and it was rolled back")
		return
	}
	h.audit(r, "mail.ip_pool.delete", value, true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// DomainOutboundPut assigns a domain to a pool address.
// PUT /domains/{id}/mail/outbound-ip
func (h *Handlers) DomainOutboundPut(w http.ResponseWriter, r *http.Request) {
	id, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	value := strings.TrimSpace(req.IP)
	if reason := h.outboundAddressRefusal(r.Context(), value); reason != "" {
		httpx.WriteError(w, http.StatusBadRequest, reason)
		return
	}
	if !h.saveOutboundAddress(w, r, id, value) {
		return
	}
	if err := ApplyOutboundRouting(r.Context(), h.DB); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "postfix rejected the routing and it was rolled back")
		return
	}
	h.audit(r, "mail.outbound_ip.update", value, true)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": value})
}

// outboundAddressRefusal returns why an address may not be assigned, or an empty
// reason. The empty address is the server default and always may be.
func (h *Handlers) outboundAddressRefusal(ctx context.Context, value string) string {
	if value == "" {
		return ""
	}
	// Only an address that is in the pool and enabled may be assigned. A
	// domain pointed at anything else would name a transport that does not
	// exist, and Postfix defers rather than falling back.
	var enabled int
	if err := h.DB.QueryRowContext(ctx,
		`SELECT enabled FROM mail_ip_pool WHERE ip=?`, value).Scan(&enabled); err != nil {
		return "that address is not in the pool"
	}
	if enabled != 1 {
		return "that address is disabled"
	}
	return ""
}

// saveOutboundAddress writes the assignment. It writes the refusal and reports
// false when the request must stop.
func (h *Handlers) saveOutboundAddress(w http.ResponseWriter, r *http.Request, domainID int64, value string) bool {
	result, err := h.DB.ExecContext(r.Context(),
		`UPDATE mail_domains SET outbound_ip=? WHERE domain_id=?`, value, domainID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save the outbound address")
		return false
	}
	if affected, err := result.RowsAffected(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save the outbound address")
		return false
	} else if affected == 0 {
		// Zero rows means either mail is not enabled for the domain or the value
		// is unchanged. Only the first is an error the caller can act on.
		var exists int
		_ = h.DB.QueryRowContext(r.Context(),
			`SELECT COUNT(*) FROM mail_domains WHERE domain_id=?`, domainID).Scan(&exists)
		if exists == 0 {
			httpx.WriteError(w, http.StatusBadRequest, "enable mail for this domain first")
			return false
		}
	}
	return true
}

// addressIsLocal reports whether the address is configured on an interface of
// this machine.
var addressIsLocal = func(value string) bool {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	target := net.ParseIP(value)
	if target == nil {
		return false
	}
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok && network.IP.Equal(target) {
			return true
		}
	}
	return false
}

// lookupPTR returns the reverse name and whether it forward-confirms.
//
// The queries go to a public resolver for the same reason the verification
// screen's do: this host runs an authoritative BIND and could answer from its
// own zone, hiding the mismatch being looked for.
func lookupPTR(ctx context.Context, value string) (string, bool) {
	resolver := poolResolver()
	names, err := resolver.LookupAddr(ctx, value)
	if err != nil || len(names) == 0 {
		return "", false
	}
	sort.Strings(names)
	name := strings.TrimSuffix(names[0], ".")
	for _, candidate := range names {
		addresses, err := resolver.LookupIPAddr(ctx, strings.TrimSuffix(candidate, "."))
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if address.IP.String() == value {
				return strings.TrimSuffix(candidate, "."), true
			}
		}
	}
	return name, false
}

// poolResolver is a seam so the scanner can be tested without network access.
var poolResolver = func() addrLookup {
	server := config.DNSVerifyResolver()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: dnsblQueryTimeout}
			return dialer.DialContext(ctx, network, server)
		},
	}
}

// addrLookup is the slice of *net.Resolver this file uses.
type addrLookup interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// poolAddressesForRouting returns the enabled pool addresses and the domains
// assigned to each, which is everything the Postfix configuration needs.
func poolAddressesForRouting(ctx context.Context, db *sql.DB) ([]string, map[string]string, error) {
	addresses, err := enabledPoolAddresses(ctx, db)
	if err != nil {
		return nil, nil, err
	}

	enabled := map[string]bool{}
	for _, value := range addresses {
		enabled[value] = true
	}

	domainRows, err := db.QueryContext(ctx,
		`SELECT domain_name, outbound_ip FROM mail_domains
		  WHERE status='active' AND outbound_ip <> '' ORDER BY domain_name`)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = domainRows.Close() }()
	assignments := map[string]string{}
	for domainRows.Next() {
		var domain, value string
		if err := domainRows.Scan(&domain, &value); err != nil {
			return nil, nil, err
		}
		// A domain pointing at an address that is gone or disabled falls back to
		// the server default rather than naming a transport that does not exist,
		// which Postfix answers by deferring every message from that domain.
		if !enabled[value] || !validRoutingDomain(domain) {
			continue
		}
		assignments[domain] = value
	}
	return addresses, assignments, domainRows.Err()
}

// enabledPoolAddresses reads the enabled pool addresses that parse as an IP.
func enabledPoolAddresses(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT ip FROM mail_ip_pool WHERE enabled=1 ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	var addresses []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if net.ParseIP(value) == nil {
			continue // never write a transport that cannot bind
		}
		addresses = append(addresses, value)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return addresses, nil
}

// validRoutingDomain rejects anything that is not a plain hostname, because the
// value is written as the left-hand side of a Postfix table line.
func validRoutingDomain(domain string) bool {
	return filterDomainPattern.MatchString(strings.ToLower(domain))
}

// transportName is the master.cf service name for one address. It is derived
// from the address itself so the same address always maps to the same transport,
// which keeps a rewrite of the configuration from renaming everything.
func transportName(value string) string {
	replaced := strings.NewReplacer(".", "_", ":", "_").Replace(value)
	return "servika_out_" + replaced
}
