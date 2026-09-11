package dns

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// SOA contains the configurable Start of Authority settings for a domain.
type SOA struct {
	PrimaryNS  string `json:"primary_ns"`
	Hostmaster string `json:"hostmaster"`
	Refresh    int    `json:"refresh"`
	Retry      int    `json:"retry"`
	Expire     int    `json:"expire"`
	Minimum    int    `json:"minimum"`
	TTL        int    `json:"ttl"`
}

// defaultSOA builds the SOA defaults for a domain. The primary NS must be
// CONSISTENT with the zone's NS records, so it is the first of the shared
// nameserver pair (see nameserver.go). It used to be hardcoded to
// "ns1.<domain>", which under the shared model writes a host into the SOA that
// appears nowhere in the zone's NS records: named-checkzone accepts that "lame
// SOA", but DNS auditors and some registry checks flag it.
func defaultSOA(domainName, ns1 string) SOA {
	if !ValidNSHost(ns1) {
		ns1 = "ns1." + domainName
	}
	return SOA{
		PrimaryNS:  ns1,
		Hostmaster: "admin@" + domainName,
		Refresh:    3600,
		Retry:      900,
		Expire:     1209600,
		Minimum:    3600,
		TTL:        3600,
	}
}

// LoadSOA returns the stored SOA settings or domain-specific defaults.
func LoadSOA(ctx context.Context, db *sql.DB, domainID int64, domainName string) SOA {
	ns1, _ := NameserverPair(ctx, db, domainID, domainName)
	soa := defaultSOA(domainName, ns1)
	var primaryNS, hostmaster string
	var refresh, retry, expire, minimum, ttl int
	if err := db.QueryRowContext(ctx,
		`SELECT primary_ns, hostmaster, refresh, retry, expire, minimum, ttl FROM dns_soa WHERE domain_id=?`,
		domainID).Scan(&primaryNS, &hostmaster, &refresh, &retry, &expire, &minimum, &ttl); err != nil {
		return soa
	}
	if primaryNS != "" {
		soa.PrimaryNS = primaryNS
	}
	if hostmaster != "" {
		soa.Hostmaster = hostmaster
	}
	if refresh > 0 {
		soa.Refresh = refresh
	}
	if retry > 0 {
		soa.Retry = retry
	}
	if expire > 0 {
		soa.Expire = expire
	}
	if minimum > 0 {
		soa.Minimum = minimum
	}
	if ttl > 0 {
		soa.TTL = ttl
	}
	return soa
}

// GetSOA returns the SOA settings for a domain.
func (h *Handlers) GetSOA(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var domainName string
	if err := h.DB.QueryRowContext(r.Context(), `SELECT domain_name FROM domains WHERE id=?`, id).Scan(&domainName); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, LoadSOA(r.Context(), h.DB, id, domainName))
}

// PutSOA updates the SOA settings and rewrites the domain's zone file.
func (h *Handlers) PutSOA(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var domainName string
	var isDemo int
	if err := h.DB.QueryRowContext(r.Context(), `SELECT domain_name, is_demo FROM domains WHERE id=?`, id).Scan(&domainName, &isDemo); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if isDemo == 1 {
		httpx.WriteError(w, http.StatusForbidden, "sOA settings are read-only for demo subscriptions")
		return
	}
	var soa SOA
	if err := json.NewDecoder(r.Body).Decode(&soa); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ns1, _ := NameserverPair(r.Context(), h.DB, id, domainName)
	defaults := defaultSOA(domainName, ns1)
	if soa.PrimaryNS = strings.TrimSpace(soa.PrimaryNS); soa.PrimaryNS == "" {
		soa.PrimaryNS = defaults.PrimaryNS
	}
	if soa.Hostmaster = strings.TrimSpace(soa.Hostmaster); soa.Hostmaster == "" {
		soa.Hostmaster = defaults.Hostmaster
	}
	if soa.Refresh <= 0 {
		soa.Refresh = defaults.Refresh
	}
	if soa.Retry <= 0 {
		soa.Retry = defaults.Retry
	}
	if soa.Expire <= 0 {
		soa.Expire = defaults.Expire
	}
	if soa.Minimum <= 0 {
		soa.Minimum = defaults.Minimum
	}
	if soa.TTL <= 0 {
		soa.TTL = defaults.TTL
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO dns_soa(domain_id, primary_ns, hostmaster, refresh, retry, expire, minimum, ttl)
		 VALUES(?,?,?,?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE primary_ns=VALUES(primary_ns), hostmaster=VALUES(hostmaster),
		   refresh=VALUES(refresh), retry=VALUES(retry), expire=VALUES(expire),
		   minimum=VALUES(minimum), ttl=VALUES(ttl)`,
		id, soa.PrimaryNS, soa.Hostmaster, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum, soa.TTL); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not save SOA settings")
		return
	}
	if err := WriteZone(r.Context(), h.DB, id); err != nil {
		httpx.LogR(r, "dns WriteZone(soa) domain=%d: %v", id, err)
	}
	httpx.WriteJSON(w, http.StatusOK, soa)
}
