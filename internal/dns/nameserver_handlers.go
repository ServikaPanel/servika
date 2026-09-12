package dns

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"servika/internal/httpx"
	"servika/internal/logx"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

// NameserverSetting is one nameserver pair, used for both the panel-wide and
// the reseller setting.
type NameserverSetting struct {
	NS1 string `json:"ns1"`
	NS2 string `json:"ns2"`
	// Source says where the values came from: "reseller", "panel" or "none".
	// The panel shows it as "currently using X".
	Source string `json:"source,omitempty"`
	// Warning is filled when no real pair is configured.
	Warning string `json:"warning,omitempty"`
	// SuggestedNS1/SuggestedNS2 are GUESSED from the panel domain when nothing
	// is configured. They are only a suggestion and are never written into a
	// zone before an administrator confirms them.
	SuggestedNS1 string `json:"suggested_ns1,omitempty"`
	SuggestedNS2 string `json:"suggested_ns2,omitempty"`
}

const (
	sourceReseller = "reseller"
	sourcePanel    = "panel"
	sourceNone     = "none"

	unconfiguredWarning = "no nameservers are configured, so zones temporarily use ns1.<domain> (vanity) " +
		"and customers cannot point their domains at the panel"
	customerUnconfiguredWarning = "these addresses cannot be used because the server has no shared nameservers; " +
		"an administrator must configure them under Settings"
)

var (
	errInvalidNSBody = errors.New("invalid request body")
	errInvalidNSHost = errors.New("nameserver names must be fully qualified domain names (for example ns1.example.com)")
	errIdenticalNS   = errors.New("ns1 and ns2 cannot be the same")
)

func readNameserverBody(r *http.Request) (ns1, ns2 string, err error) {
	var body NameserverSetting
	if decodeErr := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); decodeErr != nil {
		return "", "", errInvalidNSBody
	}
	ns1 = strings.ToLower(strings.TrimSpace(body.NS1))
	ns2 = strings.ToLower(strings.TrimSpace(body.NS2))
	if !ValidNSHost(ns1) || !ValidNSHost(ns2) {
		return "", "", errInvalidNSHost
	}
	if ns1 == ns2 {
		return "", "", errIdenticalNS
	}
	return ns1, ns2, nil
}

// GetNameserver returns the panel-wide nameserver pair and where it came from.
func (h *Handlers) GetNameserver(w http.ResponseWriter, r *http.Request) {
	var out NameserverSetting
	if ns1, ns2, ok := panelNS(r.Context(), h.DB); ok {
		out.NS1, out.NS2, out.Source = ns1, ns2, sourcePanel
	} else {
		out.Source = sourceNone
		out.Warning = unconfiguredWarning
		if first, second, ok := SuggestedNameservers(r.Context(), h.DB); ok {
			out.SuggestedNS1, out.SuggestedNS2 = first, second
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// PutNameserver stores the panel-wide nameserver pair.
func (h *Handlers) PutNameserver(w http.ResponseWriter, r *http.Request) {
	ns1, ns2, err := readNameserverBody(r)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE panel_settings SET ns1_hostname=?, ns2_hostname=? WHERE id=1`, ns1, ns2); err != nil {
		httpx.LogR(r, "save panel nameservers: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "nameservers could not be saved")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, NameserverSetting{NS1: ns1, NS2: ns2, Source: sourcePanel})
}

// GetResellerNameserver returns a reseller's own white-label pair, falling back
// to the panel-wide pair when the reseller has not set one.
func (h *Handlers) GetResellerNameserver(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFrom(r)
	if claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var out NameserverSetting
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT ns1, ns2 FROM reseller_nameservers WHERE user_id=?`, claims.UserID).Scan(&out.NS1, &out.NS2)
	if err == nil && ValidNSHost(out.NS1) && ValidNSHost(out.NS2) {
		out.Source = sourceReseller
		httpx.WriteJSON(w, http.StatusOK, out)
		return
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		httpx.LogR(r, "read reseller nameservers user=%d: %v", claims.UserID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "nameservers could not be read")
		return
	}
	if ns1, ns2, ok := panelNS(r.Context(), h.DB); ok {
		httpx.WriteJSON(w, http.StatusOK, NameserverSetting{NS1: ns1, NS2: ns2, Source: sourcePanel})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, NameserverSetting{
		Source:  sourceNone,
		Warning: "the server has no shared nameservers configured; contact your administrator",
	})
}

// PutResellerNameserver stores a reseller's white-label pair.
//
// The reseller creates the A records for these hostnames in its OWN DNS. The
// panel cannot verify that, because the reseller's domain is not necessarily
// hosted here, so the response carries the reminder instead.
func (h *Handlers) PutResellerNameserver(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFrom(r)
	if claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	ns1, ns2, err := readNameserverBody(r)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO reseller_nameservers(user_id, ns1, ns2) VALUES(?,?,?)
		 ON DUPLICATE KEY UPDATE ns1=VALUES(ns1), ns2=VALUES(ns2)`,
		claims.UserID, ns1, ns2); err != nil {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		httpx.LogR(r, "save reseller nameservers user=%d: %v", claims.UserID, err)
		httpx.WriteError(w, http.StatusInternalServerError, "nameservers could not be saved")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, NameserverSetting{NS1: ns1, NS2: ns2, Source: sourceReseller,
		Warning: "point the A records for " + ns1 + " and " + ns2 + " at this server's IP address in your own DNS provider; " +
			"until then your customers' domains will not resolve"})
}

// MigrationResult reports what MigrateNameservers changed.
type MigrationResult struct {
	Total   int      `json:"total"`
	Updated int      `json:"updated"`
	Failed  []string `json:"failed,omitempty"`
}

// MigrateNameservers moves every domain's NS records and SOA primary NS onto
// the currently resolved pair and rewrites the zones.
//
// This exists because changing the setting alone is not enough: the rows
// already in dns_records and dns_soa keep the OLD values, and the template only
// runs for NEW domains. Without this, migrating an existing installation would
// mean editing every domain by hand.
//
// It is idempotent: a domain that is already correct is left untouched.
func (h *Handlers) MigrateNameservers(w http.ResponseWriter, r *http.Request) {
	result, err := MigrateNameserverRecords(r.Context(), h.DB)
	if err != nil {
		httpx.LogR(r, "migrate nameserver records: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "nameserver migration failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, result)
}

// MigrateNameserverRecords syncs the NS and SOA rows of every domain with the
// resolved nameserver pair. A domain that already matches is skipped.
func MigrateNameserverRecords(ctx context.Context, db *sql.DB) (MigrationResult, error) {
	var result MigrationResult
	rows, err := db.QueryContext(ctx, `SELECT id, domain_name FROM domains ORDER BY id`)
	if err != nil {
		return result, err
	}
	type domainRow struct {
		id   int64
		name string
	}
	var domainList []domainRow
	for rows.Next() {
		var row domainRow
		if err := rows.Scan(&row.id, &row.name); err != nil {
			_ = rows.Close()
			return result, err
		}
		domainList = append(domainList, row)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return result, err
	}
	if err := rows.Close(); err != nil {
		return result, err
	}

	for _, row := range domainList {
		result.Total++
		ns1, ns2 := NameserverPair(ctx, db, row.id, row.name)
		changed, err := syncNameserverRecords(ctx, db, row.id, row.name, ns1, ns2)
		if err != nil {
			// The detail goes to the log, not the API response; the operator
			// needs to know WHICH domain failed, and the server log carries why.
			logx.Errorf("dns nameserver migration domain=%d: %v", row.id, err)
			result.Failed = append(result.Failed, row.name)
			continue
		}
		if !changed {
			continue
		}
		result.Updated++
		if err := WriteZone(ctx, db, row.id); err != nil {
			logx.Errorf("dns nameserver migration WriteZone domain=%d: %v", row.id, err)
			result.Failed = append(result.Failed, row.name)
		}
	}
	return result, nil
}

// syncNameserverRecords makes a domain's apex NS records exactly {ns1, ns2} and
// pulls the SOA primary NS onto ns1. It reports whether anything changed.
//
// Glue is delegated to SyncGlueRecords, which decides per domain: a nameserver
// inside this zone needs an in-zone A record, one outside it leaves only the
// vanity model's ns1/ns2 A records to clean up.
func syncNameserverRecords(ctx context.Context, db *sql.DB, domainID int64, domainName, ns1, ns2 string) (bool, error) {
	current, err := currentNSRecords(ctx, db, domainID)
	if err != nil {
		return false, err
	}
	nsCorrect := nsPairMatches(current, ns1, ns2)

	soaCorrect, err := soaNamesPrimary(ctx, db, domainID, ns1)
	if err != nil {
		return false, err
	}

	// Glue must be settled per domain: an in-zone nameserver needs an A record
	// inside this very zone or BIND refuses to load it, while an out-of-zone one
	// only leaves the vanity model's ns1/ns2 A records behind.
	var ipv4 string
	if err := db.QueryRowContext(ctx, `SELECT ipv4 FROM domains WHERE id=?`, domainID).Scan(&ipv4); err != nil {
		return false, err
	}
	glueChanged, err := SyncGlueRecords(ctx, db, domainID, domainName, ipv4, ns1, ns2)
	if err != nil {
		return false, err
	}

	if nsCorrect && soaCorrect && !glueChanged {
		return false, nil
	}
	if err := writeNameserverRecords(ctx, db, domainID, ns1, ns2, nsCorrect, soaCorrect); err != nil {
		return false, err
	}
	return true, nil
}

// currentNSRecords returns the apex NS values a zone publishes today, lowercased
// and without their trailing dot.
func currentNSRecords(ctx context.Context, db *sql.DB, domainID int64) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT value FROM dns_records WHERE domain_id=? AND type='NS' AND name='@'`, domainID)
	if err != nil {
		return nil, err
	}
	var current []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			_ = rows.Close()
			return nil, err
		}
		current = append(current, strings.ToLower(strings.TrimSuffix(value, ".")))
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return current, nil
}

// nsPairMatches reports whether the zone already publishes exactly the pair.
func nsPairMatches(current []string, ns1, ns2 string) bool {
	wanted := map[string]bool{ns1: true, ns2: true}
	if len(current) != 2 {
		return false
	}
	for _, value := range current {
		if !wanted[value] {
			return false
		}
	}
	return true
}

// soaNamesPrimary reports whether the SOA already names the first nameserver.
//
// A domain with no SOA row yet gets one from the template path, not here.
func soaNamesPrimary(ctx context.Context, db *sql.DB, domainID int64, ns1 string) (bool, error) {
	var soaPrimary string
	err := db.QueryRowContext(ctx, `SELECT primary_ns FROM dns_soa WHERE domain_id=?`, domainID).Scan(&soaPrimary)
	soaMissing := errors.Is(err, sql.ErrNoRows)
	if err != nil && !soaMissing {
		return false, err
	}
	return soaMissing || strings.EqualFold(strings.TrimSuffix(soaPrimary, "."), ns1), nil
}

// writeNameserverRecords replaces whichever of the NS set and the SOA primary
// does not name the pair.
func writeNameserverRecords(ctx context.Context, db *sql.DB, domainID int64, ns1, ns2 string, nsCorrect, soaCorrect bool) error {
	if !nsCorrect {
		if _, err := db.ExecContext(ctx,
			`DELETE FROM dns_records WHERE domain_id=? AND type='NS' AND name='@'`, domainID); err != nil {
			return err
		}
		for _, host := range []string{ns1, ns2} {
			if _, err := db.ExecContext(ctx,
				`INSERT INTO dns_records(domain_id, name, type, value, ttl, priority, enabled)
				 VALUES(?, '@', 'NS', ?, 86400, 0, 1)`, domainID, host); err != nil {
				return err
			}
		}
	}
	if !soaCorrect {
		if _, err := db.ExecContext(ctx,
			`UPDATE dns_soa SET primary_ns=? WHERE domain_id=?`, ns1, domainID); err != nil {
			return err
		}
	}
	return nil
}

// GetDomainNameserver tells a customer where to point their domain. It is shown
// next to the IPv4 address on the connection page: the panel's version of the
// "point your domain at ns1.../ns2..." instruction every hosting provider gives.
func (h *Handlers) GetDomainNameserver(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var domainName string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name FROM domains WHERE id=?`, id).Scan(&domainName); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	ns1, ns2 := NameserverPair(r.Context(), h.DB, id, domainName)
	out := NameserverSetting{NS1: ns1, NS2: ns2, Source: sourcePanel}
	if _, _, ok := resellerNS(r.Context(), h.DB, id); ok {
		out.Source = sourceReseller
	} else if !NameserversConfigured(r.Context(), h.DB) {
		// The vanity fallback. These values must NOT be handed to a customer:
		// they need a glue record at the registrar of every single domain.
		out.Source = sourceNone
		out.Warning = customerUnconfiguredWarning
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
