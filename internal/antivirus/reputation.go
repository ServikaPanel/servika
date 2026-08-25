package antivirus

// Whether a domain on this server is on a DNS blocklist.
//
// A site can be clean on disk, clean in its database, and still be refused by
// mail servers and marked in browsers because the domain itself was reported.
// Nothing in the panel said so: internal/mail asks a blocklist about the
// server's SENDING ADDRESSES, which is a different subject, and a customer
// whose domain was listed learned it from their visitors.
//
// Five rules bind anything that touches this file, and each closes a hole that
// is invisible from the code alone.
//
// THE ZONE LIST DEFAULTS TO EMPTY, WHICH IS OFF. A panel update must not start
// querying a third-party service about every domain an operator hosts, which is
// the same reason host_apps_enabled and session_idle_minutes default to 0. It
// is also the honest default here for a second reason: measured against the
// live service, a host resolving through 1.1.1.1 or 8.8.8.8 gets
// 127.255.255.254 from Spamhaus for a listed name and a clean one alike, so the
// operator has to name a zone their own resolver can answer before this reports
// anything at all.
//
// NO DNS QUERY RUNS ON THE REQUEST PATH. One query per zone per domain, at
// seconds each when a blocklist is slow, is 500 domains times up to 8 zones on
// one HTTP request. The scheduler writes domain_reputation and the endpoint
// reads it, which is the shape internal/mail's pool scanner already uses.
//
// "COULD NOT BE QUERIED" IS ITS OWN STATE AND IS DRAWN AS ONE. An empty zone
// list and a clean domain both leave the hit list empty, so `queried` carries
// the difference. Folding them together turns a domain nothing could check into
// a domain reported clean, which is the one answer this screen must not invent.
//
// A ZONE THAT ANSWERS 127.255.255.0/24 IS NOT A LISTING. That block carries
// error codes about the QUERY, not answers about the subject. internal/dnsbl
// owns that rule and both callers get it from there.
//
// THE LIST ENDPOINT IS NARROWED BY THE QUERY. A row-by-row ownership check does
// not work on a list endpoint: the rows a reseller may not see would already
// have been read and counted.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/dnsbl"
	"servika/internal/httpx"
	"servika/internal/middleware"
)

const (
	// reputationInterval is how often every domain is re-checked. A blocklist
	// listing is not a fast-moving fact and each pass is one query per zone per
	// domain, so this is deliberately daily rather than hourly.
	reputationInterval = 24 * time.Hour
	// reputationQueryTimeout bounds ONE query. A listed name answers quickly; a
	// zone that does not answer must not hold the whole pass.
	reputationQueryTimeout = 4 * time.Second
	// reputationBudget bounds the whole pass, so a server full of domains and a
	// slow blocklist cannot leave the goroutine running into the next interval.
	reputationBudget = 30 * time.Minute
	// reasonZonesInvalid and reasonTooManyZones are the stable codes a refused
	// zone list answers with. The screen renders twelve languages, so it matches
	// on these rather than on prose.
	//
	// Neither may END in an i18next plural category (_zero, _one, _two, _few,
	// _many, _other). The natural spelling of the second, domain_dnsbl_zones_
	// too_many, is read by i18next as the _many form of a key nobody wrote, so
	// it resolves in English (whose plural set is _one and _other) and in no
	// other language. scripts/i18n-verify.mjs is what reports it.
	reasonZonesInvalid = "domain_dnsbl_zone_invalid"
	reasonTooManyZones = "domain_dnsbl_too_many_zones"
)

// reputationResolver is the seam a test replaces. Production resolves through
// whatever the panel is configured to verify DNS with, which is the resolver an
// operator chose to trust.
var reputationResolver = func() dnsbl.HostLookup {
	server := config.DNSVerifyResolver()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: reputationQueryTimeout}
			return dialer.DialContext(ctx, network, server)
		},
	}
}

// boundedReputationResolver puts a per-query deadline on the shared resolver.
// dnsbl hands the pass context straight through, and one unreachable zone would
// otherwise spend the whole budget.
type boundedReputationResolver struct{ ctx context.Context }

func (b boundedReputationResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	query, cancel := context.WithTimeout(b.ctx, reputationQueryTimeout)
	defer cancel()
	return reputationResolver().LookupHost(query, host)
}

// ReputationEntry is one domain's stored state.
type ReputationEntry struct {
	DomainID int64  `json:"domain_id"`
	Domain   string `json:"domain"`
	// Listed names the zones that list this domain. Empty means nothing does,
	// but only when Queried is true.
	Listed []string `json:"listed"`
	// Zones names what was asked, so the row says what it is an answer about.
	Zones []string `json:"zones"`
	// Queried is false when no zone could be asked. The screen draws that as
	// "could not be checked", never as clean.
	Queried    bool   `json:"queried"`
	LastScanAt string `json:"last_scan_at"`
}

// ReputationZones reads the configured blocklist zones.
func ReputationZones(ctx context.Context, db *sql.DB) ([]string, error) {
	var raw string
	if err := db.QueryRowContext(ctx,
		`SELECT domain_dnsbl_zones FROM panel_settings WHERE id=1`).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return strings.Fields(raw), nil
}

// StartReputationScanner refreshes every domain's state on a timer.
func StartReputationScanner(db *sql.DB) {
	go func() {
		// Nothing here is urgent, so it does not compete with the rest of boot.
		time.Sleep(3 * time.Minute)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), reputationBudget)
			if err := ScanReputation(ctx, db); err != nil {
				log.Printf("domain reputation scan: %v", err)
			}
			cancel()
			time.Sleep(reputationInterval)
		}
	}()
}

// ScanReputation asks every configured zone about every top-level domain and
// stores what it learned.
//
// Addon and subdomain rows are skipped: a blocklist lists a registered name, so
// asking about a subdomain queries a name no blocklist has an entry for and
// records an answer about the wrong subject.
func ScanReputation(ctx context.Context, db *sql.DB) error {
	zones, err := ReputationZones(ctx, db)
	if err != nil {
		return err
	}

	rows, err := db.QueryContext(ctx,
		`SELECT id, domain_name FROM domains WHERE parent_domain_id IS NULL ORDER BY id`)
	if err != nil {
		return err
	}
	type target struct {
		id   int64
		name string
	}
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.name); err != nil {
			_ = rows.Close()
			return err
		}
		targets = append(targets, t)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	resolver := boundedReputationResolver{ctx: ctx}
	stored := strings.Join(zones, " ")
	for _, t := range targets {
		if ctx.Err() != nil {
			// The budget ran out. What was written stays written; the rest keeps
			// whatever it had, which is the honest state rather than a row
			// claiming an answer nobody got.
			return ctx.Err()
		}
		hits, queried := dnsbl.LookupDomain(ctx, resolver, t.name, zones)
		if _, err := db.ExecContext(ctx,
			`INSERT INTO domain_reputation (domain_id, listed, zones, queried, last_scan_at)
			 VALUES (?,?,?,?,NOW())
			 ON DUPLICATE KEY UPDATE listed=VALUES(listed), zones=VALUES(zones),
			                         queried=VALUES(queried), last_scan_at=NOW()`,
			t.id, strings.Join(hits, " "), stored, queried); err != nil {
			return err
		}
	}
	return nil
}

// AdminReputation answers GET /admin/antivirus/reputation (ResellerOrAbove).
//
// Every domain is listed, including the ones with no stored row: a domain the
// scanner has never reached is exactly the one an operator needs to see, and
// leaving it out would make the list read as complete when it is not.
func (h *Handlers) AdminReputation(w http.ResponseWriter, r *http.Request) {
	condition, args, unrestricted := middleware.ScopeCondition(r, "d")
	query := `SELECT d.id, d.domain_name, COALESCE(rep.listed,''), COALESCE(rep.zones,''),
	                 COALESCE(rep.queried,0), rep.last_scan_at
	            FROM domains d
	            LEFT JOIN domain_reputation rep ON rep.domain_id = d.id
	           WHERE d.parent_domain_id IS NULL`
	if !unrestricted {
		// #nosec G202 -- condition is a constant scope fragment from ScopeCondition with a literal alias; every user value is bound through args.
		query += ` AND ` + condition
	}
	query += ` ORDER BY d.domain_name`

	// #nosec G202 G701 -- condition is a constant scope fragment from ScopeCondition with a literal alias; every user value is bound through args.
	rows, err := h.DB.QueryContext(r.Context(), query, args...)
	if err != nil {
		log.Printf("antivirus: the domain reputation list could not be read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read domain reputation")
		return
	}
	defer func() { _ = rows.Close() }()

	out := []ReputationEntry{}
	for rows.Next() {
		var entry ReputationEntry
		var listed, zones string
		var scanned sql.NullString
		if err := rows.Scan(&entry.DomainID, &entry.Domain, &listed, &zones,
			&entry.Queried, &scanned); err != nil {
			// A failed row is REPORTED, never skipped. A short list here reads as
			// fewer domains checked than there are, which is the reading this
			// screen exists to prevent.
			log.Printf("antivirus: a domain reputation row could not be read: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "could not read domain reputation")
			return
		}
		entry.Listed = strings.Fields(listed)
		entry.Zones = strings.Fields(zones)
		entry.LastScanAt = scanned.String
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		log.Printf("antivirus: the domain reputation read ended early: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read domain reputation")
		return
	}

	zones, err := ReputationZones(r.Context(), h.DB)
	if err != nil {
		log.Printf("antivirus: the blocklist zone list could not be read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read domain reputation")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"entries": out,
		// The configured zones travel beside the rows so the screen can say the
		// feature is off rather than drawing every domain as unchecked with no
		// reason given.
		"zones": zones,
	})
}

// AdminReputationZonesSave answers PUT /admin/antivirus/reputation/zones
// (AdminOnly).
//
// It is admin only where the list is ResellerOrAbove, because the zones decide
// which third-party service this server queries about every domain on it. That
// is the operator's decision, not a per-scope one.
func (h *Handlers) AdminReputationZonesSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Zones string `json:"zones"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	zones, err := dnsbl.ValidateZones(req.Zones)
	if err != nil {
		var zoneErr *dnsbl.ZoneError
		if errors.As(err, &zoneErr) && zoneErr.TooMany {
			httpx.WriteError(w, http.StatusBadRequest, reasonTooManyZones)
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, reasonZonesInvalid)
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE panel_settings SET domain_dnsbl_zones=? WHERE id=1`,
		strings.Join(zones, " ")); err != nil {
		log.Printf("antivirus: the blocklist zone list could not be saved: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not save the blocklist zones")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"zones": zones})
}
