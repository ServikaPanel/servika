package mail

import (
	"context"
	"database/sql"
	"log"
	"net"
	"strings"
	"time"
)

// Blocklist scanning for the outbound addresses.
//
// This runs in the background rather than when a screen is opened. A blocklist
// answers over DNS from someone else's infrastructure, and a panel request that
// waited on eight of them would hang for as long as the slowest one; the answer
// also changes on the scale of hours, so measuring it per request buys nothing.

const (
	// dnsblQueryTimeout bounds one blocklist query. A listed address answers at
	// once; an unreachable zone answers never.
	dnsblQueryTimeout = 4 * time.Second
	// dnsblScanInterval is how often the pool is rescanned. A delisting takes
	// hours to propagate, so scanning faster only adds queries.
	dnsblScanInterval = time.Hour
)

// StartPoolScanner rescans the pool on a timer.
//
// primary is the server's own outbound address. It is scanned alongside the
// pool because the pool is EMPTY on a default install, and a server that never
// configured one had no blocklist monitoring at all: the one address every
// domain actually sends from was the one address nothing looked at.
func StartPoolScanner(db *sql.DB, primary string) {
	go func() {
		// Nothing here is urgent, so it does not compete with the rest of boot.
		time.Sleep(2 * time.Minute)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			if err := ScanPool(ctx, db, primary); err != nil {
				log.Printf("mail address pool scan: %v", err)
			}
			cancel()
			time.Sleep(dnsblScanInterval)
		}
	}()
}

// ScanPool checks every pool address against the configured blocklists and
// refreshes its reverse DNS.
//
// The zones are the ones already configured for rejecting inbound mail. Using a
// different list would mean an operator's own sending addresses were judged by
// blocklists they had not chosen to trust.
func ScanPool(ctx context.Context, db *sql.DB, primary string) error {
	settings, err := ReadServerSettings(ctx, db)
	if err != nil {
		return err
	}
	zones := strings.Fields(settings.DNSBLZones)

	rows, err := db.QueryContext(ctx, `SELECT id, ip, dnsbl_listed FROM mail_ip_pool ORDER BY id`)
	if err != nil {
		return err
	}
	type poolRow struct {
		id int64
		ip string
		// wasListed is the state the previous scan left, so the moment an
		// address BECOMES listed can be announced. Without it a listing is a
		// column nobody reads until someone opens the screen.
		wasListed bool
	}
	var pool []poolRow
	for rows.Next() {
		var row poolRow
		var listed int
		if err := rows.Scan(&row.id, &row.ip, &listed); err != nil {
			_ = rows.Close()
			return err
		}
		row.wasListed = listed == 1
		pool = append(pool, row)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	for _, row := range pool {
		ptrName, ptrOK := lookupPTR(ctx, row.ip)
		hits, _ := dnsblHits(ctx, row.ip, zones)
		announceListing(row.ip, row.wasListed, hits)
		if _, err := db.ExecContext(ctx,
			`UPDATE mail_ip_pool
			    SET ptr_name=?, ptr_ok=?, dnsbl_listed=?, dnsbl_zones=?, last_scan_at=NOW()
			  WHERE id=?`,
			ptrName, boolToInt(ptrOK), boolToInt(len(hits) > 0), strings.Join(hits, " "), row.id); err != nil {
			// One address failing must not stop the rest: the others still need
			// their state refreshed, and the failure is visible in the log.
			log.Printf("mail address pool scan for %d: %v", row.id, err)
		}
	}
	return scanPrimary(ctx, db, primary, zones)
}

// scanPrimary refreshes the state of the server's own outbound address.
//
// The result lives in mail_server_settings rather than as a row in the pool.
// The pool is the operator's own list of addresses to move a customer between,
// so an address nobody added would invite being deleted, and deleting it would
// silently switch this monitoring off again.
func scanPrimary(ctx context.Context, db *sql.DB, primary string, zones []string) error {
	primary = strings.TrimSpace(primary)
	if primary == "" {
		return nil
	}
	var wasListed int
	// A read failure here is not fatal to the scan: it only costs the
	// transition notice, and refreshing the state still matters.
	_ = db.QueryRowContext(ctx,
		`SELECT primary_dnsbl_zones <> '' FROM mail_server_settings WHERE id = 1`).Scan(&wasListed)

	ptrName, ptrOK := lookupPTR(ctx, primary)
	hits, queried := dnsblHits(ctx, primary, zones)
	announceListing(primary, wasListed == 1, hits)

	_, err := db.ExecContext(ctx,
		`UPDATE mail_server_settings
		    SET primary_ip=?, primary_ptr_name=?, primary_ptr_ok=?,
		        primary_dnsbl_scanned=?, primary_dnsbl_zones=?, primary_scan_at=NOW()
		  WHERE id = 1`,
		primary, ptrName, boolToInt(ptrOK), boolToInt(queried), strings.Join(hits, " "))
	return err
}

// announceListing logs the moment an address BECOMES listed.
//
// The stored columns already carry the state, but a state nobody looks at is
// not a warning. The transition is what an operator can act on and what a log
// watcher can alert from; a delisting needs no notice, because the state clears
// itself on the next scan.
func announceListing(address string, wasListed bool, hits []string) {
	if len(hits) > 0 && !wasListed {
		// #nosec G706 -- address came from a validated pool row or the panel's own IP detection, and the zones passed dnsblZonePattern.
		log.Printf("mail: %s is now listed on %s", address, strings.Join(hits, " "))
	}
}

// dnsblHits returns the zones that list the address, and whether the address
// could be queried at all.
//
// A blocklist answers by resolving the reversed address under its zone, so a
// name that resolves means listed and one that does not means clean. A lookup
// that fails for any other reason is NOT counted as a hit: reporting an
// unreachable blocklist as a listing would have an operator chasing a delisting
// that was never needed.
//
// The second return separates "queried and clean" from "never queried". They
// are not the same answer and used to be indistinguishable: an IPv6 address has
// no reversed IPv4 form, so it returned no hits and read as clean, which is a
// false assurance about an address that was never checked.
func dnsblHits(ctx context.Context, value string, zones []string) ([]string, bool) {
	if len(zones) == 0 {
		return nil, false
	}
	reversed := reverseIPv4(value)
	if reversed == "" {
		return nil, false // only IPv4 blocklists are queried this way
	}
	resolver := poolResolver()
	var hits []string
	for _, zone := range zones {
		query, cancel := context.WithTimeout(ctx, dnsblQueryTimeout)
		addresses, err := resolver.LookupHost(query, reversed+"."+zone)
		cancel()
		if err == nil && len(addresses) > 0 {
			hits = append(hits, zone)
		}
	}
	return hits, true
}

// reverseIPv4 turns 203.0.113.5 into 5.113.0.203, which is how a blocklist zone
// is queried. Anything that is not IPv4 returns empty.
func reverseIPv4(value string) string {
	ip := net.ParseIP(value)
	if ip == nil {
		return ""
	}
	four := ip.To4()
	if four == nil {
		return ""
	}
	parts := strings.Split(four.String(), ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}
