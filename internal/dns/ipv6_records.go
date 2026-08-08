package dns

import (
	"context"
	"database/sql"
	"strings"
)

// Bringing an existing zone's AAAA records into line after the domain's IPv6
// address is set, changed or cleared.
//
// This deliberately does NOT go through SeedDefaults. That function inserts any
// template row the zone does not already hold, and the template's SPF string
// changed when IPv6 arrived: seeding a domain that already carries
// `v=spf1 ... ip4:X ~all` would add a SECOND apex TXT beside it. Two SPF records
// make a receiver return permerror for the whole domain, which fails SPF and
// takes DMARC down with it. Only AAAA records are touched here.
//
// The SPF string of an EXISTING domain is left alone for the same reason from
// the other side: it is a record the customer can edit, and rewriting one to
// insert an ip6 term is a silent change to how their mail authenticates. A
// domain seeded after an address exists gets the ip6 term from the template; an
// existing one gets it when its operator asks for it on the DNS screen.

// RepointIPv6 updates the domain's AAAA records for a change of address.
//
// previous and next are the addresses before and after the change; either may
// be empty. It returns how many records it added, changed or removed.
func RepointIPv6(ctx context.Context, db *sql.DB, domainID int64, domainName, previous, next string) (int, error) {
	previous = strings.TrimSpace(previous)
	next = strings.TrimSpace(next)
	if previous == next {
		return 0, nil
	}
	switch {
	case next == "":
		return removeIPv6Records(ctx, db, domainID, previous)
	case previous == "":
		return addIPv6Records(ctx, db, domainID, domainName, next)
	default:
		return moveIPv6Records(ctx, db, domainID, previous, next)
	}
}

// removeIPv6Records deletes the records that carried the old address.
//
// Only records holding exactly that value go. A AAAA the customer added
// pointing somewhere else is theirs and is not the panel's to delete.
func removeIPv6Records(ctx context.Context, db *sql.DB, domainID int64, previous string) (int, error) {
	if previous == "" {
		return 0, nil
	}
	result, err := db.ExecContext(ctx,
		`DELETE FROM dns_records WHERE domain_id=? AND type='AAAA' AND value=?`,
		domainID, previous)
	if err != nil {
		return 0, err
	}
	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// moveIPv6Records repoints the records that carried the old address.
//
// The rows that would collide with an existing record at the new address are
// deleted first. dns_records carries no uniqueness constraint, so a plain UPDATE
// would leave the zone holding the same AAAA twice.
func moveIPv6Records(ctx context.Context, db *sql.DB, domainID int64, previous, next string) (int, error) {
	if _, err := db.ExecContext(ctx,
		`DELETE FROM dns_records
		  WHERE domain_id=? AND type='AAAA' AND value=?
		    AND name IN (SELECT name FROM (
		          SELECT name FROM dns_records WHERE domain_id=? AND type='AAAA' AND value=?
		        ) AS existing)`,
		domainID, previous, domainID, next); err != nil {
		return 0, err
	}
	result, err := db.ExecContext(ctx,
		`UPDATE dns_records SET value=? WHERE domain_id=? AND type='AAAA' AND value=?`,
		next, domainID, previous)
	if err != nil {
		return 0, err
	}
	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// addIPv6Records writes the template's AAAA rows for a domain that had no
// address until now.
//
// A domain seeded while its IPv6 was empty has no AAAA rows at all, because
// SeedDefaults skips a record that exists only to carry an address it does not
// have. This is what gives that domain the records it never got.
func addIPv6Records(ctx context.Context, db *sql.DB, domainID int64, domainName, next string) (int, error) {
	if next == "" {
		return 0, nil
	}
	rows, err := LoadTemplate(ctx, db)
	if err != nil || len(rows) == 0 {
		rows = builtinDefaults()
	}
	meta := LoadTemplateMeta(ctx, db)
	ns1, ns2 := NameserverPair(ctx, db, domainID, domainName)

	added := 0
	for _, row := range rows {
		if !row.Enabled || !strings.EqualFold(strings.TrimSpace(row.Type), "AAAA") {
			continue
		}
		if !strings.Contains(row.Value, "{IP6}") {
			continue // a fixed AAAA in the template is not this domain's address
		}
		name := substituteTemplate(row.Name, domainName, "", next, meta.DKIMSelector, "", ns1, ns2)
		value := substituteTemplate(row.Value, domainName, "", next, meta.DKIMSelector, "", ns1, ns2)

		var count int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM dns_records WHERE domain_id=? AND name=? AND type='AAAA'`,
			domainID, name).Scan(&count); err != nil {
			return added, err
		}
		if count > 0 {
			continue // the zone already answers for this name over IPv6
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO dns_records(domain_id, name, type, value, ttl, priority, enabled)
			 VALUES(?,?,'AAAA',?,?,0,1)`,
			domainID, name, value, row.TTL); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}
