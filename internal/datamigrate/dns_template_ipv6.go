package datamigrate

import (
	"context"
	"database/sql"
	"log"
)

// BackfillDNSTemplateIPv6 adds the AAAA rows and the ip6 SPF term to an
// existing server-wide DNS template.
//
// dns.SeedTemplateIfEmpty writes the built-in rows only when the table is
// EMPTY, which is true exactly once, on the very first boot of a new install.
// Every server that already runs Servika therefore has a populated template and
// would never see a row added to the built-in set, so the AAAA records would
// reach new installs and no existing one.
//
// Nothing here is destructive. A row is added only when the same name and type
// is absent, and the SPF string is rewritten only when it still carries the
// exact text the built-in template shipped: an operator who edited their own
// SPF keeps it, because guessing at a hand-written policy is how a working mail
// setup gets broken by an upgrade.
func BackfillDNSTemplateIPv6(ctx context.Context, db *sql.DB) {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_template`).Scan(&count); err != nil {
		log.Printf("dns template ipv6 backfill: could not read the template: %v", err)
		return
	}
	if count == 0 {
		return // a fresh install; SeedTemplateIfEmpty writes the current set
	}

	added := 0
	for _, row := range ipv6TemplateRows {
		var exists int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM dns_template WHERE name=? AND type='AAAA'`, row.name).Scan(&exists); err != nil {
			log.Printf("dns template ipv6 backfill: could not check %s: %v", row.name, err)
			return
		}
		if exists > 0 {
			continue
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO dns_template(name,type,value,ttl,priority,sort_order,enabled) VALUES(?,'AAAA','{IP6}',3600,0,?,1)`,
			row.name, row.sortOrder); err != nil {
			log.Printf("dns template ipv6 backfill: could not add %s: %v", row.name, err)
			return
		}
		added++
	}

	result, err := db.ExecContext(ctx,
		`UPDATE dns_template SET value=? WHERE type='TXT' AND value=?`,
		spfWithIPv6, spfWithoutIPv6)
	if err != nil {
		log.Printf("dns template ipv6 backfill: could not update the SPF record: %v", err)
		return
	}
	updated, _ := result.RowsAffected()

	if added > 0 || updated > 0 {
		log.Printf("dns template ipv6 backfill: %d AAAA rows added, %d SPF rows updated", added, updated)
	}
}

// The built-in SPF strings, before and after. Matched EXACTLY: an operator's
// own policy is never rewritten.
const (
	spfWithoutIPv6 = "v=spf1 a mx ip4:{IP} ~all"
	spfWithIPv6    = "v=spf1 a mx ip4:{IP} ip6:{IP6} ~all"
)

// ipv6TemplateRows mirrors the AAAA rows of the built-in template. The sort
// order keeps the AAAA rows in the same relative order as the A records they
// accompany, so the screen reads in the same sequence it always did.
var ipv6TemplateRows = []struct {
	name      string
	sortOrder int
}{
	{"@", 11},
	{"www", 21},
	{"mail", 35},
	{"smtp", 36},
	{"imap", 37},
	{"autoconfig", 38},
	{"autodiscover", 39},
}

// TemplateRowNames returns the names this backfill manages, so a test can hold
// it against the built-in template rather than trusting the two lists to have
// been kept in step by hand.
func TemplateRowNames() []string {
	names := make([]string, 0, len(ipv6TemplateRows))
	for _, row := range ipv6TemplateRows {
		names = append(names, row.name)
	}
	return names
}

// SPFStrings returns the before and after SPF text for the same reason.
func SPFStrings() (before, after string) {
	return spfWithoutIPv6, spfWithIPv6
}
