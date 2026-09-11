package dns

import (
	"context"
	"database/sql"
	"log"
	"net/http"

	"servika/internal/httpx"
)

// The template only shapes zones created AFTER it changed, so new record types
// never reach the domains that already exist. This applies the mail discovery
// records to the stored template and to every existing zone, and is safe to run
// again: a row that is already there is left alone.

// MailDiscoveryResult reports what an apply run did.
type MailDiscoveryResult struct {
	TemplateAdded int `json:"template_added"`
	Domains       int `json:"domains"`
	RecordsAdded  int `json:"records_added"`
	Failed        int `json:"failed"`
}

// ApplyMailDiscovery tops up the stored template with any missing mail discovery
// row and then seeds every domain from the template.
//
// Only these rows are added. Re-applying the whole built-in set would resurrect
// records an operator had deliberately deleted, which is a different and
// unwelcome decision to make on their behalf.
func ApplyMailDiscovery(ctx context.Context, db *sql.DB) (MailDiscoveryResult, error) {
	var result MailDiscoveryResult

	for _, row := range MailDiscoveryRows() {
		var count int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM dns_template WHERE name=? AND type=? AND value=?`,
			row.Name, row.Type, row.Value).Scan(&count); err != nil {
			return result, err
		}
		if count > 0 {
			continue
		}
		enabled := 0
		if row.Enabled {
			enabled = 1
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO dns_template(name,type,value,ttl,priority,sort_order,enabled) VALUES(?,?,?,?,?,?,?)`,
			row.Name, row.Type, row.Value, row.TTL, row.Priority, row.SortOrder, enabled); err != nil {
			return result, err
		}
		result.TemplateAdded++
	}

	rows, err := db.QueryContext(ctx, `SELECT id, domain_name, COALESCE(ipv4,'') FROM domains ORDER BY id`)
	if err != nil {
		return result, err
	}
	type domainRow struct {
		id   int64
		name string
		ipv4 string
	}
	var domainList []domainRow
	for rows.Next() {
		var row domainRow
		if err := rows.Scan(&row.id, &row.name, &row.ipv4); err != nil {
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

	for _, domain := range domainList {
		result.Domains++
		added, err := seedDefaults(ctx, db, domain.id, domain.name, domain.ipv4)
		if err != nil {
			// Which domain failed goes to the log; the response carries a count,
			// because one broken zone must not stop the rest from being fixed.
			log.Printf("mail discovery records for domain %d: %v", domain.id, err)
			result.Failed++
			continue
		}
		if added == 0 {
			continue // Already had them; no need to rewrite an unchanged zone.
		}
		result.RecordsAdded += added
		if err := writeZone(ctx, db, domain.id); err != nil {
			log.Printf("write zone after adding mail discovery records for domain %d: %v", domain.id, err)
			result.Failed++
		}
	}
	return result, nil
}

// MigrateMailDiscovery is the admin endpoint behind the apply run.
func (h *Handlers) MigrateMailDiscovery(w http.ResponseWriter, r *http.Request) {
	result, err := ApplyMailDiscovery(r.Context(), h.DB)
	if err != nil {
		httpx.LogR(r, "apply mail discovery records: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "mail discovery record migration failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, result)
}
