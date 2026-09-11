// Package overview serves server-wide, read-only summary lists.
//
// Every existing DNS/SSL/mail/database endpoint is domain-scoped
// (/domains/{id}/dns and friends). This package provides their server-wide
// counterpart: "which certificate expires when", "which domain is missing an
// MX record", "how many mailboxes in total" answered without walking domains
// one by one. It only reads — edits still go through the domain-scoped
// endpoints, so authorization and validation logic stays in one place.
//
// Access: admin + reseller (ResellerOrAbove). Lists are narrowed with
// middleware.ScopeSQL — an admin sees every domain, a reseller only its own
// customers', a customer only its own. The narrowing is inside the query;
// filtering row by row would not prevent leaks on list endpoints.
package overview

import (
	"context"
	"database/sql"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"servika/internal/credentials"
	"servika/internal/httpx"
	"servika/internal/middleware"
)

// Handlers provides the server-wide overview HTTP handlers.
type Handlers struct{ DB *sql.DB }

// ---------- DNS ----------

type DNSRow struct {
	DomainID    int64  `json:"domain_id"`
	DomainName  string `json:"domain_name"`
	Status      string `json:"status"`
	RecordCount int    `json:"record_count"`
	ACount      int    `json:"a_count"`
	MXCount     int    `json:"mx_count"`
	TXTCount    int    `json:"txt_count"`
	DisabledN   int    `json:"disabled_count"`
	DNSSEC      bool   `json:"dnssec_active"`
}

func (h *Handlers) DNS(w http.ResponseWriter, r *http.Request) {
	q := `
SELECT d.id, d.domain_name, d.status, d.dnssec_active,
       COUNT(r.id),
       COALESCE(SUM(r.type='A'), 0),
       COALESCE(SUM(r.type='MX'), 0),
       COALESCE(SUM(r.type='TXT'), 0),
       COALESCE(SUM(r.enabled=0), 0)
FROM domains d
LEFT JOIN dns_records r ON r.domain_id = d.id`

	cond, arg := middleware.ScopeSQL(r, "d")
	// #nosec G202 -- cond is a constant scope fragment from ScopeSQL with a literal alias; user values are bound via arg placeholders.
	q += cond + `
GROUP BY d.id, d.domain_name, d.status, d.dnssec_active
ORDER BY d.domain_name`

	// #nosec G701 G202 -- cond is a constant scope fragment from ScopeSQL with a literal alias; all user values are bound via arg placeholders.
	rows, err := h.DB.QueryContext(r.Context(), q, arg...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "dns overview failed")
		return
	}
	defer func() { _ = rows.Close() }() // read-only query: closing the result set has nothing to flush

	out := make([]DNSRow, 0)
	for rows.Next() {
		var s DNSRow
		var dnssec int
		if err := rows.Scan(&s.DomainID, &s.DomainName, &s.Status, &dnssec,
			&s.RecordCount, &s.ACount, &s.MXCount, &s.TXTCount, &s.DisabledN); err != nil {
			// A dropped row is a domain missing from an overview built to show every
			// domain, so it reads as one that has no DNS at all.
			httpx.LogR(r, "overview: skipping an unreadable dns row: %v", err)
			continue
		}
		s.DNSSEC = dnssec == 1
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "dns overview failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// ---------- SSL ----------

type SSLRow struct {
	DomainID   int64  `json:"domain_id"`
	DomainName string `json:"domain_name"`
	Status     string `json:"status"`
	Enabled    bool   `json:"ssl_enabled"`
	Expiry     string `json:"ssl_expiry"` // YYYY-MM-DD, "" if unknown
	// Source is which kind of certificate is installed. Without it this screen
	// cannot tell a browser-trusted certificate from the self-signed fail-safe,
	// and showed both as plain "enabled".
	Source        string `json:"ssl_source,omitempty"`
	RemainingDays *int   `json:"remaining_days"`
}

// selfSignedSortDays is how soon a self-signed certificate is treated as
// expiring for ordering purposes.
//
// A self-signed certificate is stamped a year out, so by remaining days it sorts
// below every real one and lands at the bottom of a screen whose whole job is
// catching the ones that need attention. It is not expiring, but the site is
// already showing every visitor a warning page, so it belongs with the urgent
// ones. Fourteen days is the threshold the screen itself already treats as
// urgent, which is why it is the value used here rather than an invented one.
const selfSignedSortDays = 14

// sslUrgencyExpr is the date the SSL list sorts by: a certificate's own expiry,
// except that a self-signed one sorts as if it expired selfSignedSortDays out.
//
// Both sides are computed in SQL (CURDATE/DATE_ADD) so the comparison never
// mixes a Go clock with the MySQL session one. The interval comes from the Go
// constant rather than a second literal, so the ordering and the threshold it
// is named after cannot drift apart. The source value is spelled inline because
// it goes into SQL text; internal/domains owns the constants and writes it.
var sslUrgencyExpr = `CASE WHEN d.ssl_enabled = 1 AND d.ssl_source = 'self-signed'
              THEN DATE_ADD(CURDATE(), INTERVAL ` + strconv.Itoa(selfSignedSortDays) + ` DAY)
              ELSE d.ssl_expiry END`

// sslListQuery assembles the SSL overview statement around a scope condition.
//
// Split out so the assembly is testable: cond is a WHERE clause, so it has to
// land between the FROM and the ORDER BY, and the urgency expression has to be
// in the ORDER BY rather than only in the projection.
//
// Ordered for the screen's real job: expired, expiring and self-signed
// certificates first, then the rest by expiry, and domains with no SSL at all
// last.
func sslListQuery(cond string) string {
	// #nosec G202 -- cond is a constant scope fragment from ScopeSQL with a literal alias; user values are bound via placeholders by the caller.
	return `
SELECT d.id, d.domain_name, d.status, d.ssl_enabled,
       COALESCE(DATE_FORMAT(d.ssl_expiry, '%Y-%m-%d'), ''),
       COALESCE(d.ssl_source, ''),
       CASE WHEN d.ssl_expiry IS NULL THEN NULL ELSE DATEDIFF(d.ssl_expiry, CURDATE()) END
FROM domains d` + cond + `
ORDER BY (d.ssl_expiry IS NULL), ` + sslUrgencyExpr + ` ASC, d.domain_name`
}

func (h *Handlers) SSL(w http.ResponseWriter, r *http.Request) {
	cond, arg := middleware.ScopeSQL(r, "d")

	// #nosec G701 G202 -- the statement is assembled from package constants and a ScopeSQL fragment with a literal alias; all user values are bound via arg placeholders.
	rows, err := h.DB.QueryContext(r.Context(), sslListQuery(cond), arg...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "ssl overview failed")
		return
	}
	defer func() { _ = rows.Close() }() // read-only query: closing the result set has nothing to flush

	out := make([]SSLRow, 0)
	for rows.Next() {
		var s SSLRow
		var enabled int
		var remaining sql.NullInt64
		if err := rows.Scan(&s.DomainID, &s.DomainName, &s.Status, &enabled, &s.Expiry, &s.Source, &remaining); err != nil {
			// A dropped row hides a certificate from the screen an operator uses to
			// find the ones about to expire.
			httpx.LogR(r, "overview: skipping an unreadable ssl row: %v", err)
			continue
		}
		s.Enabled = enabled == 1
		if remaining.Valid {
			d := int(remaining.Int64)
			s.RemainingDays = &d
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "ssl overview failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// ---------- Mail ----------

type MailRow struct {
	DomainID     int64  `json:"domain_id"`
	DomainName   string `json:"domain_name"`
	MailEnabled  bool   `json:"mail_enabled"`
	MailStatus   string `json:"mail_status"` // active | suspended | "" (never provisioned)
	MailboxCount int    `json:"mailbox_count"`
	AliasCount   int    `json:"alias_count"`
	SuspendedBox int    `json:"suspended_mailbox_count"`
}

func (h *Handlers) Mail(w http.ResponseWriter, r *http.Request) {
	// Subqueries are used: JOINing mailboxes and mail_aliases at once produces a
	// cartesian product and inflates the counts.
	q := `
SELECT d.id, d.domain_name,
       COALESCE(md.status, ''),
       (SELECT COUNT(*) FROM mailboxes mb WHERE mb.domain_id = d.id),
       (SELECT COUNT(*) FROM mail_aliases a WHERE a.domain_id = d.id),
       (SELECT COUNT(*) FROM mailboxes mb2 WHERE mb2.domain_id = d.id AND mb2.status = 'suspended')
FROM domains d
LEFT JOIN mail_domains md ON md.domain_id = d.id`

	cond, arg := middleware.ScopeSQL(r, "d")
	// #nosec G202 -- cond is a constant scope fragment from ScopeSQL with a literal alias; user values are bound via arg placeholders.
	q += cond + `
ORDER BY d.domain_name`

	// #nosec G701 -- cond is a constant scope fragment from ScopeSQL with a literal alias; all user values are bound via arg placeholders.
	rows, err := h.DB.QueryContext(r.Context(), q, arg...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "mail overview failed")
		return
	}
	defer func() { _ = rows.Close() }() // read-only query: closing the result set has nothing to flush

	out := make([]MailRow, 0)
	for rows.Next() {
		var s MailRow
		if err := rows.Scan(&s.DomainID, &s.DomainName, &s.MailStatus,
			&s.MailboxCount, &s.AliasCount, &s.SuspendedBox); err != nil {
			// A dropped row reads as a domain with no mail service at all.
			httpx.LogR(r, "overview: skipping an unreadable mail row: %v", err)
			continue
		}
		s.MailEnabled = s.MailStatus != ""
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "mail overview failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// ---------- Databases ----------

type DBRow struct {
	ID         int64  `json:"id"`
	DomainID   int64  `json:"domain_id"`
	DomainName string `json:"domain_name"`
	DBName     string `json:"db_name"`
	DBUser     string `json:"db_user"`
	DBHost     string `json:"db_host"`
	DBPass     string `json:"db_pass"`
	SizeKB     int64  `json:"size_kb"`
	CreatedAt  string `json:"created_at"`
}

// revealDBPass turns a stored db_accounts.db_pass_plain into the value the
// response carries. The column holds ciphertext bound to the database user as
// AEAD associated data (see internal/credentials), so the user has to be handed
// back in for it to open.
//
// A value that will not decrypt is reported as EMPTY rather than passed
// through. Echoing the stored form would put a base64 blob where the interface
// prints a password: it is useless to whoever reads it, and it publishes the
// ciphertext of a credential to anyone who can reach the list.
//
// This is the same rule the domain-scoped list already applies
// (internal/domains.ListDatabases); both surfaces answer for the same column
// and must not disagree about what an unreadable row looks like.
func revealDBPass(dbUser, stored string) string {
	pass, err := credentials.DecryptDBPass(dbUser, stored)
	if err != nil {
		return ""
	}
	return pass
}

// dbSizes: schema name -> KB.
//
// The panel's own DSN (the `panel` user) is only privileged on the `panel`
// schema; because MySQL filters information_schema.TABLES by privilege, the
// size of customer databases is NEVER visible over that connection (it silently
// returns 0). So we follow the same path the panel uses when creating a
// database: the `mysql` client running as root's unix-socket identity (see
// internal/credentials). On error an empty map is returned — the size column
// shows "—" and the list still loads.
func dbSizes() map[string]int64 {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "mysql", "-N", "-B", "-e",
		`SELECT table_schema, COALESCE(SUM(data_length + index_length), 0) DIV 1024
		 FROM information_schema.TABLES GROUP BY table_schema`).Output()
	if err != nil {
		return map[string]int64{}
	}
	return parseDBSizes(out)
}

// parseDBSizes turns the tab-separated `mysql -N -B` output ("schema\tKB" per
// line) into a schema->KB map. Malformed lines (wrong field count, non-numeric
// size) are skipped so one bad row never blanks the whole list. Kept separate
// from dbSizes so this untrusted-subprocess parsing is unit-testable.
func parseDBSizes(raw []byte) map[string]int64 {
	sizes := make(map[string]int64)
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		field := strings.Split(line, "\t")
		if len(field) != 2 {
			continue
		}
		kb, err := strconv.ParseInt(strings.TrimSpace(field[1]), 10, 64)
		if err != nil {
			continue
		}
		sizes[strings.TrimSpace(field[0])] = kb
	}
	return sizes
}

func (h *Handlers) Databases(w http.ResponseWriter, r *http.Request) {
	q := `
SELECT a.id, a.domain_id, d.domain_name, a.db_name, a.db_user, a.db_host, a.db_pass_plain,
       COALESCE(DATE_FORMAT(a.created_at, '%Y-%m-%d'), '')
FROM db_accounts a
JOIN domains d ON d.id = a.domain_id`

	cond, arg := middleware.ScopeSQL(r, "d")
	// #nosec G202 -- cond is a constant scope fragment from ScopeSQL with a literal alias; user values are bound via arg placeholders.
	q += cond + `
ORDER BY d.domain_name, a.db_name`

	// #nosec G701 G202 -- cond is a constant scope fragment from ScopeSQL with a literal alias; all user values are bound via arg placeholders.
	rows, err := h.DB.QueryContext(r.Context(), q, arg...)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "databases overview failed")
		return
	}
	defer func() { _ = rows.Close() }() // read-only query: closing the result set has nothing to flush

	out := make([]DBRow, 0)
	for rows.Next() {
		var s DBRow
		// Scanning one row can fail without the rest of the list being wrong, so a
		// bad row is dropped instead of failing the request; it is logged rather
		// than discarded silently, because a list that is quietly short reads as
		// "this database does not exist".
		if err := rows.Scan(&s.ID, &s.DomainID, &s.DomainName, &s.DBName, &s.DBUser, &s.DBHost, &s.DBPass, &s.CreatedAt); err != nil {
			httpx.LogR(r, "overview: skipping unreadable db_accounts row: %v", err)
			continue
		}
		s.DBPass = revealDBPass(s.DBUser, s.DBPass)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "databases overview failed")
		return
	}

	sizes := dbSizes()
	for i := range out {
		out[i].SizeKB = sizes[out[i].DBName]
	}

	httpx.WriteJSON(w, http.StatusOK, out)
}
