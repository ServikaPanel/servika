package antivirus

// Which domain on this server has something wrong with it.
//
// Three screens existed and none of them answered that. The overview is
// server-wide, the history is one row per detection, and the quarantine list is
// one row per held file. A per-domain summary was nowhere, so the question an
// operator actually asks first, "which of my sites is infected", could only be
// answered by reading a detection list and grouping it by eye.
//
// Two facts about this schema shape the whole query and neither is visible from
// a domain row.
//
// A SWEEP writes av_scans.domain_id as NULL (sweep.go, schedule.go,
// sweepmode.go), so a "last scan of this domain" column can never see it. On a
// server where only the nightly sweep runs, every row would read "never" for
// good and the operator would conclude nothing is being scanned. The sweep is
// therefore reported BESIDE the per-domain scan as its own value, because they
// are two different events and neither stands in for the other.
//
// An ADDON or subdomain row carries its PARENT's system_user, and the per-domain
// scan builds its root from that name (antivirus.go). Scanning such a row would
// walk the parent's tree and file the result against the wrong domain, so only
// top-level rows are listed.

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"servika/internal/httpx"
	"servika/internal/middleware"
)

// DomainEntry is one domain with what the scanner knows about it.
type DomainEntry struct {
	DomainID   int64  `json:"domain_id"`
	Domain     string `json:"domain"`
	SystemUser string `json:"system_user"`
	// LastScanAt is the last FINISHED scan of this domain alone, empty when
	// there has never been one. It is a different claim from the server sweep
	// below, which covers this domain without producing a row for it.
	LastScanAt string `json:"last_scan_at"`
	Scanned    int    `json:"scanned"`
	Skipped    int    `json:"skipped"`
	// Uncontained is the number that means somebody has to act: a detection
	// that was left where it was found. A file in quarantine is one the panel
	// already dealt with and is counted separately.
	Uncontained int `json:"uncontained"`
	Held        int `json:"held"`
	// Scannable says whether the scan button can succeed at all. Scan refuses a
	// demo subscription with 403 and a system user outside the c_ namespace with
	// 400, and drawing a control that always fails is worse than drawing none.
	Scannable bool `json:"scannable"`
}

// AdminDomains answers GET /admin/antivirus/domains (ResellerOrAbove).
//
// The narrowing is in the QUERY rather than a middleware tier, for the reason
// every list endpoint here follows: a row-by-row ownership check would have
// already read and counted the rows a reseller may not see.
func (h *Handlers) AdminDomains(w http.ResponseWriter, r *http.Request) {
	condition, args, unrestricted := middleware.ScopeCondition(r, "d")

	// One subquery finds the last qualifying scan and the join brings every
	// column of it, rather than a correlated subquery per column.
	//
	// scope='domain' is required, and not because a sweep might match: a sweep's
	// domain_id is NULL so it never could. A REAL-TIME detection is what matches,
	// because watch.go writes a finished row with domain_id set, scope='realtime'
	// and scanned=1. Without the filter this column would report a detection as
	// "last scan, 1 file", which is not a scan of anything.
	//
	// status='finished' keeps a scan that is still running from being reported
	// as the last one with nothing scanned yet.
	query := `SELECT d.id, d.domain_name, d.system_user, COALESCE(d.is_demo, 0),
	                 s.finished_at, COALESCE(s.scanned, 0), COALESCE(s.skipped, 0),
	                 (SELECT COUNT(*) FROM av_findings f
	                    LEFT JOIN av_quarantine q
	                           ON q.finding_id = f.id AND q.restored_at IS NULL
	                   WHERE f.domain_id = d.id AND q.id IS NULL),
	                 (SELECT COUNT(*) FROM av_quarantine hq
	                   WHERE hq.domain_id = d.id AND hq.restored_at IS NULL)
	            FROM domains d
	            LEFT JOIN av_scans s ON s.id = (
	                  SELECT t.id FROM av_scans t
	                   WHERE t.domain_id = d.id AND t.scope = 'domain'
	                     AND t.status = 'finished'
	                   ORDER BY t.id DESC LIMIT 1)
	           WHERE d.parent_domain_id IS NULL`
	if !unrestricted {
		// #nosec G202 -- condition is a constant scope fragment from ScopeCondition with a literal alias; every user value is bound through args.
		query += ` AND ` + condition
	}
	// #nosec G202 -- adminMaxRows is a package constant, never caller text.
	query += ` ORDER BY d.domain_name LIMIT ` + strconv.Itoa(adminMaxRows)

	// #nosec G202 G701 -- condition is a constant scope fragment from ScopeCondition with a literal alias; every user value is bound through args.
	rows, err := h.DB.QueryContext(r.Context(), query, args...)
	if err != nil {
		log.Printf("antivirus: the domain list could not be read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the domain list")
		return
	}
	defer func() { _ = rows.Close() }()

	out := []DomainEntry{}
	for rows.Next() {
		var entry DomainEntry
		var isDemo int
		var lastScan sql.NullString
		if err := rows.Scan(&entry.DomainID, &entry.Domain, &entry.SystemUser, &isDemo,
			&lastScan, &entry.Scanned, &entry.Skipped,
			&entry.Uncontained, &entry.Held); err != nil {
			// A failed row is REPORTED, never skipped. A short list here reads as
			// fewer domains carrying findings than there are, which is the one
			// answer this screen must not invent.
			log.Printf("antivirus: a domain row could not be read: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "could not read the domain list")
			return
		}
		entry.LastScanAt = lastScan.String
		// The c_ prefix is tested in Go rather than with a LIKE, because `_` is a
		// LIKE wildcard: 'c\_%' would need escaping and 'c_%' matches any second
		// character at all.
		entry.Scannable = isDemo == 0 && strings.HasPrefix(entry.SystemUser, "c_")
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		log.Printf("antivirus: the domain list read ended early: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the domain list")
		return
	}

	sweep, err := lastSweepAt(r, h.DB)
	if err != nil {
		log.Printf("antivirus: the last sweep could not be read: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not read the domain list")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"entries": out,
		// One value for the whole server rather than a column repeated on every
		// row. It is deliberately NOT narrowed by scope: it names no domain, and
		// what it tells a reseller is whether their sites are being covered at
		// all, which is the question the per-domain column cannot answer.
		"last_sweep_at": sweep,
	})
}

// lastSweepAt reports when a scan covering the whole server last finished.
//
// A sweep is identified by a NULL domain_id, which is what every sweep entry
// point writes and what no per-domain or real-time scan ever writes.
func lastSweepAt(r *http.Request, db *sql.DB) (string, error) {
	var finished sql.NullString
	err := db.QueryRowContext(r.Context(),
		`SELECT finished_at FROM av_scans
		  WHERE domain_id IS NULL AND status = 'finished'
		  ORDER BY id DESC LIMIT 1`).Scan(&finished)
	if errors.Is(err, sql.ErrNoRows) {
		// No sweep has ever finished. That is a fact about the server, not a
		// failure, and the screen draws it as "never".
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return finished.String, nil
}
