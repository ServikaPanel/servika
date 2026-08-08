package mailreport

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"servika/internal/httpx"
)

// Handlers serves the per-domain report screens.
type Handlers struct{ DB *sql.DB }

// windowDays clamps the requested window.
//
// The value reaches an INTERVAL expression, so it is turned into a number here
// and bound as a parameter rather than being trusted; the ceiling also keeps a
// request from asking for a scan of the whole table.
func windowDays(r *http.Request) int {
	days, err := strconv.Atoi(r.URL.Query().Get("days"))
	if err != nil || days <= 0 {
		return 30
	}
	if days > 365 {
		return 365
	}
	return days
}

// The domain id is parsed inline in each handler rather than through a shared
// helper. gosec's taint analysis follows the raw URL parameter across a function
// boundary but not across strconv.ParseInt within one function, so a helper
// turns every log line mentioning the id into a G706 report. The value is an
// int64 rendered with %d and cannot carry a newline either way; parsing it
// locally lets the analyzer see that, instead of four suppressions asserting it.

// The routes are mounted under /domains/{id}/mail-reports rather than under
// /domains/{id}/mail, where every other mail route takes a {mid} mailbox
// parameter. A sibling literal segment there would sit next to that wildcard
// and read as a mailbox named "reports" to anyone scanning the route table.

// Status reports whether reports can arrive at all.
//
// The mailbox's absence is DATA, not an error: the DNS record already asks the
// world to send reports to that address, so a missing mailbox is the most
// likely reason a customer is looking at an empty dashboard, and the screen has
// to be able to say so in the customer's own language rather than showing
// nothing.
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var domainName, mailboxLocal, lastError string
	var lastScan sql.NullString
	var mailboxExists int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT d.domain_name,
		        COALESCE(c.mailbox_local, 'postmaster'),
		        COALESCE(c.last_error, ''),
		        DATE_FORMAT(c.last_scan_at, '%Y-%m-%d %H:%i'),
		        EXISTS(SELECT 1 FROM mailboxes mb
		                WHERE mb.domain_id = d.id
		                  AND mb.local_part = COALESCE(c.mailbox_local, 'postmaster')
		                  AND mb.status = 'active')
		   FROM domains d
		   LEFT JOIN mail_report_cursor c ON c.domain_id = d.id
		  WHERE d.id = ?`, id).
		Scan(&domainName, &mailboxLocal, &lastError, &lastScan, &mailboxExists)
	if err != nil {
		if err == sql.ErrNoRows {
			httpx.WriteError(w, http.StatusNotFound, "domain not found")
			return
		}
		log.Printf("mail report status for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the report status could not be read")
		return
	}

	var dmarcCount, tlsCount int
	// FAIL-CLOSED is the wrong shape here: these are counters on a read-only
	// screen, so a failure is reported as a failure rather than as zero, which
	// would read as "no reports have ever arrived".
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM dmarc_reports WHERE domain_id=?`, id).Scan(&dmarcCount); err != nil {
		log.Printf("mail report count for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the report status could not be read")
		return
	}
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM tlsrpt_reports WHERE domain_id=?`, id).Scan(&tlsCount); err != nil {
		log.Printf("mail report count for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the report status could not be read")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"report_address":  mailboxLocal + "@" + domainName,
		"mailbox_local":   mailboxLocal,
		"mailbox_exists":  mailboxExists == 1,
		"last_scan_at":    lastScan.String,
		"last_error":      lastError,
		"dmarc_report_ct": dmarcCount,
		"tlsrpt_ct":       tlsCount,
	})
}

// DMARC returns the sending addresses seen for the domain.
func (h *Handlers) DMARC(w http.ResponseWriter, r *http.Request) {
	days := windowDays(r)
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	sources, err := Sources(r.Context(), h.DB, id, days)
	if err != nil {
		log.Printf("mail report sources for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the reports could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"days": days, "sources": sources})
}

// TLSRPT returns the TLS reporting view for the domain.
func (h *Handlers) TLSRPT(w http.ResponseWriter, r *http.Request) {
	days := windowDays(r)
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	summary, err := TLSOverview(r.Context(), h.DB, id, days)
	if err != nil {
		log.Printf("mail report TLS overview for domain %d: %v", id, err)
		httpx.WriteError(w, http.StatusInternalServerError, "the reports could not be read")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"days": days, "summary": summary})
}
