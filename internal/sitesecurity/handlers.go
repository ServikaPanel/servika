package sitesecurity

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"servika/internal/httpx"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
)

// Handlers serves the findings and the scan control.
type Handlers struct {
	DB        *sql.DB
	Collector *Collector
}

// NewHandlers builds the HTTP surface around one Collector.
func NewHandlers(db *sql.DB) *Handlers {
	return &Handlers{DB: db, Collector: New(db)}
}

// maxRows bounds one list response. A server with hundreds of neglected sites
// can hold more findings than a screen can draw, and the summary carries the
// real total.
const maxRows = 500

// Row is one finding as the screen sees it.
type Row struct {
	ID         int64   `json:"id"`
	DomainID   int64   `json:"domain_id"`
	DomainName string  `json:"domain_name"`
	AppType    string  `json:"app_type"`
	Install    string  `json:"install_path"`
	Package    string  `json:"package_name"`
	Installed  string  `json:"installed_version"`
	CVE        string  `json:"cve_id"`
	Severity   string  `json:"severity"`
	CVSS       float64 `json:"cvss"`
	Title      string  `json:"title"`
	FixedIn    string  `json:"fixed_in"`
	Source     string  `json:"source"`
	FirstSeen  string  `json:"first_seen"`
	LastSeen   string  `json:"last_seen"`
}

// Status is the state of the last or current sweep.
//
// unparsed_packages is reported beside the finding count on purpose. A sweep
// that could not judge forty versions is not the same as one that found
// nothing, and showing only the second would present the first as a clean bill
// of health.
type Status struct {
	State            string `json:"state"`
	StartedAt        string `json:"started_at"`
	FinishedAt       string `json:"finished_at"`
	ScannedDomains   int    `json:"scanned_domains"`
	ScannedPackages  int    `json:"scanned_packages"`
	UnparsedPackages int    `json:"unparsed_packages"`
	FindingCount     int    `json:"finding_count"`
	LastError        string `json:"last_error"`
}

const rowColumns = `f.id, f.domain_id, d.domain_name, f.app_type, f.install_path,
	f.package_name, f.installed_version, f.cve_id, f.severity, COALESCE(f.cvss,0),
	f.title, f.fixed_in, f.source,
	DATE_FORMAT(f.first_seen,'%Y-%m-%d %H:%i'), DATE_FORMAT(f.last_seen,'%Y-%m-%d %H:%i')`

// severityRank orders the list by how bad the finding is, in SQL, so paging
// past maxRows drops the least serious rows rather than an arbitrary set.
const severityRank = `CASE f.severity
	WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
	WHEN 'low' THEN 3 ELSE 4 END`

func scanRows(rows *sql.Rows) ([]Row, error) {
	out := make([]Row, 0)
	for rows.Next() {
		var row Row
		if err := rows.Scan(&row.ID, &row.DomainID, &row.DomainName, &row.AppType,
			&row.Install, &row.Package, &row.Installed, &row.CVE, &row.Severity,
			&row.CVSS, &row.Title, &row.FixedIn, &row.Source,
			&row.FirstSeen, &row.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// List — GET /admin/site-security (ResellerOrAbove).
//
// The query is NARROWED by ScopeSQL rather than filtered row by row after the
// fact: a row-by-row ownership check does not work on a list endpoint, because
// the rows a reseller may not see would already have been read and counted.
func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	condition, args := middleware.ScopeSQL(r, "d")
	// #nosec G701 G202 -- condition is a constant scope fragment from ScopeSQL with a literal alias; every user value is bound through args.
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT `+rowColumns+`
		   FROM security_findings f JOIN domains d ON d.id = f.domain_id`+
			condition+` ORDER BY `+severityRank+`, f.cvss DESC, f.id DESC LIMIT `+
			strconv.Itoa(maxRows), args...)
	if err != nil {
		log.Printf("site security list: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer func() { _ = rows.Close() }()

	out, err := scanRows(rows)
	if err != nil {
		log.Printf("site security list scan: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// DomainList — GET /domains/{id}/site-security (CustomerScope).
func (h *Handlers) DomainList(w http.ResponseWriter, r *http.Request) {
	domainID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || domainID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid domain")
		return
	}
	// #nosec G701 G202 -- every concatenated part is a package constant (rowColumns, severityRank, a strconv of a constant); the only value is bound through a placeholder.
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT `+rowColumns+`
		   FROM security_findings f JOIN domains d ON d.id = f.domain_id
		  WHERE f.domain_id = ?
		  ORDER BY `+severityRank+`, f.cvss DESC, f.id DESC LIMIT `+strconv.Itoa(maxRows),
		domainID)
	if err != nil {
		log.Printf("site security domain list: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer func() { _ = rows.Close() }()

	out, err := scanRows(rows)
	if err != nil {
		log.Printf("site security domain list scan: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// Status — GET /admin/site-security/status (ResellerOrAbove).
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	var status Status
	var started, finished sql.NullString
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT state, DATE_FORMAT(started_at,'%Y-%m-%d %H:%i'),
		        DATE_FORMAT(finished_at,'%Y-%m-%d %H:%i'),
		        scanned_domains, scanned_packages, unparsed_packages, finding_count, last_error
		   FROM security_scan_status WHERE id=1`).
		Scan(&status.State, &started, &finished, &status.ScannedDomains,
			&status.ScannedPackages, &status.UnparsedPackages, &status.FindingCount,
			&status.LastError)
	if err != nil {
		log.Printf("site security status: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	status.StartedAt = started.String
	status.FinishedAt = finished.String
	httpx.WriteJSON(w, http.StatusOK, status)
}

// reasonScanRunning is the stable code a refused start answers with.
const reasonScanRunning = "security_scan_already_running"

// Scan — POST /admin/site-security/scan (AdminOnly).
//
// Manual scanning is admin only. It runs wp-cli against every site on the
// server and sends every package name to two feeds, which is a server-wide
// action whatever scope the person asking has.
//
// The sweep runs on its OWN context, detached from the request: it takes
// minutes, and the operator closing the tab must not kill it half way and leave
// the state row saying running.
func (h *Handlers) Scan(w http.ResponseWriter, r *http.Request) {
	// The lock is taken HERE rather than inside the goroutine, so a refusal is
	// answered as a refusal instead of reported as a start that quietly did
	// nothing.
	if err := h.Collector.begin(r.Context()); err != nil {
		if errors.Is(err, ErrScanRunning) {
			httpx.WriteError(w, http.StatusConflict, reasonScanRunning)
			return
		}
		log.Printf("site security scan start: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the scan could not be started")
		return
	}
	// #nosec G118 -- detaching from the request context is the point: the sweep takes minutes and the operator closing the tab must not kill it half way and strand the state row on 'running'.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), scanBudget)
		defer cancel()
		counts, err := h.Collector.scan(ctx)
		h.Collector.finish(counts, err)
		if err != nil {
			log.Printf("site security scan: %v", err)
		}
	}()
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

// Interval reports how often the unattended sweep runs, so the screen can say
// so instead of hard-coding a number that would drift from the constant.
func Interval() time.Duration { return scanInterval }
