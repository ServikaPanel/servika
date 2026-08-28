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
	// domain_id narrows the admin list to one domain, which is what the
	// per-domain detail page fetches. It is ADDED to the scope condition, never
	// instead of it, so a reseller passing another tenant's id still sees
	// nothing: ownership is enforced by ScopeSQL, the filter only trims.
	domainFilter := ""
	if raw := r.URL.Query().Get("domain_id"); raw != "" {
		if id, err := strconv.ParseInt(raw, 10, 64); err == nil && id > 0 {
			if condition == "" {
				domainFilter = " WHERE f.domain_id = ?"
			} else {
				domainFilter = " AND f.domain_id = ?"
			}
			args = append(args, id)
		}
	}
	// #nosec G701 G202 -- condition and domainFilter are constant scope/filter fragments with literal aliases; every user value is bound through args.
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT `+rowColumns+`
		   FROM security_findings f JOIN domains d ON d.id = f.domain_id`+
			condition+domainFilter+` ORDER BY `+severityRank+`, f.cvss DESC, f.id DESC LIMIT `+
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

// AppRow is one inspected installation as the screen sees it.
type AppRow struct {
	DomainID     int64  `json:"domain_id"`
	DomainName   string `json:"domain_name"`
	AppType      string `json:"app_type"`
	Install      string `json:"install_path"`
	AppVersion   string `json:"app_version"`
	PackageCount int    `json:"package_count"`
	FindingCount int    `json:"finding_count"`
	LastScanned  string `json:"last_scanned"`
}

// AppsResponse is the inventory plus the domains that are missing from it.
//
// Unscanned is the half that carries the warning. Without it an empty findings
// list means either "everything is clean" or "nothing was ever looked at", and
// those are opposite answers drawn identically.
type AppsResponse struct {
	Total     int      `json:"total"`
	Items     []AppRow `json:"items"`
	Unscanned []string `json:"unscanned_domains"`
}

// Apps — GET /admin/site-security/apps (ResellerOrAbove).
//
// BOTH queries are narrowed by ScopeSQL. Narrowing only the inventory would
// leave the unscanned list naming every domain on the server, so a reseller
// would read their neighbours' domain names off a screen built to reassure them
// about their own.
func (h *Handlers) Apps(w http.ResponseWriter, r *http.Request) {
	out := AppsResponse{Items: []AppRow{}, Unscanned: []string{}}

	condition, args := middleware.ScopeSQL(r, "d")
	// #nosec G701 G202 -- condition is a constant scope fragment from ScopeSQL with a literal alias and the limit is a strconv of a constant; every user value is bound through args.
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT a.domain_id, d.domain_name, a.app_type, a.install_path, a.app_version,
		        a.package_count, a.finding_count,
		        DATE_FORMAT(a.last_scanned,'%Y-%m-%d %H:%i')
		   FROM security_apps a JOIN domains d ON d.id = a.domain_id`+
			condition+` ORDER BY a.finding_count DESC, d.domain_name ASC, a.app_type ASC,
		        a.install_path ASC LIMIT `+strconv.Itoa(maxRows), args...)
	if err != nil {
		log.Printf("site security apps: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var row AppRow
		if err := rows.Scan(&row.DomainID, &row.DomainName, &row.AppType, &row.Install,
			&row.AppVersion, &row.PackageCount, &row.FindingCount, &row.LastScanned); err != nil {
			log.Printf("site security apps scan: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
			return
		}
		out.Items = append(out.Items, row)
	}
	// rows.Err() decides between a complete list and one the server cut short.
	// Without it a query that broke half way answers 200 with a short list, and
	// "fewer installations than expected" is precisely the reading this screen
	// must never invite.
	if err := rows.Err(); err != nil {
		log.Printf("site security apps rows: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	out.Total = len(out.Items)

	// ScopeSQL returns a whole " WHERE ..." fragment, so its own conditions are
	// appended to it rather than the other way round; with no fragment (an
	// admin) this opens the WHERE itself.
	where := " WHERE "
	if condition != "" {
		where = condition + " AND "
	}
	// #nosec G701 G202 -- where is either a literal or the constant ScopeSQL fragment with a literal alias; every user value is bound through args.
	domainRows, err := h.DB.QueryContext(r.Context(),
		`SELECT d.domain_name FROM domains d`+where+
			`d.parent_domain_id IS NULL AND d.system_user LIKE 'c\\_%'
			   AND NOT EXISTS (SELECT 1 FROM security_apps a WHERE a.domain_id = d.id)
			 ORDER BY d.domain_name LIMIT `+strconv.Itoa(maxRows), args...)
	if err != nil {
		log.Printf("site security unscanned: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer func() { _ = domainRows.Close() }()
	for domainRows.Next() {
		var name string
		if err := domainRows.Scan(&name); err != nil {
			log.Printf("site security unscanned scan: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
			return
		}
		out.Unscanned = append(out.Unscanned, name)
	}
	if err := domainRows.Err(); err != nil {
		log.Printf("site security unscanned rows: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, out)
}

// DomainRow is one domain as the monitor's single table sees it. A domain with
// several installations produces one row per installation; a domain with none
// produces one row with an empty app_type and a status of no_app or pending.
type DomainRow struct {
	DomainID     int64  `json:"domain_id"`
	DomainName   string `json:"domain_name"`
	AppType      string `json:"app_type"`
	Install      string `json:"install_path"`
	AppVersion   string `json:"app_version"`
	PackageCount int    `json:"package_count"`
	FindingCount int    `json:"finding_count"`
	LastScanned  string `json:"last_scanned"`
	Status       string `json:"status"`
}

// deriveStatus turns a domain row into the one word the badge draws. The order
// matters: a domain being scanned right now reads "scanning" whatever its stored
// counts say, and "no_app" is told apart from "pending" ONLY by everScanned (a
// whole-server sweep has finished at least once), which is the clean-versus-
// never-looked-at distinction this screen exists to keep.
func deriveStatus(running bool, scanning map[int64]bool, domainID int64,
	hasApp bool, findingCount int, everScanned bool) string {
	switch {
	case running && (len(scanning) == 0 || scanning[domainID]):
		return "scanning"
	case hasApp && findingCount > 0:
		return "open"
	case hasApp:
		return "clean"
	case everScanned:
		return "no_app"
	default:
		return "pending"
	}
}

// Domains — GET /admin/site-security/domains (ResellerOrAbove).
//
// The DRIVER is the domains table, LEFT JOINed onto security_apps, so every
// top-level tenant domain gets a row even when no app was found on it. The query
// is narrowed by ScopeSQL exactly like List, or a reseller would read their
// neighbours' domain names off a screen built to reassure them about their own.
func (h *Handlers) Domains(w http.ResponseWriter, r *http.Request) {
	everScanned, err := h.everScanned(r.Context())
	if err != nil {
		log.Printf("site security domains status: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	running, scanning := h.Collector.ScanStatus()

	condition, args := middleware.ScopeSQL(r, "d")
	where := " WHERE "
	if condition != "" {
		where = condition + " AND "
	}
	// #nosec G701 G202 -- where is either a literal or the constant ScopeSQL fragment with a literal alias, and the limit is a strconv of a constant; every user value is bound through args.
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT d.id, d.domain_name, COALESCE(a.app_type,''), COALESCE(a.install_path,''),
		        COALESCE(a.app_version,''), COALESCE(a.package_count,0), COALESCE(a.finding_count,0),
		        COALESCE(DATE_FORMAT(a.last_scanned,'%Y-%m-%d %H:%i'),'')
		   FROM domains d LEFT JOIN security_apps a ON a.domain_id = d.id`+where+
			`d.parent_domain_id IS NULL AND d.system_user LIKE 'c\\_%'
		  ORDER BY (a.app_type IS NULL) ASC, a.finding_count DESC, d.domain_name ASC,
		           a.app_type ASC, a.install_path ASC LIMIT `+strconv.Itoa(maxRows), args...)
	if err != nil {
		log.Printf("site security domains: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer func() { _ = rows.Close() }()

	out := make([]DomainRow, 0)
	for rows.Next() {
		var row DomainRow
		if err := rows.Scan(&row.DomainID, &row.DomainName, &row.AppType, &row.Install,
			&row.AppVersion, &row.PackageCount, &row.FindingCount, &row.LastScanned); err != nil {
			log.Printf("site security domains scan: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
			return
		}
		row.Status = deriveStatus(running, scanning, row.DomainID,
			row.AppType != "", row.FindingCount, everScanned)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		log.Printf("site security domains rows: %v", err)
		httpx.WriteError(w, http.StatusInternalServerError, "database read failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// everScanned reports whether a whole-server sweep has ever finished cleanly,
// which is what separates a domain with no supported app from one that has never
// been looked at.
func (h *Handlers) everScanned(ctx context.Context) (bool, error) {
	var ever bool
	err := h.DB.QueryRowContext(ctx,
		`SELECT last_success IS NOT NULL FROM security_scan_status WHERE id=1`).Scan(&ever)
	return ever, err
}

// ScanDomain — POST /admin/site-security/domain/{id}/scan (ResellerOrAbove +
// ownership). It scans one tenant site, so it is scoped by CustomerScopeParam:
// an admin passes, a reseller or customer must own the domain. The slot is the
// same one the whole-server sweep holds, so the two cannot overlap.
func (h *Handlers) ScanDomain(w http.ResponseWriter, r *http.Request) {
	domainID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || domainID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid domain")
		return
	}
	item, err := h.Collector.BeginOne(r.Context(), domainID)
	if err != nil {
		switch {
		case errors.Is(err, ErrScanRunning):
			httpx.WriteError(w, http.StatusConflict, reasonScanRunning)
		case errors.Is(err, ErrDomainNotFound):
			httpx.WriteError(w, http.StatusNotFound, "invalid domain")
		default:
			log.Printf("site security domain scan start: %v", err)
			httpx.WriteError(w, http.StatusInternalServerError, "the scan could not be started")
		}
		return
	}
	// #nosec G118 -- detaching from the request context is the point: a single-domain scan still reaches the feeds and outlives the request that asked for it; the slot is released by RunOne.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), scanBudget)
		defer cancel()
		if e := h.Collector.RunOne(ctx, item); e != nil {
			log.Printf("site security domain scan: %v", e)
		}
	}()
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"started": true})
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
