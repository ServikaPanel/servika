package antivirus

// The server-wide sweep: one scan across every tenant tree, or across the whole
// filesystem, instead of one domain at a time.
//
// A per-domain scan can only be started by somebody who knows which domain to
// suspect. The sweep is for the case nobody does, which is every case before
// the first symptom. It reuses the same worker, the same rules, the same
// av_findings rows and the same quarantine, because a second finding model
// would need its own screen and its own containment path.
//
// Two things separate it from a domain scan and both are recorded rather than
// implied. av_scans.scope says how wide it was, and av_findings.domain_id is
// resolved PER FINDING from the path, so a webshell found under a tenant home
// is attributed to that tenant and can be contained into that tenant's own
// quarantine store, while one found outside every home is reported and nothing
// more: the store is keyed on a tenant, so there is nowhere for such a file to
// go and offering the action would be offering a button that always fails.

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"strings"

	"servika/internal/avsettings"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

// homePrefix is where a tenant tree lives. A finding under it belongs to the
// tenant that owns that system user; a finding anywhere else belongs to nobody
// the panel can act for.
const homePrefix = "/home/"

// Sweep starts a server-wide scan.
//
// POST /admin/antivirus/sweep. It is admin-only and has no scoped variant:
// there is no ownership chain to narrow a sweep of the whole server by, and its
// scope is a server-wide setting rather than a per-request choice.
func (h *Handlers) Sweep(w http.ResponseWriter, r *http.Request) {
	settings, err := avsettings.Read(r.Context(), h.DB)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the antivirus settings could not be read")
		return
	}
	req := sweepRequest(settings)
	if !req.RuleEngine && !req.LocationHeuristics {
		httpx.WriteError(w, http.StatusConflict,
			"every detection layer is switched off, so a sweep would inspect nothing")
		return
	}

	// The same single slot a domain scan takes. A sweep running beside a domain
	// scan would read the same trees twice under one resource limit.
	if !scanning.CompareAndSwap(0, 1) {
		httpx.WriteError(w, http.StatusConflict, "another server scan is in progress; please wait")
		return
	}
	// domain_id is NULL: a sweep has no domain. Its findings resolve one each.
	res, err := h.DB.Exec(
		`INSERT INTO av_scans (domain_id, scope, status, engine) VALUES (NULL,?,?,?)`,
		settings.Scope, "running", engineName())
	if err != nil {
		scanning.Store(0)
		httpx.WriteError(w, http.StatusInternalServerError, "could not create scan record")
		return
	}
	sid, _ := res.LastInsertId()

	// #nosec G118 -- the request context is deliberately NOT used: the caller gets
	// a scan id immediately and polls, so closing the tab must not cancel a sweep
	// of the whole server that is already under way.
	go func() {
		defer scanning.Store(0)
		ctx, cancel := context.WithTimeout(context.Background(), parentBudget)
		defer cancel()
		runSweep(ctx, h.DB, sid, req)
	}()

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"scan_id": sid, "scope": settings.Scope, "roots": req.Roots,
	})
}

// sweepRequest turns the operator's settings into a scan request.
//
// The handler and the scheduler both start the same sweep, so they build it
// through one function: a switch honoured on one path and not the other is a
// switch that is not honoured.
func sweepRequest(s avsettings.Settings) ScanRequest {
	return ScanRequest{
		Roots:              s.ScanRoots(),
		RuleEngine:         s.RuleEngine,
		LocationHeuristics: s.LocationHeuristics,
		CriticalThreshold:  s.CriticalThreshold,
		Excluded:           s.ExcludedList(),
		AutoQuarantine:     s.AutoQuarantine,
	}
}

// runSweep performs a sweep whose row already exists and whose lock is already
// held, and closes the row when it is done.
//
// The caller owns the lock rather than this function, because the handler has to
// answer a refusal before it starts a goroutine while the scheduler simply skips
// the hour.
func runSweep(ctx context.Context, db *sql.DB, sid int64, req ScanRequest) {
	result, confined, err := Scan(ctx, req, "sweep-"+strconv.FormatInt(sid, 10))
	if err != nil {
		// #nosec G706 -- logged values are an integer scan id and systemd command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("antivirus: sweep %d could not run: %v", sid, err)
	}
	owners := newOwnerLookup(db)
	for _, f := range result.Findings {
		if err := insertSweepFinding(db, sid, owners.forPath(f.File), f); err != nil {
			// #nosec G706 -- logged values are an integer scan id and a database error; no raw tenant string with CR/LF reaches the log.
			log.Printf("antivirus: sweep %d could not record a finding: %v", sid, err)
		}
	}
	// Containment runs BEFORE the status is written, so a screen that sees a
	// finished sweep sees the containment that went with it.
	if req.AutoQuarantine {
		recordAutoQuarantine(db, sid, (&Handlers{DB: db}).autoQuarantine(ctx, sid))
	}
	status := "finished"
	if err != nil || result.Partial || ctx.Err() != nil {
		status = "failed"
	}
	if _, err := db.Exec(
		`UPDATE av_scans SET status=?, scanned=?, infected=?, confined=?, finished_at=NOW() WHERE id=?`,
		status, result.Scanned, len(result.Findings), confined, sid); err != nil {
		log.Printf("antivirus: sweep %d could not be closed: %v", sid, err)
	}
}

// SweepStatus reports one sweep. GET /admin/antivirus/sweep/{sid}.
func (h *Handlers) SweepStatus(w http.ResponseWriter, r *http.Request) {
	sid, _ := strconv.ParseInt(chi.URLParam(r, "sid"), 10, 64)
	var status, scope, engine, startedAt string
	var finishedAt sql.NullString
	var scanned, infected, autoTaken, autoFailed int
	var confined bool
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT status, scope, engine, scanned, infected, confined,
		        auto_quarantined, auto_quarantine_failed, started_at, finished_at
		   FROM av_scans WHERE id=? AND domain_id IS NULL`, sid).
		Scan(&status, &scope, &engine, &scanned, &infected, &confined,
			&autoTaken, &autoFailed, &startedAt, &finishedAt); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "sweep not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id": sid, "status": status, "scope": scope, "engine": engine,
		"scanned": scanned, "infected": infected, "confined": confined,
		"started_at": startedAt, "finished_at": finishedAt.String,
		"auto_quarantined": autoTaken, "auto_quarantine_failed": autoFailed,
		"findings": h.sweepFindings(r.Context(), sid),
	})
}

// SweepList reports the sweeps this server has run.
// GET /admin/antivirus/sweep.
func (h *Handlers) SweepList(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, status, scope, engine, scanned, infected, confined,
		        auto_quarantined, auto_quarantine_failed, started_at, finished_at
		   FROM av_scans WHERE domain_id IS NULL ORDER BY id DESC LIMIT 50`)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the sweeps could not be listed")
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id int64
		var status, scope, engine, startedAt string
		var finishedAt sql.NullString
		var scanned, infected, autoTaken, autoFailed int
		var confined bool
		if err := rows.Scan(&id, &status, &scope, &engine, &scanned, &infected,
			&confined, &autoTaken, &autoFailed, &startedAt, &finishedAt); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "status": status, "scope": scope, "engine": engine,
			"scanned": scanned, "infected": infected, "confined": confined,
			"auto_quarantined": autoTaken, "auto_quarantine_failed": autoFailed,
			"started_at": startedAt, "finished_at": finishedAt.String,
		})
	}
	// A query that broke half way would otherwise answer 200 with a short list,
	// and "fewer sweeps than expected" reads as a server that has been scanned
	// less often than it has.
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the sweeps could not be listed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// sweepFindings reads one sweep's findings, including the ones that belong to no
// domain.
func (h *Handlers) sweepFindings(ctx context.Context, sid int64) []Finding {
	out := []Finding{}
	rows, err := h.DB.QueryContext(ctx,
		`SELECT id, file, signature, engine, score, level, COALESCE(rules,''), quarantined,
		        COALESCE(domain_id, 0)
		   FROM av_findings WHERE scan_id=? ORDER BY score DESC, id`, sid)
	if err != nil {
		return out
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.File, &f.Signature, &f.Engine,
			&f.Score, &f.Level, &f.Rules, &f.Quarantine, &f.DomainID); err == nil {
			out = append(out, f)
		}
	}
	_ = rows.Err()
	return out
}

// insertSweepFinding writes a finding whose domain may be unknown.
//
// It is separate from insertFinding because that one takes a domain id the
// caller already knows; here NULL is a real answer and 0 would be a foreign key
// pointing at nothing.
func insertSweepFinding(db *sql.DB, scanID int64, domainID sql.NullInt64, finding Finding) error {
	level, score := finding.Level, finding.Score
	if level == "" {
		level, score = LevelCritical, scoreCritical
	}
	_, err := db.Exec(
		`INSERT INTO av_findings (scan_id, domain_id, file, signature, engine, score, level, rules)
		 VALUES (?,?,?,?,?,?,?,?)`,
		scanID, domainID, finding.File, finding.Signature, finding.Engine, score, level, finding.Rules)
	return err
}

// ownerLookup resolves the tenant a swept path belongs to.
//
// A sweep produces at most a few hundred findings but they cluster in a handful
// of homes, so the answer is cached per system user. A lookup that FAILS is
// cached as "no owner" rather than retried per finding: the alternative is one
// database round trip per finding on a server whose database is already the
// thing that failed.
type ownerLookup struct {
	db    *sql.DB
	cache map[string]sql.NullInt64
}

func newOwnerLookup(db *sql.DB) *ownerLookup {
	return &ownerLookup{db: db, cache: map[string]sql.NullInt64{}}
}

// forPath returns the domain that owns a path, or a NULL id.
func (o *ownerLookup) forPath(path string) sql.NullInt64 {
	user, ok := systemUserFromPath(path)
	if !ok {
		return sql.NullInt64{}
	}
	if id, seen := o.cache[user]; seen {
		return id
	}
	var id sql.NullInt64
	// Only a top-level row carries a system user of its own; an addon or
	// subdomain row repeats its parent's, so narrowing to the parent is what
	// makes this answer one domain rather than an arbitrary one of several.
	var found int64
	err := o.db.QueryRow(
		`SELECT id FROM domains WHERE system_user=? AND parent_domain_id IS NULL LIMIT 1`, user).
		Scan(&found)
	if err == nil {
		id = sql.NullInt64{Int64: found, Valid: true}
	}
	o.cache[user] = id
	return id
}

// systemUserFromPath extracts the tenant identity from an absolute path.
//
// Only /home/<user>/... counts. The name is checked against the tenant prefix
// every other part of the panel keys on, so a directory somebody created under
// /home by hand cannot be reported as a tenant's.
func systemUserFromPath(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, homePrefix)
	if !ok {
		return "", false
	}
	user, _, ok := strings.Cut(rest, "/")
	if !ok || user == "" || !strings.HasPrefix(user, "c_") {
		return "", false
	}
	return user, true
}

// SweepQuarantine contains one finding from a sweep.
// POST /admin/antivirus/sweep/finding/{fid}/quarantine.
//
// It exists because the per-domain endpoint is reached through a domain URL and
// a sweep has no domain in its URL. The containment itself is the SAME code: the
// tenant is read from the finding's own row, never from the request, so an
// admin cannot name a domain the file does not belong to.
func (h *Handlers) SweepQuarantine(w http.ResponseWriter, r *http.Request) {
	fid, _ := strconv.ParseInt(chi.URLParam(r, "fid"), 10, 64)
	domainID, systemUser, reason := h.sweepFindingOwner(r.Context(), fid)
	if reason != "" {
		writeReason(w, reason)
		return
	}
	if reason := h.quarantineFinding(domainID, systemUser, fid); reason != "" {
		writeReason(w, reason)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// sweepFindingOwner resolves the tenant a finding belongs to, or a reason code.
//
// A finding with no domain is REFUSED rather than contained somewhere generic.
// The quarantine store lives at one directory per tenant and RemoveStoreForUser
// refuses any name without the tenant prefix, so a file outside every home has
// nowhere to go: containing it would mean inventing a store the rest of the
// package cannot manage.
func (h *Handlers) sweepFindingOwner(ctx context.Context, findingID int64) (int64, string, string) {
	var domainID sql.NullInt64
	if err := h.DB.QueryRowContext(ctx,
		`SELECT domain_id FROM av_findings WHERE id=?`, findingID).Scan(&domainID); err != nil {
		return 0, "", reasonFindingUnknown
	}
	if !domainID.Valid {
		return 0, "", reasonPathOutsideHome
	}
	var systemUser string
	if err := h.DB.QueryRowContext(ctx,
		`SELECT system_user FROM domains WHERE id=?`, domainID.Int64).Scan(&systemUser); err != nil {
		return 0, "", reasonFindingUnknown
	}
	return domainID.Int64, systemUser, ""
}
