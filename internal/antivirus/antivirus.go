// Package antivirus provides per-domain malware scanning with ClamAV and lightweight heuristics.
// A server-wide atomic lock allows only one scan at a time to limit memory pressure.
// Quarantine lives in quarantine.go: a file is copied out of the tenant tree into
// a root-owned store outside every home, and the original is removed last.
package antivirus

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"servika/internal/avsettings"
	"servika/internal/config"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

func clamBin() string { return config.ClamScanBin() }

func freshclamBin() string { return config.FreshclamBin() }

type Handlers struct{ DB *sql.DB }

// scanning is a server-wide lock. A single slot prevents ClamAV database memory pressure.
var scanning atomic.Int32

// scanBudget bounds one scan. It is not tied to the request: the caller gets a
// scan id immediately and polls, so closing the tab must not stop the sweep.
const scanBudget = 8 * time.Minute

// HealRunningScans closes the scans that were in flight when the panel stopped.
//
// The single-slot lock lives in memory, so a restart frees it while the row
// stays 'running' for good: the screen then shows a scan that never ends and
// never lets the customer start another. There is no process to wait for after a
// restart, so every such row is failed rather than resumed.
func HealRunningScans(db *sql.DB) {
	if db == nil {
		return
	}
	result, err := db.Exec(`UPDATE av_scans SET status='failed', finished_at=NOW() WHERE status='running'`)
	if err != nil {
		log.Printf("antivirus: could not close the scans left running: %v", err)
		return
	}
	if closed, err := result.RowsAffected(); err == nil && closed > 0 {
		log.Printf("antivirus: closed %d scan(s) left running by a restart", closed)
	}
}

var errCap = errors.New("file-limit-reached")

// fileCap bounds one walk. It exists so the 8-minute budget is reached by a
// sweep that is genuinely huge rather than by one that is stuck, and a walk
// that hits it is reported as INCOMPLETE.
//
// It is a variable so a test can exercise the cap without writing fifty
// thousand files, which took 24 seconds and would be paid on every CI run.
var fileCap = 50000

type Finding struct {
	// ID is what the quarantine endpoint takes. The path is deliberately not
	// accepted from a caller, so the screen has to name the row instead.
	ID        int64  `json:"id"`
	File      string `json:"file"`
	Signature string `json:"signature"`
	Engine    string `json:"engine"`
	// Score is the weighed evidence and Level is the verdict it produced. A
	// detector with a verdict of its own (ClamAV, the WordPress checksum check)
	// leaves both empty and RecordScan fills in the critical end.
	Score int    `json:"score"`
	Level string `json:"level"`
	// Rules names every heuristic that matched, where Signature names only the
	// highest-scoring one. It is empty for a detector that has no rule set.
	Rules      string `json:"rules"`
	Quarantine int    `json:"quarantined"`
}

func (h *Handlers) domain(r *http.Request) (id int64, systemUser string, demo, ok bool) {
	id, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var isDemo int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user, COALESCE(is_demo,0) FROM domains WHERE id=?`, id).Scan(&systemUser, &isDemo); err != nil {
		return id, "", false, false
	}
	return id, systemUser, isDemo == 1, true
}

func newestClamDB() string {
	var newest time.Time
	for _, f := range []string{"daily.cld", "daily.cvd", "main.cld", "main.cvd"} {
		if fi, err := os.Stat("/var/lib/clamav/" + f); err == nil {
			if fi.ModTime().After(newest) {
				newest = fi.ModTime()
			}
		}
	}
	if newest.IsZero() {
		return ""
	}
	return newest.Format("2006-01-02 15:04")
}

func engineName() string {
	if _, err := os.Stat(clamBin()); err == nil {
		return "clamav+heuristic"
	}
	return "heuristic"
}

// GET /domains/{id}/antivirus
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	id, systemUser, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	_, clamErr := os.Stat(clamBin())
	resp := map[string]any{
		"clamav":         clamErr == nil,
		"signature_date": newestClamDB(),
		"username":       systemUser,
		"last_scan":      nil,
		"findings":       []Finding{},
	}
	var sid int64
	var status, engine, startedAt string
	var finishedAt sql.NullString
	var scanned, infected int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, status, engine, scanned, infected, started_at, finished_at
		   FROM av_scans WHERE domain_id=? ORDER BY id DESC LIMIT 1`, id).
		Scan(&sid, &status, &engine, &scanned, &infected, &startedAt, &finishedAt); err == nil {
		resp["last_scan"] = map[string]any{
			"id": sid, "status": status, "engine": engine, "scanned": scanned,
			"infected": infected, "started_at": startedAt, "finished_at": finishedAt.String,
		}
		resp["findings"] = h.findings(r.Context(), sid)
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// RecordScan writes a finished scan and its findings, for a source of findings
// other than this package's own file scan.
//
// It exists so a second detector reaches the SAME screen, the same quarantine
// and the same bulk cleanup instead of growing a parallel finding model that
// would need its own listing and its own containment path. The caller owns the
// engine name, which is what the screen groups by.
//
// The paths must already be absolute and under the tenant home: the quarantine
// path refuses anything else, but a caller that records a bad path leaves a
// finding nothing can act on.
//
// A caller that leaves Level empty is a detector with a verdict of its own
// rather than a weighed one, so its finding is recorded at the critical end.
// Defaulting the other way would silently demote every such finding to a level
// the screen shows less prominently, which for a webshell is the wrong
// direction to be wrong in.
func RecordScan(db *sql.DB, domainID int64, engine string, scanned int, findings []Finding) (int64, error) {
	result, err := db.Exec(
		`INSERT INTO av_scans (domain_id, status, engine, scanned, infected, finished_at)
		 VALUES (?, 'finished', ?, ?, ?, NOW())`,
		domainID, engine, scanned, len(findings))
	if err != nil {
		return 0, err
	}
	scanID, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	for _, finding := range findings {
		if err := insertFinding(db, scanID, domainID, finding); err != nil {
			return scanID, err
		}
	}
	return scanID, nil
}

// scanRequest builds a request from the operator's stored settings.
//
// The settings are read here, in the panel process, and travel to the worker in
// its request file. Letting the worker read them itself would give it a
// database connection, which is the one thing keeping it a scanner rather than
// a second half of the panel.
func scanRequest(ctx context.Context, db *sql.DB, roots ...string) (ScanRequest, error) {
	settings, err := avsettings.Read(ctx, db)
	if err != nil {
		return ScanRequest{}, err
	}
	return ScanRequest{
		Roots:              roots,
		RuleEngine:         settings.RuleEngine,
		LocationHeuristics: settings.LocationHeuristics,
		CriticalThreshold:  settings.CriticalThreshold,
	}, nil
}

// insertFinding is the one place a finding row is written, so the critical
// default cannot be applied on one path and forgotten on the other.
func insertFinding(db *sql.DB, scanID, domainID int64, finding Finding) error {
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

func (h *Handlers) findings(ctx context.Context, sid int64) []Finding {
	out := []Finding{}
	rows, err := h.DB.QueryContext(ctx,
		`SELECT id, file, signature, engine, score, level, COALESCE(rules,''), quarantined
		   FROM av_findings WHERE scan_id=? ORDER BY score DESC, id`, sid)
	if err != nil {
		return out
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var b Finding
		if err := rows.Scan(&b.ID, &b.File, &b.Signature, &b.Engine,
			&b.Score, &b.Level, &b.Rules, &b.Quarantine); err == nil {
			out = append(out, b)
		}
	}
	_ = rows.Err()
	return out
}

// POST /domains/{id}/antivirus/scan
func (h *Handlers) Scan(w http.ResponseWriter, r *http.Request) {
	id, systemUser, demo, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo {
		httpx.WriteError(w, http.StatusForbidden, "not available for demo subscriptions")
		return
	}
	if !strings.HasPrefix(systemUser, "c_") {
		httpx.WriteError(w, http.StatusBadRequest, "invalid user")
		return
	}
	root := "/home/" + systemUser + "/public_html"
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if _, err := os.Stat(root); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "public_html not found")
		return
	}
	// The layer switches are read BEFORE the lock is taken and travel with the
	// request, because the worker has no database connection to read them with.
	// An unreadable settings row does not silently fall back to scanning
	// everything: the operator turned a layer off on a server the scan was
	// slowing down, and ignoring that is the failure they would notice.
	req, err := scanRequest(r.Context(), h.DB, root)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "the antivirus settings could not be read")
		return
	}
	if !scanning.CompareAndSwap(0, 1) {
		httpx.WriteError(w, http.StatusConflict, "another server scan is in progress; please wait")
		return
	}
	res, err := h.DB.Exec(`INSERT INTO av_scans (domain_id, status, engine) VALUES (?,?,?)`, id, "running", engineName())
	if err != nil {
		scanning.Store(0)
		httpx.WriteError(w, http.StatusInternalServerError, "could not create scan record")
		return
	}
	sid, _ := res.LastInsertId()
	// #nosec G118 -- the request context is deliberately NOT used: the caller
	// gets a scan id immediately and polls for the result, so closing the tab
	// must not cancel a sweep that is already under way. The scan carries its
	// own budget instead, and the settings it needs were read from the request
	// context above, before this goroutine starts.
	go func() {
		defer scanning.Store(0)
		ctx, cancel := context.WithTimeout(context.Background(), parentBudget)
		defer cancel()
		result, confined, err := Scan(ctx, req, strconv.FormatInt(sid, 10))
		if err != nil {
			// #nosec G706 -- logged values are an integer scan id and systemd command output; no raw tenant string with CR/LF reaches the log.
			log.Printf("antivirus: scan %d could not run: %v", sid, err)
		}
		for _, f := range result.Findings {
			_ = insertFinding(h.DB, sid, id, f)
		}
		// A scan that ran out of its budget covered part of the tree, so it is
		// recorded as FAILED with the findings it did get. Calling it finished
		// would present a partial sweep as a clean bill of health, which for a
		// webshell in the part that was never reached is the worst answer the
		// screen can give. A scan that could not be placed in the resource slice
		// at all is failed for the same reason: it produced nothing, and an
		// empty finding list is exactly what a clean site looks like.
		status := "finished"
		if err != nil || result.Partial || ctx.Err() != nil {
			status = "failed"
		}
		_, _ = h.DB.Exec(`UPDATE av_scans SET status=?, scanned=?, infected=?, confined=?, finished_at=NOW() WHERE id=?`,
			status, result.Scanned, len(result.Findings), confined, sid)
	}()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"scan_id": sid})
}

// GET /domains/{id}/antivirus/scan/{sid}
func (h *Handlers) ScanStatus(w http.ResponseWriter, r *http.Request) {
	id, _, _, ok := h.domain(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	sid, _ := strconv.ParseInt(chi.URLParam(r, "sid"), 10, 64)
	var status, engine, startedAt string
	var finishedAt sql.NullString
	var scanned, infected int
	var confined bool
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT status, engine, scanned, infected, confined, started_at, finished_at FROM av_scans WHERE id=? AND domain_id=?`, sid, id).
		Scan(&status, &engine, &scanned, &infected, &confined, &startedAt, &finishedAt); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "scan not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id": sid, "status": status, "engine": engine, "scanned": scanned,
		"infected": infected, "started_at": startedAt, "finished_at": finishedAt.String,
		// confined says whether the kernel really held the scan to the
		// operator's resource limits. It is reported rather than assumed,
		// because a host with no systemd runs the scan unlimited and nothing
		// else on this screen would say so.
		"confined": confined,
		"findings": h.findings(r.Context(), sid),
	})
}

// POST /domains/{id}/antivirus/update-signature  → freshclam
func (h *Handlers) UpdateSignature(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat(freshclamBin()); err != nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "freshclam is not installed")
		return
	}
	if !scanning.CompareAndSwap(0, 1) {
		httpx.WriteError(w, http.StatusConflict, "another operation is in progress; please wait")
		return
	}
	defer scanning.Store(0)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	out, err := exec.CommandContext(ctx, freshclamBin()).CombinedOutput()
	output := string(out)
	if len(output) > 4000 {
		output = output[len(output)-4000:]
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok": err == nil, "signature_date": newestClamDB(), "output": output,
	})
}

// runScan: ClamAV (if available) + heuristics. Returns scanned file count + findings.
//
// A layer the request turns off is SKIPPED, not run and then filtered. Filtering
// would throw away the only concrete thing turning a layer off buys, which is
// the CPU and the file reads it does not spend, and the operator turning it off
// is doing so on a server the scan is slowing down.
func runScan(ctx context.Context, root string, req ScanRequest) (scanned int, findings []Finding, complete bool) {
	seen := map[string]bool{}

	// 1) ClamAV
	if _, err := os.Stat(clamBin()); err == nil {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		cmd := exec.CommandContext(ctx, clamBin(), "-r", "-i", "--no-summary", "--stdout",
			"--max-filesize=25M", "--max-scansize=500M", root)
		out, _ := cmd.CombinedOutput()
		for line := range strings.SplitSeq(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasSuffix(line, " FOUND") {
				if i := strings.LastIndex(line, ": "); i > 0 {
					file := line[:i]
					signature := strings.TrimSuffix(line[i+2:], " FOUND")
					if !seen["c|"+file] {
						seen["c|"+file] = true
						// ClamAV reached a verdict of its own rather than an
						// evidence weight, so it is recorded at the critical end
						// instead of being fed through the thresholds.
						findings = append(findings, Finding{
							File: file, Signature: signature, Engine: "clamav",
							Score: scoreCritical, Level: LevelCritical,
						})
					}
				}
			}
		}
	}

	// 2) Heuristic scan of the file kinds a site executes or serves
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".quarantined":
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		limit := readLimitFor(ext)
		if !req.RuleEngine {
			limit = 0
		}
		// The path is judged even when the content will not be read. A payload
		// can sit in a file past the read limit, and where it sits is evidence
		// that costs nothing to collect.
		var matches []match
		if req.LocationHeuristics {
			matches = locationMatches(root, p)
		}
		if limit == 0 && len(matches) == 0 {
			return nil
		}
		fi, e := d.Info()
		if e != nil {
			return nil
		}
		scanned++
		if scanned > fileCap {
			return errCap
		}
		if limit > 0 && fi.Size() <= limit {
			// #nosec G122 G304 -- operator-initiated antivirus scan reads files under the scan root; content is only pattern-matched, never returned to a tenant.
			if b, e := os.ReadFile(p); e == nil {
				matches = append(matches, evaluate(ext, b)...)
			}
		}
		// One finding per FILE, not per matching rule. Three rows for one file
		// used to mean bulk cleanup contained it on the first row and then
		// reported "file missing" twice for the same file it had just
		// quarantined, so a successful cleanup read as two failures.
		score, signature, matched, level := verdict(matches, req.CriticalThreshold)
		if level == "" || seen["h|"+p] {
			return nil
		}
		seen["h|"+p] = true
		findings = append(findings, Finding{
			File: p, Signature: signature, Engine: "heuristic",
			Score: score, Level: level, Rules: strings.Join(matched, ", "),
		})
		return nil
	})
	// A sweep that stopped at the file cap or ran out of its budget covered part
	// of the tree. Reporting it as complete would present it as a clean bill of
	// health for everything it never reached, which is the same defect the
	// status check in the handler exists to prevent. The cap was silently
	// swallowed here before: the walk's error was discarded and 50000 files was
	// reported as a finished scan of the whole tree.
	return scanned, findings, walkErr == nil && ctx.Err() == nil
}

// phpish reports whether a PHP-FPM pool would execute this extension. The list
// lives in rules.go beside the rules scoped to it, so the two cannot drift.
func phpish(ext string) bool { return slices.Contains(phpExts, ext) }

// Read limits per file kind. Zero means the file is not opened at all.
const (
	// phpReadLimit is the limit the scan has always used for executable PHP.
	phpReadLimit = 3 * 1024 * 1024
	// jsReadLimit is deliberately far smaller. Measured on a real tenant tree
	// (WordPress core plus the five most-installed plugins): 1972 JavaScript
	// files hold 152.9 MB against 68.7 MB of PHP, because a handful of vendor
	// bundles reach 13 MB while the median file is 6 KB. Reading them at the PHP
	// limit took the whole sweep from 19 s to 55 s; at 256 KB it takes 31 s and
	// still opens 1862 of the 1972 files. What that trades away is a payload
	// appended to a multi-megabyte bundle, which is the same trade the PHP limit
	// has always made, and the scan has an 8-minute budget it must finish inside
	// or the result is reported as a partial one.
	jsReadLimit = 256 * 1024
	// htAccessReadLimit: an override file is a few kilobytes; anything at this
	// size is not one.
	htAccessReadLimit = 256 * 1024
)

// readLimitFor returns how many bytes of a file the scan will read, or 0 when
// the file is not one a site executes or serves.
//
// .htaccess and JavaScript were never opened before, so the two rules that
// depend on them, a PHP handler bound to an image extension and an injected
// eval(String.fromCharCode(...)), could not have fired however they were
// written.
func readLimitFor(ext string) int64 {
	switch {
	case phpish(ext):
		return phpReadLimit
	case slices.Contains(jsExts, ext):
		return jsReadLimit
	case ext == extHTAccess:
		return htAccessReadLimit
	}
	return 0
}
