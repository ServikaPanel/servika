// Package antivirus provides per-domain malware scanning with ClamAV and lightweight heuristics.
// A server-wide atomic lock allows only one scan at a time to limit memory pressure.
// Quarantine uses a same-filesystem rename and restricts paths to the domain home.
package antivirus

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"servika/internal/config"
	"servika/internal/httpx"

	"github.com/go-chi/chi/v5"
)

func clamBin() string { return config.ClamScanBin() }

func freshclamBin() string { return config.FreshclamBin() }

type Handlers struct{ DB *sql.DB }

// scanning is a server-wide lock. A single slot prevents ClamAV database memory pressure.
var scanning atomic.Int32

var errCap = errors.New("file-limit-reached")

// Low false-positive, high-signal PHP webshell/obfuscation signatures
var heuristics = []struct {
	name string
	re   *regexp.Regexp
}{
	{"PHP.Webshell.EvalBase64", regexp.MustCompile(`(?i)eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode)\s*\(`)},
	{"PHP.Webshell.PregReplaceE", regexp.MustCompile(`(?i)preg_replace\s*\(\s*['"][^'"]{0,200}/e['"]`)},
	{"PHP.Webshell.AssertInput", regexp.MustCompile(`(?i)assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`)},
	{"PHP.Webshell.SystemInput", regexp.MustCompile(`(?i)(shell_exec|passthru|system|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)`)},
	{"PHP.Webshell.KnownMarker", regexp.MustCompile(`(?i)(c99shell|r57shell|b374k|wso[_ ]?shell|filesman|indoxploit|angelshell|priv8|mini\s*shell)`)},
	{"PHP.Obf.CreateFunc", regexp.MustCompile(`(?i)create_function\s*\([^)]*base64_decode`)},
	{"PHP.Obf.CharObfEval", regexp.MustCompile(`(?i)\$\{?['"]?\w+['"]?\}?\s*\(\s*\$\{?['"]?\w+['"]?\}?\s*\)\s*;.*base64`)},
}

type Finding struct {
	// ID is what the quarantine endpoint takes. The path is deliberately not
	// accepted from a caller, so the screen has to name the row instead.
	ID         int64  `json:"id"`
	File       string `json:"file"`
	Signature  string `json:"signature"`
	Engine     string `json:"engine"`
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
		if _, err := db.Exec(
			`INSERT INTO av_findings (scan_id, domain_id, file, signature, engine) VALUES (?,?,?,?,?)`,
			scanID, domainID, finding.File, finding.Signature, finding.Engine); err != nil {
			return scanID, err
		}
	}
	return scanID, nil
}

func (h *Handlers) findings(ctx context.Context, sid int64) []Finding {
	out := []Finding{}
	rows, err := h.DB.QueryContext(ctx, `SELECT id, file, signature, engine, quarantined FROM av_findings WHERE scan_id=? ORDER BY id`, sid)
	if err != nil {
		return out
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var b Finding
		if err := rows.Scan(&b.ID, &b.File, &b.Signature, &b.Engine, &b.Quarantine); err == nil {
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
	go func() {
		defer scanning.Store(0)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()
		scanned, findings := runScan(ctx, root)
		for _, f := range findings {
			_, _ = h.DB.Exec(`INSERT INTO av_findings (scan_id, domain_id, file, signature, engine) VALUES (?,?,?,?,?)`,
				sid, id, f.File, f.Signature, f.Engine)
		}
		_, _ = h.DB.Exec(`UPDATE av_scans SET status='finished', scanned=?, infected=?, finished_at=NOW() WHERE id=?`,
			scanned, len(findings), sid)
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
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT status, engine, scanned, infected, started_at, finished_at FROM av_scans WHERE id=? AND domain_id=?`, sid, id).
		Scan(&status, &engine, &scanned, &infected, &startedAt, &finishedAt); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "scan not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id": sid, "status": status, "engine": engine, "scanned": scanned,
		"infected": infected, "started_at": startedAt, "finished_at": finishedAt.String,
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
func runScan(ctx context.Context, root string) (int, []Finding) {
	var findings []Finding
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
						findings = append(findings, Finding{File: file, Signature: signature, Engine: "clamav"})
					}
				}
			}
		}
	}

	// 2) Heuristic PHP webshell scan
	scanned := 0
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
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
		if !phpish(strings.ToLower(filepath.Ext(p))) {
			return nil
		}
		fi, e := d.Info()
		if e != nil || fi.Size() > 3*1024*1024 {
			return nil
		}
		scanned++
		if scanned > 50000 {
			return errCap
		}
		// #nosec G122 G304 -- operator-initiated antivirus scan reads files under the scan root; content is only pattern-matched, never returned to a tenant.
		b, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		for _, hs := range heuristics {
			if hs.re.Match(b) {
				k := "h|" + p + "|" + hs.name
				if !seen[k] {
					seen[k] = true
					findings = append(findings, Finding{File: p, Signature: hs.name, Engine: "heuristic"})
				}
			}
		}
		return nil
	})
	return scanned, findings
}

func phpish(ext string) bool {
	switch ext {
	case ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".phar", ".inc", ".pht":
		return true
	}
	return false
}
