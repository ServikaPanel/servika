// Package antivirus provides per-domain malware scanning with ClamAV and lightweight heuristics.
// A server-wide atomic lock allows only one scan at a time to limit memory pressure.
// Quarantine uses a same-filesystem rename and restricts paths to the domain home.
package antivirus

import (
	"context"
	"database/sql"
	"encoding/json"
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
	"servika/internal/files"
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

// Stable reason codes. The API answers in English and the panel draws twelve
// languages, so a screen that matched the message would break on the first
// wording change.
// quarantineDir is the tenant-home directory a quarantined file is moved into,
// relative to the home so every operation on it goes through safeio.
const quarantineDir = ".quarantined"

const (
	reasonFindingUnknown  = "av_finding_unknown"
	reasonFileMissing     = "av_file_missing"
	reasonPathOutsideHome = "av_path_outside_home"
	reasonQuarantineFail  = "av_quarantine_failed"
)

// homeRelative turns a finding's absolute path into a path relative to the
// tenant home, refusing anything that does not sit under it.
//
// The finding rows are written by this package's own scan, so a mismatch is a
// bug rather than an attack, but the conversion is the last point at which a
// path that escaped the home can be caught before a root-privileged file
// operation, so it refuses rather than repairing.
func homeRelative(home, absolute string) (string, bool) {
	clean := filepath.Clean(absolute)
	if !strings.HasPrefix(clean, home+"/") {
		return "", false
	}
	rel := strings.TrimPrefix(clean, home+"/")
	if rel == "" || rel == "." {
		return "", false
	}
	return rel, true
}

// POST /domains/{id}/antivirus/quarantine  {finding_id}
//
// The path is read from the FINDING, never from the request. It used to be sent
// by the caller and checked with a string prefix, which is not a boundary: lstat
// and rename follow symlinks in every component except the last, so a tenant who
// planted a link inside their own public_html could have the panel move any file
// on the host, as root, into their quarantine directory.
func (h *Handlers) Quarantine(w http.ResponseWriter, r *http.Request) {
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
	var req struct {
		FindingID int64 `json:"finding_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Narrowed by domain in the QUERY: the caller owns this domain, which does not
	// make every finding id theirs.
	var absolute string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT file FROM av_findings WHERE id=? AND domain_id=?`, req.FindingID, id).
		Scan(&absolute); err != nil {
		httpx.WriteJSON(w, http.StatusNotFound,
			map[string]any{"error": "finding not found", "reason": reasonFindingUnknown})
		return
	}

	home := "/home/" + systemUser
	rel, inside := homeRelative(home, absolute)
	if !inside {
		httpx.WriteJSON(w, http.StatusBadRequest,
			map[string]any{"error": "path is outside the domain directory", "reason": reasonPathOutsideHome})
		return
	}
	// Every component is pinned with openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS,
	// so a planted link at any level fails the open instead of redirecting it.
	source, err := files.OpenBeneath(home, rel)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest,
			map[string]any{"error": "file not found", "reason": reasonFileMissing})
		return
	}
	defer func() { _ = source.Close() }()
	info, statErr := source.Stat()
	// Asserted on the DESCRIPTOR, not on a separate stat of the path: a fifo or a
	// device node under the home opens successfully and must not be read.
	if statErr != nil || !info.Mode().IsRegular() {
		httpx.WriteJSON(w, http.StatusBadRequest,
			map[string]any{"error": "not a regular file", "reason": reasonFileMissing})
		return
	}

	// The content is taken from the descriptor openat2 already pinned, and the
	// source is removed through the same jail. Nothing here re-walks the path as
	// text, so there is no window in which a component could be swapped between
	// the check and the operation.
	targetRel := quarantineDir + "/" + time.Now().Format("20060102_150405") + "_" + filepath.Base(rel)
	if err := files.MkdirAllBeneath(home, quarantineDir, systemUser); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError,
			map[string]any{"error": "could not create quarantine directory", "reason": reasonQuarantineFail})
		return
	}
	if _, err := files.StreamIntoBeneath(home, targetRel, source, systemUser); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError,
			map[string]any{"error": "operation failed", "reason": reasonQuarantineFail})
		return
	}
	if err := files.RemoveAllBeneath(home, rel); err != nil {
		// The copy landed but the original is still live, so the file is NOT
		// quarantined. Take the copy back rather than report a containment that
		// did not happen.
		_ = files.RemoveAllBeneath(home, targetRel)
		httpx.WriteJSON(w, http.StatusInternalServerError,
			map[string]any{"error": "operation failed", "reason": reasonQuarantineFail})
		return
	}
	_ = files.ChmodBeneath(home, targetRel, 0o000) // not executable, not readable
	_, _ = h.DB.Exec(`UPDATE av_findings SET quarantined=1 WHERE id=? AND domain_id=?`, req.FindingID, id)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "target": home + "/" + targetRel})
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
