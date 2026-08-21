package wordpress

// Core integrity: what `wp core verify-checksums` found, turned into findings the
// malware screen can act on.
//
// The command has no machine-readable output (measured with WP-CLI 2.12.0:
// `--format=json` is refused with "unknown --format parameter"), and every line
// goes to STDERR, so the prose is parsed and runWPTimeout's CombinedOutput is
// what carries it. The three verdicts are distinct actions, not one "dirty"
// flag: an extra file in a core directory is exactly the webshell case and can
// be quarantined, while a modified or missing core file is repaired by
// re-downloading core, which Repair already does.

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/antivirus"
	"servika/internal/httpx"
	"servika/internal/wpchecksums"
)

// checksumWarmTimeout bounds the cache fetch and, when the command could not
// measure, the comparison that follows. It is far shorter than the command's own
// network budget because it is the SECOND thing on the path: a slow fetch here
// would delay the check that is about to run anyway.
const checksumWarmTimeout = 60 * time.Second

// The signature names are the API contract the screen groups by, so they are
// stable strings rather than derived from the wp-cli wording.
const (
	SignatureExtraFile = "WP.Core.ExtraFile"
	SignatureModified  = "WP.Core.Modified"
	SignatureMissing   = "WP.Core.Missing"
)

// checksumEngine is the engine name the findings carry, so the screen can tell
// them from a ClamAV or heuristic hit.
const checksumEngine = "wp-checksums"

// verdict is one line of the report.
type verdict struct {
	Signature string
	// Rel is relative to the WordPress directory, exactly as wp-cli prints it.
	Rel string
}

// checksumSignatures maps the measured wp-cli wording to a stable signature.
//
// The messages are spelled once, in internal/wpchecksums, so the offline
// comparison and the parser of the command's own output cannot drift into
// reporting the same defect under two different signatures.
var checksumSignatures = map[string]string{
	wpchecksums.MessageExtra:    SignatureExtraFile,
	wpchecksums.MessageModified: SignatureModified,
	wpchecksums.MessageMissing:  SignatureMissing,
}

// checksumPrefixes is the same table as the line prefix the command prints.
//
// The order matters only for reading: the strings do not overlap. Anything else,
// including the "Error: WordPress installation doesn't verify against checksums."
// summary line, is NOT a finding and must not become one, or every check would
// report one extra file that does not exist.
var checksumPrefixes = []struct {
	prefix    string
	signature string
}{
	{"Warning: " + wpchecksums.MessageExtra + ": ", SignatureExtraFile},
	{"Warning: " + wpchecksums.MessageModified + ": ", SignatureModified},
	{"Warning: " + wpchecksums.MessageMissing + ": ", SignatureMissing},
}

// parseChecksumReport turns wp-cli's output into verdicts.
//
// A path is taken verbatim after the prefix, because a WordPress path may
// legitimately contain a space and splitting on whitespace would truncate it.
// Anything that climbs out of the installation is DROPPED rather than repaired:
// this is third-party text for this purpose, and a finding is later resolved
// against the tenant home by the code that acts on it.
func parseChecksumReport(output string) []verdict {
	var out []verdict
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		for _, candidate := range checksumPrefixes {
			if !strings.HasPrefix(line, candidate.prefix) {
				continue
			}
			rel := strings.TrimSpace(strings.TrimPrefix(line, candidate.prefix))
			if rel == "" || filepath.IsAbs(rel) {
				break
			}
			// filepath.Clean collapses "a/../b"; anything still climbing is refused.
			clean := filepath.Clean(rel)
			if clean == ".." || strings.HasPrefix(clean, "../") {
				break
			}
			out = append(out, verdict{Signature: candidate.signature, Rel: clean})
			break
		}
	}
	return out
}

// The three states the repair screen reports for a check. They are the API
// contract that screen groups by, so they are stable strings.
const (
	// StateClean means the tree was compared and matched.
	StateClean = "clean"
	// StateIssuesFound means the tree was compared and did not match.
	StateIssuesFound = "issues-found"
	// StateNotMeasured means nothing was compared. It is deliberately NOT folded
	// into either of the others: reporting it as clean is the defect this exists
	// to remove, and reporting it as issues-found makes a repair that worked
	// look like one that failed.
	StateNotMeasured = "not-measured"
)

// checksumState turns a check's result into the state the screen renders.
func checksumState(verdicts []verdict, measured bool) string {
	switch {
	case !measured:
		return StateNotMeasured
	case len(verdicts) > 0:
		return StateIssuesFound
	default:
		return StateClean
	}
}

// commandMeasured reports whether the command actually compared the tree.
//
// A zero exit is a comparison whatever it found, and a non-zero exit that still
// printed a warning is a comparison that found something. A non-zero exit with
// no warning at all is the command giving up before it compared anything, which
// is every way of failing to obtain the table.
func commandMeasured(runErr error, verdicts []verdict) bool {
	return runErr == nil || len(verdicts) > 0
}

// runChecksums performs the check and reports whether anything was COMPARED.
//
// The command's exit status alone cannot answer that, measured against WP-CLI
// 2.12.0:
//
//	clean installation, API up        exit 0, "Success: ..."
//	extra file only, API up           exit 0, one Warning line
//	modified core file, API up        exit 1, Warning lines plus an Error line
//	api.wordpress.org unreachable     exit 1, "Error: RuntimeException: Failed to get url ..."
//	version wordpress.org never had   exit 1, "Error: Couldn't get checksums from WordPress.org."
//
// An extra file is the webshell case this endpoint exists to catch and it exits
// 0, so "exit 0 means clean" is false. What separates the last two rows from
// everything above them is that the run produced NO parsed warning at all, which
// is the test used here. Matching the error TEXT would work today and break on
// the next wp-cli release, because that wording is the command's, not an API.
//
// When nothing was compared the cached table is tried, which is what
// internal/wpchecksums keeps for exactly this moment.
func (h *Handlers) runChecksums(systemUser, dir string) (verdicts []verdict, output string, measured bool) {
	home := "/home/" + systemUser
	relDir := strings.TrimPrefix(strings.TrimPrefix(dir, home), "/")

	// The table is fetched BEFORE the command runs, while the network is by
	// definition working. Warming it only on the fallback path would fetch at the
	// one moment the network is down, so the cache would never fill.
	ctx, cancel := context.WithTimeout(context.Background(), checksumWarmTimeout)
	defer cancel()
	details, detailsErr := wpchecksums.ReadDetails(home, relDir)
	if detailsErr == nil {
		wpchecksums.Warm(ctx, details)
	}

	// The command reaches wordpress.org for the checksum list, so it gets the
	// network budget rather than the local one.
	raw, runErr := runWPTimeout(wpNetworkTimeout, systemUser, "core", "verify-checksums", "--path="+dir)
	verdicts = parseChecksumReport(string(raw))
	if commandMeasured(runErr, verdicts) {
		return verdicts, strings.TrimSpace(string(raw)), true
	}

	if detailsErr != nil {
		return nil, strings.TrimSpace(string(raw)), false
	}
	table, tableErr := wpchecksums.Table(ctx, details)
	if tableErr != nil {
		return nil, strings.TrimSpace(string(raw)), false
	}
	offline, verifyErr := wpchecksums.Verify(home, relDir, table)
	if verifyErr != nil {
		return nil, strings.TrimSpace(string(raw)), false
	}
	// The offline report is rendered in the command's own wording, so the screen
	// shows one shape whichever engine answered.
	lines := make([]string, 0, len(offline)+1)
	for _, item := range offline {
		verdicts = append(verdicts, verdict{Signature: checksumSignatures[item.Message], Rel: item.Rel})
		lines = append(lines, "Warning: "+item.Message+": "+item.Rel)
	}
	lines = append(lines, "Compared against the cached checksum table; wordpress.org was not reachable.")
	return verdicts, strings.Join(lines, "\n"), true
}

// POST /domains/{id}/wordpress/verify  {dir}
//
// The findings are recorded through internal/antivirus so quarantine and bulk
// cleanup act on them exactly as they do on a scanner hit, rather than growing a
// second finding model with its own listing and its own containment path.
//
// A check that could not compare anything answers `measured: false` and records
// NOTHING. The endpoint used to discard the command's error, so an unreachable
// api.wordpress.org produced zero verdicts and the screen told the customer the
// core files matched the official checksums. Zero findings and no comparison are
// the same JSON; they are not the same fact.
func (h *Handlers) VerifyChecksums(w http.ResponseWriter, r *http.Request) {
	var req struct{ Dir string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id, _, _, _, _, _, found := h.domain(r)
	if !found {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	systemUser, dir, ok := h.prepareMutation(w, r, req.Dir)
	if !ok {
		return
	}

	verdicts, output, measured := h.runChecksums(systemUser, dir)
	if !measured {
		// 200 rather than an error status: the request was handled and the answer
		// is a fact about the check, which the screen has to render either way.
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"measured": false,
			"reason":   "wp_checksums_unavailable",
			"output":   truncateOutput(output),
		})
		return
	}

	home := "/home/" + systemUser
	counts := map[string]int{}
	findings := []antivirus.Finding{}
	for _, item := range verdicts {
		counts[item.Signature]++
		// Only a file that is really there can be quarantined. A missing or
		// modified core file is repaired by re-downloading core, so recording it
		// as a finding would put a row on the screen whose only action fails.
		if item.Signature != SignatureExtraFile {
			continue
		}
		absolute := filepath.Join(dir, item.Rel)
		if !strings.HasPrefix(absolute, home+"/") {
			continue
		}
		findings = append(findings, antivirus.Finding{
			File:      absolute,
			Signature: item.Signature,
			Engine:    checksumEngine,
		})
	}

	scanID := int64(0)
	if len(findings) > 0 {
		recorded, err := antivirus.RecordScan(h.DB, id, checksumEngine, len(verdicts), findings)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "the check ran but its findings could not be recorded")
			return
		}
		scanID = recorded
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"measured": true,
		"scan_id":  scanID,
		"extra":    counts[SignatureExtraFile],
		"modified": counts[SignatureModified],
		"missing":  counts[SignatureMissing],
		"output":   truncateOutput(output),
	})
}
