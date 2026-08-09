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
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"

	"servika/internal/antivirus"
	"servika/internal/httpx"
)

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

// checksumPrefixes maps the measured wp-cli wording to a stable signature.
//
// The order matters only for reading: the strings do not overlap. Anything else,
// including the "Error: WordPress installation doesn't verify against checksums."
// summary line, is NOT a finding and must not become one, or every check would
// report one extra file that does not exist.
var checksumPrefixes = []struct {
	prefix    string
	signature string
}{
	{"Warning: File should not exist: ", SignatureExtraFile},
	{"Warning: File doesn't verify against checksum: ", SignatureModified},
	{"Warning: File doesn't exist: ", SignatureMissing},
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

// POST /domains/{id}/wordpress/verify  {dir}
//
// The findings are recorded through internal/antivirus so quarantine and bulk
// cleanup act on them exactly as they do on a scanner hit, rather than growing a
// second finding model with its own listing and its own containment path.
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

	// The command reaches wordpress.org for the checksum list, so it gets the
	// network budget rather than the local one.
	output, _ := runWPTimeout(wpNetworkTimeout, systemUser, "core", "verify-checksums", "--path="+dir)
	verdicts := parseChecksumReport(string(output))

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
		"scan_id":  scanID,
		"extra":    counts[SignatureExtraFile],
		"modified": counts[SignatureModified],
		"missing":  counts[SignatureMissing],
		"output":   truncateOutput(strings.TrimSpace(string(output))),
	})
}
