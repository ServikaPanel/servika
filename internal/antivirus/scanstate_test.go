package antivirus

import (
	"os"
	"strings"
	"testing"
)

// A scan that ran out of its budget covered part of the tree, so it must not be
// recorded as finished. A partial sweep presented as a clean result is the worst
// answer this screen can give: the webshell in the part that was never reached
// reads as "no findings".
func TestATimedOutScanIsRecordedAsFailed(t *testing.T) {
	body := scanBody(t)

	if !strings.Contains(body, `status := "finished"`) ||
		!strings.Contains(body, "if ctx.Err() != nil {") ||
		!strings.Contains(body, `status = "failed"`) {
		t.Error("a scan that exhausted its budget is recorded as finished again")
	}
	// The status has to reach the UPDATE; a computed value nothing uses is the
	// same as no check at all.
	if !strings.Contains(body, "UPDATE av_scans SET status=?, scanned=?, infected=?, finished_at=NOW() WHERE id=?") {
		t.Error("the scan status is no longer written from the computed value")
	}
	if strings.Contains(body, "UPDATE av_scans SET status='finished'") {
		t.Error("the scan status is hard-coded to finished again")
	}
}

// The findings collected before the budget ran out are still written. Dropping
// them would throw away real detections because the sweep was cut short.
func TestAPartialScanKeepsWhatItFound(t *testing.T) {
	body := scanBody(t)

	insert := strings.Index(body, "INSERT INTO av_findings")
	status := strings.Index(body, `status := "finished"`)
	switch {
	case insert < 0:
		t.Fatal("the findings are no longer written")
	case status < 0:
		t.Fatal("the status check moved; this test has to follow it")
	case insert > status:
		t.Error("the findings are written after the status decision, so a cut-short scan may lose them")
	}
}

// A restart frees the in-memory lock but not the row, so every scan left running
// is closed at startup rather than left to spin on the screen for good.
func TestTheHealClosesEveryRunningScan(t *testing.T) {
	source, err := os.ReadFile("antivirus.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	if !strings.Contains(body,
		`UPDATE av_scans SET status='failed', finished_at=NOW() WHERE status='running'`) {
		t.Error("the startup heal no longer closes the scans left running")
	}
	if !strings.Contains(body, "func HealRunningScans(db *sql.DB)") {
		t.Fatal("HealRunningScans was renamed; main wires it by name")
	}
	// A nil database must not panic the startup path.
	HealRunningScans(nil)
}

// scanBody returns the Scan handler's source, which is where the status decision
// lives. It cannot be executed here: it walks a real tenant tree and shells out
// to clamscan.
func scanBody(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("antivirus.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	start := strings.Index(body, "func (h *Handlers) Scan(")
	if start < 0 {
		t.Fatal("Scan was renamed; this test has to follow it")
	}
	end := strings.Index(body[start:], "\n// GET /domains/{id}/antivirus/scan/{sid}")
	if end < 0 {
		return body[start:]
	}
	return body[start : start+end]
}
