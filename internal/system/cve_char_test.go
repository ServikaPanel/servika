package system

import (
	"strings"
	"testing"
	"time"
)

// setForTest replaces a package variable for one test. It is shared by the
// characterization tests in this package.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

// dnfAnswers scripts the two reads a scan makes: the CVE list and the advisory
// summary. The list call is the one whose last argument is "cves".
func dnfAnswers(t *testing.T, list, summary string) {
	t.Helper()
	setForTest(t, &cveShell, func(_ time.Duration, args ...string) string {
		if len(args) > 0 && args[len(args)-1] == "cves" {
			return list
		}
		return summary
	})
}

// The same CVE is listed once per affected package, so a scan that counted
// lines would report a server as several times more vulnerable than it is.
func TestCveScanCountsEachCveOnceAtItsHighestSeverity(t *testing.T) {
	dnfAnswers(t, strings.Join([]string{
		"CVE-2025-0001 Moderate/Sec. kernel-6.12.0-1.x86_64",
		"CVE-2025-0001 Critical/Sec. kernel-core-6.12.0-1.x86_64",
		"CVE-2025-0002 Important/Sec. openssl-3.2.2-1.x86_64",
		"CVE-2025-0003 Low/Sec. curl-8.9.1-1.x86_64",
		"CVE-2025-0004 Moderate/Sec. tar-1.35-1.x86_64",
	}, "\n"), "")

	summary := cveScan()
	if summary.TotalCves != 4 || summary.Critical != 1 || summary.Important != 1 || summary.Low != 1 {
		t.Fatalf("counts = %+v, want 4 total with one critical, one important and one low", summary)
	}
	if summary.Moderate != 1 {
		t.Errorf("moderate = %d, want only the CVE that is moderate everywhere it appears", summary.Moderate)
	}
	if len(summary.TopCves) == 0 || summary.TopCves[0].Package != "kernel-core-6.12.0-1.x86_64" {
		t.Errorf("top = %+v, want the package of the highest severity line", summary.TopCves)
	}
	if summary.LastScan == "" {
		t.Error("the scan did not record when it ran")
	}
}

// A line the scan cannot read is skipped rather than counted as an unknown
// vulnerability.
func TestCveScanSkipsWhatItCannotRead(t *testing.T) {
	dnfAnswers(t, strings.Join([]string{
		"Last metadata expiration check: 0:12:01 ago.",
		"CVE-2025-0001",
		"CVE-2025-0002 Unknown/Sec. openssl-3.2.2-1.x86_64",
		"not-a-cve Critical/Sec. kernel-6.12.0-1.x86_64",
		"CVE-2025-0003 Critical/Sec. kernel-6.12.0-1.x86_64",
	}, "\n"), "")

	summary := cveScan()
	if summary.TotalCves != 1 || summary.Critical != 1 {
		t.Fatalf("counts = %+v, want only the one readable critical line", summary)
	}
}

// The top list is what the dashboard renders, so it is bounded and its order is
// decided here rather than by the map the counts came from.
func TestCveScanOrdersTheTopListAndBoundsIt(t *testing.T) {
	var lines []string
	for _, id := range []string{"0012", "0003", "0007", "0001", "0009", "0002",
		"0011", "0004", "0008", "0005", "0010", "0006"} {
		lines = append(lines, "CVE-2025-"+id+" Critical/Sec. kernel-6.12.0-1.x86_64")
	}
	lines = append(lines, "CVE-2025-9999 Important/Sec. openssl-3.2.2-1.x86_64")
	dnfAnswers(t, strings.Join(lines, "\n"), "")

	summary := cveScan()
	if len(summary.TopCves) != 10 {
		t.Fatalf("top list holds %d entries, want the cap of 10", len(summary.TopCves))
	}
	if summary.TopCves[0].ID != "CVE-2025-0001" || summary.TopCves[9].ID != "CVE-2025-0010" {
		t.Errorf("top list runs from %q to %q, want the criticals in id order",
			summary.TopCves[0].ID, summary.TopCves[9].ID)
	}
	for _, entry := range summary.TopCves {
		if entry.Severity != "critical" {
			t.Errorf("an important CVE reached the capped list before the criticals: %+v", entry)
		}
	}
}

// The advisory total is the one summary line without a severity word in it: the
// per-severity lines end the same way and would each overwrite the count.
func TestCveScanReadsTheAdvisoryTotalFromItsOwnLine(t *testing.T) {
	dnfAnswers(t, "", strings.Join([]string{
		"    3 Critical Security notice(s)",
		"    5 Important Security notice(s)",
		"    2 Moderate Security notice(s)",
		"    1 Low Security notice(s)",
		"   15 Security notice(s)",
		"    4 Bugfix notice(s)",
	}, "\n"))

	if summary := cveScan(); summary.TotalAdvisories != 15 {
		t.Fatalf("advisories = %d, want 15", summary.TotalAdvisories)
	}
}
