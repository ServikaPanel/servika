package antivirus

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"servika/internal/avsettings"
)

// TestMain makes this test binary answer -scan-worker as well.
//
// Scan re-executes os.Executable(), which under `go test` is this binary, so
// without this the confined path could only ever be exercised by hand against a
// deployed panel. `go test` passes its own flags, so the check below is false
// on an ordinary run.
func TestMain(m *testing.M) {
	if RunWorkerIfAsked() {
		return
	}
	os.Exit(m.Run())
}

// The webshell every case below plants. It matches PHP.Webshell.EvalSuperglobal,
// which is weightProof, so one file is one critical finding.
const workerWebshell = "<?php eval($_POST['c']); ?>"

func plantTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "shell.php"), []byte(workerWebshell), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.php"),
		[]byte("<?php echo get_header(); ?>"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// The unconfined path and the worker binary must scan the same thing. They share
// executeScan for exactly that reason, and this is what holds them together.
func TestTheWorkerAndTheFallbackFindTheSameThing(t *testing.T) {
	root := plantTree(t)
	req := DefaultRequest(root)

	direct := executeScan(context.Background(), req)
	if len(direct.Findings) != 1 {
		t.Fatalf("the in-process scan found %d findings, want 1: %+v", len(direct.Findings), direct.Findings)
	}
	if direct.Findings[0].Level != LevelCritical {
		t.Errorf("the planted webshell is not critical: %+v", direct.Findings[0])
	}

	// Now through the file protocol the worker actually uses.
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "request.json")
	resultPath := filepath.Join(dir, "result.json")
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(requestPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runWorker(requestPath, resultPath); err != nil {
		t.Fatalf("the worker failed: %v", err)
	}
	viaFile, err := readResult(resultPath)
	if err != nil {
		t.Fatalf("the result could not be read back: %v", err)
	}
	if len(viaFile.Findings) != len(direct.Findings) {
		t.Fatalf("the worker found %d findings, the in-process scan %d",
			len(viaFile.Findings), len(direct.Findings))
	}
	if viaFile.Findings[0].File != direct.Findings[0].File ||
		viaFile.Findings[0].Signature != direct.Findings[0].Signature ||
		viaFile.Findings[0].Score != direct.Findings[0].Score ||
		viaFile.Findings[0].Level != direct.Findings[0].Level {
		t.Errorf("the finding did not survive the file protocol:\n  worker: %+v\n  direct: %+v",
			viaFile.Findings[0], direct.Findings[0])
	}
	if viaFile.Scanned != direct.Scanned {
		t.Errorf("scanned count %d vs %d", viaFile.Scanned, direct.Scanned)
	}
}

// The result file is the whole handoff, so a missing or unreadable one is a
// FAILED scan. Returning an empty result there would report a sweep that never
// happened as a site with no malware on it.
func TestAnUnreadableResultIsAFailureAndNotAnEmptyScan(t *testing.T) {
	dir := t.TempDir()

	if _, err := readResult(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("a missing result file was read as a completed scan")
	}

	truncated := filepath.Join(dir, "truncated.json")
	if err := os.WriteFile(truncated, []byte(`{"scanned":3,"findings":[{"file":"/a`), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := readResult(truncated)
	if err == nil {
		t.Errorf("a truncated result was read as a completed scan: %+v", result)
	}
	if len(result.Findings) != 0 {
		t.Errorf("a refused result still carried findings: %+v", result)
	}

	// A result larger than the ceiling is refused before it is decoded.
	huge := filepath.Join(dir, "huge.json")
	f, err := os.Create(huge) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(resultLimit + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readResult(huge); err == nil {
		t.Error("an oversized result was accepted")
	}
}

func TestTheWorkerRefusesARequestWithNoRoot(t *testing.T) {
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "request.json")
	resultPath := filepath.Join(dir, "result.json")
	if err := os.WriteFile(requestPath, []byte(`{"roots":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runWorker(requestPath, resultPath)
	if err == nil {
		t.Fatal("a request naming no root was accepted")
	}
	if !strings.Contains(err.Error(), "root") {
		t.Errorf("the error does not name what was missing: %v", err)
	}
	// Nothing may be written for a request that was refused: a result file here
	// would be an empty finding list, which reads as a clean scan.
	if _, err := os.Stat(resultPath); err == nil {
		t.Error("a refused request still produced a result file")
	}
}

// A host with no systemd runs the scan unconfined. That is allowed, and it must
// be REPORTED as unconfined: a caller writing confined=1 there would record a
// limit the kernel never applied.
func TestAHostWithoutSystemdScansUnconfinedAndSaysSo(t *testing.T) {
	restore := systemdRunBin
	systemdRunBin = func() (string, error) { return "", errors.New("not found") }
	t.Cleanup(func() { systemdRunBin = restore })

	root := plantTree(t)
	result, confined, err := Scan(context.Background(), DefaultRequest(root), "1")
	if err != nil {
		t.Fatalf("the fallback failed: %v", err)
	}
	if confined {
		t.Error("a host with no systemd reported the scan as confined")
	}
	if len(result.Findings) != 1 {
		t.Errorf("the fallback found %d findings, want 1", len(result.Findings))
	}
}

// A systemd-run failure is NOT downgraded to an unconfined run. An operator who
// set a limit would otherwise get an unlimited scan across every site on the
// server, reported as an ordinary one.
func TestAFailedLaunchIsRefusedRatherThanRunUnconfined(t *testing.T) {
	restore := systemdRunBin
	// /usr/bin/false stands in for a systemd-run that cannot start the unit.
	systemdRunBin = func() (string, error) { return "/usr/bin/false", nil }
	t.Cleanup(func() { systemdRunBin = restore })

	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("no systemd on this host, so the confined path cannot be reached")
	}

	root := plantTree(t)
	result, confined, err := Scan(context.Background(), DefaultRequest(root), "1")
	if err == nil {
		t.Fatal("a failed launch was reported as a successful scan")
	}
	if confined {
		t.Error("a failed launch was reported as confined")
	}
	if len(result.Findings) != 0 {
		t.Error("a failed launch still returned findings")
	}
}

// The label reaches a systemd unit name. A scan id is all that is ever passed,
// but a unit name is not a place to discover later that the assumption was wrong.
func TestTheUnitNameCannotCarryAnythingSystemdWouldRefuse(t *testing.T) {
	cases := map[string]string{
		"7":                                  "servika-av-scan-7",
		"":                                   "servika-av-scan-adhoc",
		"a b":                                "servika-av-scan-a-b",
		"../../etc/passwd":                   "servika-av-scan-------etc-passwd",
		"a@b.service":                        "servika-av-scan-a-b-service",
		"0123456789012345678901234567890123": "servika-av-scan-01234567890123456789012345678901",
	}
	for in, want := range cases {
		if got := unitName(in); got != want {
			t.Errorf("unitName(%q) = %q, want %q", in, got, want)
		}
	}
	for in := range cases {
		got := unitName(in)
		if strings.ContainsAny(got, "/. @\\\n\t") {
			t.Errorf("unitName(%q) = %q carries a character systemd would refuse", in, got)
		}
	}
}

// The deadlines have to nest outwards, or the outer one fires first and throws
// away findings the worker already had in hand.
func TestTheDeadlinesNestOutwards(t *testing.T) {
	if scanBudget >= unitBudget || unitBudget >= parentBudget {
		t.Errorf("the deadlines do not nest: scan=%v unit=%v parent=%v",
			scanBudget, unitBudget, parentBudget)
	}
}

// The production path, end to end. Everything above measures the protocol and
// the refusals; only this puts a real scan in a real cgroup and reads back the
// control group the scan OBSERVED, which is the difference between asking
// systemd for a limit and getting one.
//
// It needs root and a running systemd, so it is skipped on every development
// machine. TestMain is what makes it possible: this binary answers -scan-worker.
func TestTheScanReallyRunsInsideTheResourceSlice(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required: this test writes a real systemd unit")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("no systemd on this host")
	}

	if err := avsettings.ApplyLimits(avsettings.Settings{
		CPUPercent: 150, RAMMB: 400, IOWeight: 50,
	}); err != nil {
		t.Fatalf("could not write the resource slice: %v", err)
	}

	root := plantTree(t)
	result, confined, err := Scan(context.Background(), DefaultRequest(root), "e2e")
	if err != nil {
		t.Fatalf("the confined scan failed: %v", err)
	}
	t.Logf("the scan ran in %s", result.Cgroup)

	if !confined {
		t.Errorf("the scan was not confined; it ran in %q", result.Cgroup)
	}
	if !strings.Contains(result.Cgroup, avsettings.SliceName) {
		t.Errorf("the scan did not run in %s: %q", avsettings.SliceName, result.Cgroup)
	}
	// It ran in the slice AND it did the work. A confined scan that found
	// nothing would be the same failure the whole feature guards against.
	if len(result.Findings) != 1 {
		t.Fatalf("the confined scan found %d findings, want 1: %+v", len(result.Findings), result.Findings)
	}
	if result.Findings[0].Level != LevelCritical {
		t.Errorf("the planted webshell is not critical: %+v", result.Findings[0])
	}

	// And the kernel really held it: read the limit out of the cgroup the
	// worker named, not out of systemd's own report.
	if b, err := os.ReadFile("/sys/fs/cgroup" + filepath.Dir(result.Cgroup) + "/cpu.max"); err != nil {
		t.Errorf("cpu.max is unreadable for the slice the scan ran in: %v", err)
	} else if got := strings.TrimSpace(string(b)); got != "150000 100000" {
		t.Errorf("the scan ran under cpu.max %q, want \"150000 100000\"", got)
	}
}

// The worker never opens a database. Handing it credentials would make it a
// second place that knows the av_findings schema, and the panel process is the
// only one that should hold a connection.
func TestTheWorkerCarriesNoCredentials(t *testing.T) {
	body, err := os.ReadFile("worker.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"database/sql", "sql.DB", "insertFinding", "h.DB"} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("the scan worker reaches the database: %q", forbidden)
		}
	}
	// The request that crosses the process boundary carries roots, nothing else.
	var req ScanRequest
	encoded, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "dsn") || strings.Contains(string(encoded), "password") {
		t.Errorf("the scan request carries a credential: %s", encoded)
	}
}
