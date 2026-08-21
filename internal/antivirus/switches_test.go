package antivirus

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A tree with one file convicted by its CONTENT and one convicted only by its
// PATH, so each switch can be shown to control exactly one of them.
func plantForSwitches(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "shell.php"),
		[]byte("<?php eval($_POST['c']); ?>"), 0o600); err != nil {
		t.Fatal(err)
	}
	uploads := filepath.Join(root, "wp-content", "uploads")
	if err := os.MkdirAll(uploads, 0o700); err != nil {
		t.Fatal(err)
	}
	// Ordinary WordPress code, in a place no plugin writes .php to. Its content
	// is clean, so only the location heuristic can convict it.
	if err := os.WriteFile(filepath.Join(uploads, "thumb.php"),
		[]byte("<?php echo get_header(); ?>"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func scanFiles(t *testing.T, root string, req ScanRequest) map[string]Finding {
	t.Helper()
	_, findings, _ := runScan(context.Background(), root, req)
	out := map[string]Finding{}
	for _, f := range findings {
		out[filepath.Base(f.File)] = f
	}
	return out
}

// Each switch has to have a failing path and a passing one, or it is not
// controlling anything.
func TestEachLayerSwitchTurnsExactlyOneLayerOff(t *testing.T) {
	root := plantForSwitches(t)

	both := scanFiles(t, root, DefaultRequest(root))
	if _, ok := both["shell.php"]; !ok {
		t.Fatalf("with both layers on the webshell is missed: %v", both)
	}
	if _, ok := both["thumb.php"]; !ok {
		t.Fatalf("with both layers on the uploads .php is missed: %v", both)
	}

	// The rule engine off: the content verdict goes, the location verdict stays.
	noRules := DefaultRequest(root)
	noRules.RuleEngine = false
	got := scanFiles(t, root, noRules)
	if _, ok := got["shell.php"]; ok {
		t.Error("the rule engine is off but a content finding was still reported")
	}
	if _, ok := got["thumb.php"]; !ok {
		t.Error("turning the rule engine off also removed the location finding")
	}

	// The location heuristics off: the reverse.
	noLocation := DefaultRequest(root)
	noLocation.LocationHeuristics = false
	got = scanFiles(t, root, noLocation)
	if _, ok := got["thumb.php"]; ok {
		t.Error("the location heuristics are off but a path finding was still reported")
	}
	if _, ok := got["shell.php"]; !ok {
		t.Error("turning the location heuristics off also removed the content finding")
	}

	// Both off: nothing at all, and no file is opened.
	if got = scanFiles(t, root, ScanRequest{Roots: []string{root}}); len(got) != 0 {
		t.Errorf("with every layer off the scan still reported %v", got)
	}
}

// A layer that is off must be SKIPPED, not run and filtered. The only thing
// turning it off buys is the work it does not do, and an operator turns it off
// on a server the scan is slowing down.
func TestALayerThatIsOffIsNotRunAtAll(t *testing.T) {
	body, err := os.ReadFile("antivirus.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if !strings.Contains(source, "if !req.RuleEngine {") {
		t.Error("the rule engine switch no longer skips the read")
	}
	if !strings.Contains(source, "if req.LocationHeuristics {") {
		t.Error("the location switch no longer skips the path check")
	}

	// With both off the walk must not open a single file. A directory whose
	// files are unreadable proves it: reading one would fail, and the scan
	// would report it or stall, where skipping reads nothing.
	root := t.TempDir()
	path := filepath.Join(root, "x.php")
	if err := os.WriteFile(path, []byte("<?php eval($_POST['c']); ?>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	scanned, findings, _ := runScan(context.Background(), root, ScanRequest{Roots: []string{root}})
	if len(findings) != 0 {
		t.Errorf("a scan with every layer off still reported %v", findings)
	}
	if scanned != 0 {
		t.Errorf("a scan with every layer off still counted %d files", scanned)
	}
}

// The settings are read in the panel process and travel to the worker in its
// request. Reading them in the worker would mean handing it a database
// connection, which is what keeps it a scanner rather than half a panel.
func TestTheSettingsAreReadBeforeTheWorkerAndNotByIt(t *testing.T) {
	handler, err := os.ReadFile("antivirus.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(handler)
	if !strings.Contains(source, "func scanRequest(ctx context.Context, db *sql.DB") {
		t.Fatal("scanRequest moved; the settings must still be read on the panel side")
	}
	// An unreadable settings row refuses the scan. Falling back to scanning
	// everything would ignore exactly the decision the operator made, on the
	// server they made it for.
	request := strings.Index(source, "req, err := scanRequest(")
	lock := strings.Index(source, "takeScanSlot(r.Context(), h.DB)")
	switch {
	case request < 0:
		t.Fatal("the handler no longer reads the settings")
	case lock < 0:
		t.Fatal("the scan lock moved; this test has to follow it")
	case request > lock:
		t.Error("the settings are read after the lock is taken, so a failure holds the lock")
	}
	if !strings.Contains(source, "the antivirus settings could not be read") {
		t.Error("an unreadable settings row no longer refuses the scan")
	}
}

// The critical threshold is a setting; the reporting threshold is not. The two
// numbers were chosen together so no single rule below scoreSuspicious can
// convict a file on its own, and lowering the reporting threshold would break
// that. Raising the critical one only makes the panel more cautious about the
// word, which is the operator's call.
func TestTheCriticalThresholdMovesAndTheReportingThresholdDoesNot(t *testing.T) {
	// One weightStrong signal: 60, which is suspicious under the shipped 100.
	strong := []match{{"X.Strong", weightStrong}}

	if _, _, _, level := verdict(strong, 0); level != LevelSuspicious {
		t.Errorf("a single strong signal is %q under the shipped threshold, want suspicious", level)
	}
	if _, _, _, level := verdict(strong, 60); level != LevelCritical {
		t.Errorf("a threshold of 60 did not make a 60-point file critical: %q", level)
	}
	if _, _, _, level := verdict(strong, 200); level != LevelSuspicious {
		t.Errorf("a threshold of 200 left a 60-point file at %q, want suspicious", level)
	}

	// A weak signal alone is below the reporting threshold, and no critical
	// threshold an operator can set may change that.
	weak := []match{{"X.Weak", weightWeak}}
	for _, critical := range []int{0, 1, 20, 100, 5000} {
		if _, _, _, level := verdict(weak, critical); level != "" {
			t.Errorf("a single weak signal became %q at critical=%d", level, critical)
		}
	}

	// A threshold below the reporting threshold cannot drag the reporting
	// threshold down with it: the floor is enforced where the level is decided,
	// not only where the setting is saved.
	if got := levelFor(scoreSuspicious-1, 1); got != "" {
		t.Errorf("a critical threshold of 1 reported a sub-threshold score as %q", got)
	}
	if got := levelFor(scoreSuspicious, 1); got != LevelCritical {
		t.Errorf("a critical threshold of 1 did not make a reportable score critical: %q", got)
	}
}
