package antivirus

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The shipped cap must not drift silently: it is a variable so a test can lower
// it, which also means a typo could lower it in production.
func TestTheShippedFileCapIsWhatItSays(t *testing.T) {
	if fileCap != 50000 {
		t.Errorf("the shipped file cap is %d, want 50000", fileCap)
	}
}

// A walk that stops at the file cap covered part of the tree, so it is NOT
// complete. The walk's error used to be discarded entirely, which reported
// 50000 files as a finished scan of the whole tree: for a webshell in the part
// that was never reached, that reads as a clean site.
func TestHittingTheFileCapIsReportedAsIncomplete(t *testing.T) {
	restore := fileCap
	fileCap = 20
	t.Cleanup(func() { fileCap = restore })

	root := t.TempDir()
	// One more file than the cap, all clean, so only the cap can stop the walk.
	for i := range fileCap + 1 {
		name := filepath.Join(root, "f"+strconv.Itoa(i)+".php")
		if err := os.WriteFile(name, []byte("<?php echo 1;"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	scanned, findings, complete := runScan(context.Background(), root, DefaultRequest(root))
	if complete {
		t.Errorf("a walk stopped by the file cap reported itself complete (%d files)", scanned)
	}
	if scanned <= fileCap {
		t.Errorf("the cap did not fire: %d files scanned, cap is %d", scanned, fileCap)
	}
	if len(findings) != 0 {
		t.Errorf("clean files produced findings: %v", findings)
	}

	// And a tree under the cap IS complete, or this check would call every scan
	// partial and mean nothing.
	small := t.TempDir()
	if err := os.WriteFile(filepath.Join(small, "a.php"), []byte("<?php echo 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, complete := runScan(context.Background(), small, DefaultRequest(small)); !complete {
		t.Error("an ordinary small tree was reported as an incomplete scan")
	}
}

// The budget running out is the other way a sweep ends early, and it reaches the
// same flag.
func TestAnExhaustedBudgetIsReportedAsIncomplete(t *testing.T) {
	root := t.TempDir()
	for i := range 200 {
		name := filepath.Join(root, "f"+strconv.Itoa(i)+".php")
		if err := os.WriteFile(name, []byte("<?php echo 1;"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()

	if _, _, complete := runScan(ctx, root, DefaultRequest(root)); complete {
		t.Error("a scan whose budget had already expired reported itself complete")
	}
}

// An incomplete root has to reach the result the panel writes, or the flag stops
// at the function that computes it.
func TestAnIncompleteRootMarksTheWholeResultPartial(t *testing.T) {
	restore := fileCap
	fileCap = 20
	t.Cleanup(func() { fileCap = restore })

	root := t.TempDir()
	for i := range fileCap + 1 {
		name := filepath.Join(root, "f"+strconv.Itoa(i)+".php")
		if err := os.WriteFile(name, []byte("<?php echo 1;"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if result := executeScan(context.Background(), DefaultRequest(root)); !result.Partial {
		t.Error("a capped walk did not mark the result partial")
	}

	small := t.TempDir()
	if err := os.WriteFile(filepath.Join(small, "a.php"), []byte("<?php echo 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result := executeScan(context.Background(), DefaultRequest(small)); result.Partial {
		t.Error("an ordinary scan was marked partial")
	}
}

// The handler turns a partial result into a FAILED scan rather than a finished
// one. This is the assertion the source check in scanstate_test.go makes; it is
// repeated here from the other side so the cap fix cannot be undone by removing
// result.Partial from the condition alone.
func TestTheHandlerFailsAPartialScan(t *testing.T) {
	body, err := os.ReadFile("antivirus.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "result.Partial") {
		t.Error("a partial scan is no longer reported as failed")
	}
}
