package antivirus

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// treeWithShells writes n PHP files, every third one a webshell, and returns
// the root. The names are zero-padded so the walk order is the numeric order.
func treeWithShells(t *testing.T, n int) string {
	t.Helper()
	root := t.TempDir()
	for i := range n {
		body := "<?php echo 'ordinary';\n"
		if i%3 == 0 {
			body = "<?php system($_GET['cmd']);\n"
		}
		name := filepath.Join(root, "f"+strconv.Itoa(1000+i)+".php")
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// The pool must not change WHAT the scan finds or the ORDER it reports it in.
// A finding list that depends on the core count cannot be compared between two
// runs, and every test in this package that asserts on a list would become
// flaky rather than wrong.
func TestTheWorkerCountChangesNeitherTheFindingsNorTheirOrder(t *testing.T) {
	root := treeWithShells(t, 30)
	req := DefaultRequest(root)

	var reference []string
	for _, workers := range []int{0, 1, 2, 8, 32} {
		req.Workers = workers
		scanned, _, findings, complete := runScan(context.Background(), root, req, nil)
		if !complete {
			t.Fatalf("%d workers: the scan reported itself incomplete", workers)
		}
		if scanned != 30 {
			t.Errorf("%d workers: scanned %d files, want 30", workers, scanned)
		}
		var got []string
		for _, f := range findings {
			got = append(got, f.File)
		}
		if len(got) != 10 {
			t.Fatalf("%d workers: %d findings, want 10", workers, len(got))
		}
		if reference == nil {
			reference = got
			continue
		}
		for i := range got {
			if got[i] != reference[i] {
				t.Fatalf("%d workers: finding %d is %s, single-worker run had %s",
					workers, i, got[i], reference[i])
			}
		}
	}
}

// The ceiling has to actually slow the scan down, or the setting is a number
// on a screen. It is measured against the floor the arithmetic demands rather
// than against a guess: n files at r a second cannot finish sooner than
// (n-1)/r, because the first file goes through on the ticker's first tick.
func TestTheFileRateCeilingSlowsTheScanDown(t *testing.T) {
	const files, rate = 24, 30
	root := treeWithShells(t, files)

	req := DefaultRequest(root)
	req.Workers = 8

	unlimited := time.Now()
	if _, _, _, complete := runScan(context.Background(), root, req, nil); !complete {
		t.Fatal("the unlimited scan reported itself incomplete")
	}
	unlimitedFor := time.Since(unlimited)

	req.FileRatePerSec = rate
	limited := time.Now()
	_, _, findings, complete := runScan(context.Background(), root, req, nil)
	limitedFor := time.Since(limited)
	if !complete {
		t.Fatal("the rate-limited scan reported itself incomplete")
	}
	// The ceiling slows the scan; it does not change what the scan finds.
	if len(findings) != 8 {
		t.Errorf("the rate ceiling changed the findings: got %d, want 8", len(findings))
	}

	floor := time.Duration(files-1) * time.Second / rate
	if limitedFor < floor {
		t.Errorf("a ceiling of %d files/s finished %d files in %v, under the %v floor",
			rate, files, limitedFor, floor)
	}
	t.Logf("unlimited %v, ceiling of %d files/s %v (floor %v)",
		unlimitedFor.Round(time.Millisecond), rate,
		limitedFor.Round(time.Millisecond), floor)
}

// A rate the write path would refuse still reaches the worker through a
// request file that outlives the code which wrote it. NewTicker panics on a
// non-positive interval, so the worker clamps rather than crashing.
func TestARateTooLargeForATickerDoesNotCrashTheScan(t *testing.T) {
	root := treeWithShells(t, 3)
	req := DefaultRequest(root)
	req.FileRatePerSec = 2_000_000_000 // time.Second/this rounds to 0
	scanned, _, findings, complete := runScan(context.Background(), root, req, nil)
	if !complete {
		t.Fatal("the scan reported itself incomplete")
	}
	if scanned != 3 || len(findings) != 1 {
		t.Errorf("scanned %d files and found %d, want 3 and 1", scanned, len(findings))
	}
}

// A cancelled scan must END. Every worker returns on cancellation, and if the
// walk then blocked sending to a channel nobody reads, the scan would hang for
// good rather than reporting itself partial.
func TestACancelledScanDoesNotHangOnItsOwnPool(t *testing.T) {
	root := treeWithShells(t, 200)
	req := DefaultRequest(root)
	req.Workers = 2
	req.FileRatePerSec = 1 // slow enough that cancellation lands mid-walk

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	done := make(chan bool, 1)
	go func() {
		_, _, _, complete := runScan(ctx, root, req, nil)
		done <- complete
	}()
	select {
	case complete := <-done:
		if complete {
			t.Error("a cancelled scan reported itself complete")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the scan never returned after its context was cancelled")
	}
}
