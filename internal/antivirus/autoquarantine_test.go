package antivirus

import (
	"os"
	"strings"
	"testing"
)

func sourceOf(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// Only a CRITICAL finding is taken. A suspicious one is, by construction, two
// signals neither of which convicts on its own, and the weighing exists exactly
// so such a file is reported to a person rather than acted on.
func TestOnlyCriticalFindingsAreContainedAutomatically(t *testing.T) {
	source := sourceOf(t, "autoquarantine.go")
	if !strings.Contains(source, "f.level=? AND f.quarantined=0`, scanID, LevelCritical") {
		t.Error("automatic containment no longer restricts itself to critical findings")
	}
	// A finding with no domain has nowhere to be contained into, and one whose
	// domain was deleted after the scan has no home directory left. The join is
	// what excludes both.
	if !strings.Contains(source, "JOIN domains d ON d.id = f.domain_id") {
		t.Error("automatic containment no longer requires a tenant to contain into")
	}
	// A file already contained must not be counted again. The whole pass would
	// otherwise report every earlier containment as work it just did.
	if !strings.Contains(source, "f.quarantined=0") {
		t.Error("automatic containment no longer skips what is already contained")
	}
}

// A run that left files behind is not a finished cleanup. Both halves are
// counted and both reach the row, or the screen reports a containment that did
// not happen.
func TestBothHalvesOfAnAutomaticPassAreCounted(t *testing.T) {
	source := sourceOf(t, "autoquarantine.go")
	// Three outcomes, not two. A WordPress core file is reported and left in
	// place, which is neither a success nor a failure: counted as taken it
	// claims a containment that did not happen, counted as failed it sends an
	// operator after a fault that is not there, counted nowhere it lets a pass
	// that left two infected core files read as a clean one.
	for _, part := range []string{"out.Taken++", "out.Failed++", "out.CoreSkipped++"} {
		if !strings.Contains(source, part) {
			t.Errorf("an automatic pass no longer counts %q", part)
		}
	}
	if !strings.Contains(source,
		"UPDATE av_scans SET auto_quarantined=?, auto_quarantine_failed=?, auto_quarantine_core_skipped=? WHERE id=?") {
		t.Error("what the automatic pass did is no longer recorded")
	}
	// A finding list cut short by a database error must not be reported as a
	// completed pass: the files that were never read are still in place.
	if !strings.Contains(source, "closeErr != nil") || !strings.Contains(source, "rows.Err()") {
		t.Error("a truncated finding list is no longer counted as a failure")
	}

	// And both counts have to reach the API, or nothing renders them.
	for _, file := range []string{"antivirus.go", "sweep.go"} {
		body := sourceOf(t, file)
		for _, field := range []string{"auto_quarantined", "auto_quarantine_failed", "auto_quarantine_core_skipped"} {
			if !strings.Contains(body, field) {
				t.Errorf("%s no longer reports %q", file, field)
			}
		}
	}
}

// The containment must not run inside the rows loop. quarantineFinding issues
// several statements of its own, and holding a result set open across them on
// one connection is what turns a slow containment into a stalled pass.
func TestTheContainmentRunsAfterTheResultSetIsClosed(t *testing.T) {
	source := sourceOf(t, "autoquarantine.go")
	closed := strings.Index(source, "_ = rows.Close()")
	contain := strings.Index(source, "h.quarantineFinding(t.domainID")
	switch {
	case closed < 0:
		t.Fatal("the result set is no longer closed explicitly")
	case contain < 0:
		t.Fatal("the containment call moved; this test has to follow it")
	case contain < closed:
		t.Error("the containment runs while the finding result set is still open")
	}
}

// Both scan paths honour the switch, and neither acts when it is off. A switch
// enforced on one path is not enforced.
func TestBothScanPathsHonourTheSwitch(t *testing.T) {
	// The per-domain scan runs the containment inline; every sweep, whether an
	// operator started it or the scheduler did, goes through runSweep.
	for file, call := range map[string]string{
		"antivirus.go": "recordAutoQuarantine(h.DB, sid, h.autoQuarantine(ctx, sid))",
		"sweep.go":     "recordAutoQuarantine(db, sid, (&Handlers{DB: db}).autoQuarantine(ctx, sid))",
	} {
		source := sourceOf(t, file)
		if !strings.Contains(source, "if req.AutoQuarantine {") {
			t.Errorf("%s does not gate automatic containment on the switch", file)
		}
		if !strings.Contains(source, call) {
			t.Errorf("%s no longer runs automatic containment", file)
		}
	}
	// The scheduler must not have grown a second copy of the sweep: a switch
	// honoured on one path and not the other is a switch that is not honoured.
	schedule := sourceOf(t, "schedule.go")
	if !strings.Contains(schedule, "runSweep(ctx, db, sid, req)") {
		t.Error("the scheduled sweep no longer goes through the shared sweep path")
	}
	if strings.Contains(schedule, "recordAutoQuarantine(") {
		t.Error("the scheduler grew its own copy of automatic containment")
	}
}

// The containment runs BEFORE the status is written, so a screen that sees a
// finished scan sees the containment that went with it rather than a list of
// findings about to move under it.
func TestContainmentRunsBeforeTheScanIsMarkedFinished(t *testing.T) {
	for _, file := range []string{"antivirus.go", "sweep.go"} {
		source := sourceOf(t, file)
		contain := strings.Index(source, "if req.AutoQuarantine {")
		status := strings.Index(source, `status := "finished"`)
		switch {
		case contain < 0 || status < 0:
			t.Fatalf("%s: the containment or the status decision moved", file)
		case contain > status:
			t.Errorf("%s marks the scan finished before containing anything", file)
		}
	}
}

// The worker never sees the switch. A worker that could act on it would be a
// worker that moves a customer's files, and it has no database to record that
// in either.
func TestTheWorkerCannotContainAnything(t *testing.T) {
	source := sourceOf(t, "worker.go")
	if !strings.Contains(source, "AutoQuarantine bool `json:\"-\"`") {
		t.Error("the automatic containment switch is serialised into the worker's request")
	}
	if strings.Contains(source, "quarantineFinding") {
		t.Error("the worker can contain a file")
	}
}
