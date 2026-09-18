package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installer returns one with its marker in a directory the test owns.
func installer(t *testing.T) *Installer {
	t.Helper()
	return NewInstaller(filepath.Join(t.TempDir(), "state", "install-active.json"))
}

// allOff says nothing is installed.
func allOff(Item) bool { return false }

func TestAnUndecidedItemIsListedButNeverOffered(t *testing.T) {
	// Hiding it would only make someone install it by hand; offering it would
	// promise a path nobody has finished. The item is built here rather than
	// taken from the catalog, so the rule stays measured on a day when every
	// real item has a decided tier.
	rows := entriesFor([]Item{{Key: "later", Tier: TierUndecided}}, allOff)
	if !rows[0].Installed && rows[0].Installable {
		t.Fatal("an undecided item was offered for installation")
	}
	for _, row := range Catalog(allOff) {
		if row.Tier == TierUndecided && row.Installable {
			t.Fatalf("the undecided catalog item %q was offered", row.Key)
		}
	}
}

func TestAnInstalledItemIsNotOfferedAgain(t *testing.T) {
	rows := entriesFor([]Item{{Key: "iis", Tier: TierProven}}, func(Item) bool { return true })
	if !rows[0].Installed || rows[0].Installable {
		t.Fatalf("an installed item read as %+v", rows[0])
	}
}

func TestEveryCatalogKeyIsUniqueAndResolvable(t *testing.T) {
	// A duplicate key would make findItem answer with whichever came first, and
	// the operator would install something other than the row they pressed.
	seen := map[string]bool{}
	for _, item := range catalog {
		if seen[item.Key] {
			t.Fatalf("the key %q appears twice in the catalog", item.Key)
		}
		seen[item.Key] = true
		if _, ok := findItem(catalog, item.Key); !ok {
			t.Fatalf("the key %q does not resolve", item.Key)
		}
	}
	if _, ok := findItem(catalog, "nothing-like-this"); ok {
		t.Fatal("an unknown key resolved")
	}
}

func TestTheCatalogRowCarriesNoCapabilityBit(t *testing.T) {
	// The bit is how installation is DETECTED; it is an internal detail and
	// carrying it out would invite a caller to act on it.
	rows := Catalog(allOff)
	if len(rows) != len(catalog) {
		t.Fatalf("the catalog answered %d rows for %d items", len(rows), len(catalog))
	}
	if rows[0].Key != catalog[0].Key {
		t.Fatal("the catalog order was not kept")
	}
}

func TestOnlyOneInstallationRunsAtATime(t *testing.T) {
	// Two MSI or dism installations at once deadlock the Windows Installer and
	// can leave the system half-installed.
	in := installer(t)
	if _, err := in.claim("a", "iis"); err != nil {
		t.Fatalf("the first claim failed: %v", err)
	}
	_, err := in.claim("b", "mssql")
	if !errors.Is(err, ErrInstallRunning) {
		t.Fatalf("a second installation was allowed: %v", err)
	}
	in.release()
	if _, err := in.claim("c", "mssql"); err != nil {
		t.Fatalf("the slot was not freed: %v", err)
	}
}

func TestARestartLeavesTheLockClosedUntilAnOperatorClearsIt(t *testing.T) {
	// On Windows a child installer does NOT die when its parent does, so an
	// in-memory flag alone would let a second installation collide with an
	// msiexec that is still running.
	in := installer(t)
	job, err := in.claim("job-1", "mssql")
	if err != nil {
		t.Fatalf("the claim failed: %v", err)
	}
	in.writeMarker(job.ID, job.Key)

	// The agent restarts: a fresh Installer over the same marker.
	next := NewInstaller(in.MarkerPath)
	next.LoadPending()
	pending, key := next.Pending()
	if !pending || key != "mssql" {
		t.Fatalf("the half-finished installation was not noticed: pending=%v key=%q", pending, key)
	}
	if _, err := next.claim("job-2", "iis"); !errors.Is(err, ErrInstallPending) {
		t.Fatalf("a new installation started over a half-finished one: %v", err)
	}
	view, ok := next.JobStatus("job-1")
	if !ok || view.State != JobCut {
		t.Fatalf("the cut job read as %+v (found=%v)", view, ok)
	}

	next.ClearPending()
	if _, err := next.claim("job-3", "iis"); err != nil {
		t.Fatalf("clearing the lock did not let an installation start: %v", err)
	}
	if _, err := os.Stat(in.MarkerPath); !os.IsNotExist(err) {
		t.Fatal("the marker survived the operator's acknowledgement")
	}
}

func TestACorruptMarkerStillCountsAsPending(t *testing.T) {
	// Failing open here would be the exact case the marker exists to stop.
	in := installer(t)
	if err := os.MkdirAll(filepath.Dir(in.MarkerPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in.MarkerPath, []byte("{ this is not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	in.LoadPending()
	if pending, _ := in.Pending(); !pending {
		t.Fatal("a corrupt marker was read as no marker")
	}
}

func TestNoMarkerMeansNothingIsPending(t *testing.T) {
	in := installer(t)
	in.LoadPending()
	if pending, _ := in.Pending(); pending {
		t.Fatal("a clean start reported a half-finished installation")
	}
}

func TestTheLogKeepsTheNewestLinesOnly(t *testing.T) {
	job := &Job{ID: "x", state: JobRunning}
	for i := range logLines + 50 {
		job.Logf("line %d", i)
	}
	view := job.view()
	if len(view.Log) != logLines {
		t.Fatalf("the log held %d lines, expected %d", len(view.Log), logLines)
	}
	if !strings.Contains(view.Log[len(view.Log)-1], "line 549") {
		t.Fatalf("the newest line was dropped: %q", view.Log[len(view.Log)-1])
	}
	if strings.Contains(view.Log[0], "line 0") {
		t.Fatal("the oldest line survived past the ceiling")
	}
}

func TestAOneOffSecretNeverReachesTheLog(t *testing.T) {
	// A log stays in the scrollback and would show a generated password again on
	// every visit (CWE-532). The panel shows this once, in its own field.
	job := &Job{ID: "x", state: JobRunning}
	job.setSecret("Generated!Pass1")
	job.Logf("the superuser password was generated")
	view := job.view()
	if view.Secret != "Generated!Pass1" {
		t.Fatalf("the secret was not carried: %q", view.Secret)
	}
	if strings.Contains(strings.Join(view.Log, "\n"), "Generated!Pass1") {
		t.Fatal("the secret was written into the log")
	}
}

func TestAPanicInAnInstallerDoesNotTakeTheAgentDown(t *testing.T) {
	// One item's installation failing must not stop the running sites or the
	// agent's own API.
	in := installer(t)
	job, err := in.claim("p", "iis")
	if err != nil {
		t.Fatal(err)
	}
	in.run(job, Item{Key: "iis", Name: "IIS"}, func(*Job) error { panic("the installer exploded") }, nil)

	view := job.view()
	if view.State != JobFailed {
		t.Fatalf("a panicking installer settled as %q", view.State)
	}
	if !strings.Contains(strings.Join(view.Log, "\n"), "isolated") {
		t.Fatalf("the panic was not reported in the log:\n%s", strings.Join(view.Log, "\n"))
	}
	if _, err := in.claim("q", "ftp"); err != nil {
		t.Fatalf("the single-flight lock stayed closed after a panic: %v", err)
	}
}

func TestAFinishedRunFreesTheLockAndTheMarker(t *testing.T) {
	in := installer(t)
	job, err := in.claim("r", "git")
	if err != nil {
		t.Fatal(err)
	}
	in.writeMarker(job.ID, job.Key)
	in.run(job, Item{Key: "git", Name: "Git"}, func(*Job) error { return nil }, nil)

	if job.view().State != JobDone {
		t.Fatalf("a clean run settled as %q", job.view().State)
	}
	if _, err := os.Stat(in.MarkerPath); !os.IsNotExist(err) {
		t.Fatal("the marker survived a finished run")
	}
	if _, err := in.claim("s", "node"); err != nil {
		t.Fatalf("the lock stayed closed after a finished run: %v", err)
	}
}

func TestAPartialResultIsNotReportedAsDone(t *testing.T) {
	// Reporting a readiness that is not there is the failure this whole file
	// exists to avoid.
	in := installer(t)
	job, _ := in.claim("t", "mysql")
	in.run(job, Item{Key: "mysql", Name: "MySQL"}, func(*Job) error {
		return ErrPartialInstall
	}, nil)
	if got := job.view().State; got != JobPartial {
		t.Fatalf("a partial installation settled as %q", got)
	}
}

func TestTheOutcomeFollowsTheError(t *testing.T) {
	if got := outcomeOf(nil); got != JobDone {
		t.Fatalf("no error settled as %q", got)
	}
	if got := outcomeOf(errors.New("boom")); got != JobFailed {
		t.Fatalf("an error settled as %q", got)
	}
	wrapped := errors.Join(ErrPartialInstall, errors.New("php is missing"))
	if got := outcomeOf(wrapped); got != JobPartial {
		t.Fatalf("a wrapped partial settled as %q", got)
	}
}

func TestTheStateChangesAfterTheClosingLogLine(t *testing.T) {
	// A client that sees "finished" must already have the closing lines in front
	// of it, or the reason for a failure never reaches the screen.
	in := installer(t)
	job, _ := in.claim("u", "iis")
	in.run(job, Item{Key: "iis", Name: "IIS"}, func(*Job) error { return errors.New("dism said no") }, nil)
	view := job.view()
	if !view.Finished {
		t.Fatal("the job did not settle")
	}
	last := view.Log[len(view.Log)-1]
	if !strings.Contains(last, "dism said no") {
		t.Fatalf("the failure reason is not the last line: %q", last)
	}
}

func TestTheProgressStartsUnknownRatherThanZero(t *testing.T) {
	// An invented estimate is the same mistake as an invented success.
	job := &Job{ID: "x", state: JobRunning}
	job.setProgress(Progress{Stage: "installing", Label: "running the installer", Percent: -1, SecondsLeft: -1})
	got := job.view().Progress
	if got.Percent != -1 || got.SecondsLeft != -1 {
		t.Fatalf("an unknown duration was reported as %+v", got)
	}
}

func TestAnUnknownJobIsNotInvented(t *testing.T) {
	in := installer(t)
	if _, ok := in.JobStatus("never-existed"); ok {
		t.Fatal("an unknown job id answered")
	}
}

func TestTheCleanupRunsAfterEveryOutcome(t *testing.T) {
	// The capability cache has to be dropped whether the installation worked or
	// not, because a partial run can still have changed the host.
	in := installer(t)
	for _, outcome := range []error{nil, ErrPartialInstall, errors.New("no")} {
		ran := false
		job, err := in.claim("v", "iis")
		if err != nil {
			t.Fatal(err)
		}
		in.run(job, Item{Key: "iis"}, func(*Job) error { return outcome }, func() { ran = true })
		if !ran {
			t.Fatalf("the cleanup was skipped for outcome %v", outcome)
		}
	}
}

func TestCommandOutputReachesTheLogLineByLine(t *testing.T) {
	// A fifteen-minute installation has to show live progress, so the output is
	// streamed rather than collected and written once at the end.
	job := &Job{ID: "x", state: JobRunning}
	w := &logWriter{job: job}
	if _, err := w.Write([]byte("first line\r\nsecond ")); err != nil {
		t.Fatal(err)
	}
	if got := len(job.view().Log); got != 1 {
		t.Fatalf("after one complete line the log held %d lines", got)
	}
	if _, err := w.Write([]byte("line\n")); err != nil {
		t.Fatal(err)
	}
	log := job.view().Log
	if len(log) != 2 || !strings.HasSuffix(log[1], "  second line") {
		t.Fatalf("a line split across two writes read as %v", log)
	}
}

func TestTheLastPartialLineIsNotLost(t *testing.T) {
	// An installer that dies without a trailing newline still has to show its
	// last words, which are usually the reason it died.
	job := &Job{ID: "x", state: JobRunning}
	w := &logWriter{job: job}
	if _, err := w.Write([]byte("Error 1603: fatal error during installation")); err != nil {
		t.Fatal(err)
	}
	if len(job.view().Log) != 0 {
		t.Fatal("an incomplete line was written before the command ended")
	}
	w.flush()
	log := job.view().Log
	if len(log) != 1 || !strings.Contains(log[0], "Error 1603") {
		t.Fatalf("the last partial line read as %v", log)
	}
	w.flush()
	if len(job.view().Log) != 1 {
		t.Fatal("a second flush wrote the same line again")
	}
}

func TestABlankOutputLineIsNotLogged(t *testing.T) {
	job := &Job{ID: "x", state: JobRunning}
	w := &logWriter{job: job}
	if _, err := w.Write([]byte("\n\r\n   \n")); err != nil {
		t.Fatal(err)
	}
	w.flush()
	if got := len(job.view().Log); got != 0 {
		t.Fatalf("blank output produced %d log lines", got)
	}
}
