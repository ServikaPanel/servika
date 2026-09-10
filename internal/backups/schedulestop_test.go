package backups

import (
	"context"
	"os"
	"strings"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"
)

// The nightly pass never registered a cancel function, so StopJob found nothing
// to cancel and took the branch written for a row a panel restart left behind:
// it marked a LIVE run as failed, answered ok:true, and the sweep kept
// saturating the host's disk for its full duration before finishJob quietly
// overwrote the failure.
func TestTheScheduledPassIsStoppable(t *testing.T) {
	const jobID = int64(4242)
	t.Cleanup(func() { unregisterJob(jobID) })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	registerJob(jobID, cancel)

	if !stopJob(jobID) {
		t.Fatal("stopJob() found no cancel function for a registered job")
	}
	if ctx.Err() == nil {
		t.Fatal("stopJob() did not cancel the job's context")
	}
}

// An id nothing registered is a row whose process is gone, which is the only
// case the failed-close branch is for.
func TestAnUnregisteredJobCannotBeCancelled(t *testing.T) {
	if stopJob(999999) {
		t.Fatal("stopJob() claimed to cancel a job that was never registered")
	}
}

// A stopped run must not read as a failed one. finishJobStopped is what tells
// the two apart, and the scheduled pass had no way to reach it.
func TestAStoppedPassIsNotRecordedAsFailed(t *testing.T) {
	if got := jobStatus(0, 0); got == "stopped" {
		t.Fatalf("jobStatus() already returns %q, so the stopped flag would be redundant", got)
	}
	// The tallies of a run stopped after two clean domains say "done"; only the
	// stopped flag can correct that.
	if got := jobStatus(2, 0); got != "done" {
		t.Fatalf("jobStatus(2, 0) = %q, want %q", got, "done")
	}
}

func stopRequest(role, username string) *auth.Claims {
	if role == "" {
		return nil
	}
	return &auth.Claims{UserID: 7, Username: username, Role: role}
}

// jobScopeFilter is a READ filter: it deliberately shows a reseller the nightly
// pass because that pass archived one of their domains. Reusing it as the write
// guard let one of its subjects end the backup of every other tenant on the
// host.
func TestAResellerCannotStopTheNightlyPass(t *testing.T) {
	reseller := jobRequest(stopRequest(middleware.RoleReseller, "agency"))

	if mayStopJob(reseller, "system") {
		t.Fatal("a reseller may stop the server-wide nightly job")
	}
}

// The two parties that may end a job: an admin, and whoever started it.
func TestAnAdminAndTheStarterMayStopAJob(t *testing.T) {
	admin := jobRequest(stopRequest(middleware.RoleAdmin, "root"))
	if !mayStopJob(admin, "system") {
		t.Fatal("an admin cannot stop the nightly job")
	}

	starter := jobRequest(stopRequest(middleware.RoleReseller, "agency"))
	if !mayStopJob(starter, "agency") {
		t.Fatal("a reseller cannot stop the job they started themselves")
	}
}

// A caller with no claims is refused, so an unauthenticated path cannot reach the
// nightly job through its started_by name of "system".
func TestACallerWithNoClaimsMayStopNothing(t *testing.T) {
	if mayStopJob(jobRequest(nil), "system") {
		t.Fatal("a caller with no claims may stop a job")
	}
}

// tickOnce writes archives and shells out to tar, so its wiring is read
// from the source rather than run. What matters is that the three pieces the
// stop control needs are all present: the registration, the check between
// domains, and the job context reaching the per-domain call.
func TestTheScheduledPassIsWiredForCancellation(t *testing.T) {
	body := functionBody(t, "schedule.go", "func tickOnce(")

	for _, want := range []string{
		"registerJob(jobID, jobCancel)",
		"unregisterJob(jobID)",
		"jobCtx.Err() != nil",
		"runOneBackup(jobCtx,",
		"finishJobStopped(db, jobID, succeeded, failed, stopped)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("tickOnce is missing %q, so the stop control does not reach it", want)
		}
	}
	// The old wiring closed every run as if it had simply finished, so a stopped
	// pass was indistinguishable from a completed one.
	if strings.Contains(body, "finishJob(db, jobID") {
		t.Error("tickOnce still closes the job without reporting a stop")
	}
}

// functionBody returns the source of one function, from its signature to the
// closing brace in the first column.
func functionBody(t *testing.T, path, signature string) string {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	start := strings.Index(string(source), signature)
	if start < 0 {
		t.Fatalf("%s does not define %q", path, signature)
	}
	rest := string(source)[start:]
	body, _, found := strings.Cut(rest, "\n}\n")
	if !found {
		t.Fatalf("%q in %s has no closing brace", signature, path)
	}
	return body
}
