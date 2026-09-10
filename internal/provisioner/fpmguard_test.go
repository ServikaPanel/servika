package provisioner

// What the post-start guard decides, measured without a systemd.
//
// The systemd numbers these tests are built on were measured against real
// systemd 257 on AlmaLinux 10 and are recorded in fpmguard.go: a manual restart
// resets NRestarts to 0, a bounded crash-loop reaches `failed` after 15 seconds
// with NRestarts=5, and an unbounded one never reaches `failed` at all.

import (
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// guardDecisionWindow is the window given to a test that expects the guard to
// ACT. It has to be wide enough that the guard is bounded by the scripted
// states rather than by the wall clock: the script clamps to its last entry, so
// the guard reaches its decision on the second read at the latest and the test
// still costs a few milliseconds. A window of a few poll intervals put a
// scheduler delay in the race, and under a loaded `go test ./...` one sleep
// outlasted the deadline, the second state was never read, and the test
// reported a guard that had simply run out of time as a guard that had failed
// to convict.
const guardDecisionWindow = time.Second

// guardProbe counts what the guard did to the scripted host.
type guardProbe struct {
	rollbacks atomic.Int32
	readCount atomic.Int32
}

func (p *guardProbe) rollbackCount() int32 { return p.rollbacks.Load() }

// reads is what separates a test that measured the guard's decision from one
// whose loop never ran at all.
func (p *guardProbe) reads() int32 { return p.readCount.Load() }

// withUnitState replaces the systemd reader for one test and counts rollbacks.
func withUnitState(t *testing.T, states ...fpmUnitState) *guardProbe {
	t.Helper()
	// What is being measured is which state leads to a rollback, not how long
	// the sleep between reads is. TestTheShippedPollIntervalIsASecond holds the
	// real value.
	previousPoll := fpmPostStartPoll
	fpmPostStartPoll = time.Millisecond
	t.Cleanup(func() { fpmPostStartPoll = previousPoll })
	probe := &guardProbe{}
	previousRead, previousRollback := readFPMUnitState, rollbackTenantFPM
	readFPMUnitState = func(string) fpmUnitState {
		at := int(probe.readCount.Add(1)) - 1
		if at >= len(states) {
			at = len(states) - 1
		}
		return states[at]
	}
	rollbackTenantFPM = func(*sql.DB, int64, string, string) error {
		probe.rollbacks.Add(1)
		return nil
	}
	t.Cleanup(func() { readFPMUnitState, rollbackTenantFPM = previousRead, previousRollback })
	return probe
}

// requireTheGuardLooked fails a no-rollback test whose loop never ran, because
// such a test passes on any guard at all.
func requireTheGuardLooked(t *testing.T, probe *guardProbe) {
	t.Helper()
	if probe.reads() == 0 {
		t.Fatal("the guard never read the unit state, so this test measured nothing")
	}
}

func healthy() fpmUnitState {
	return fpmUnitState{ActiveState: "active", SubState: "running", Known: true}
}

// A master that stays up is left alone. Without this every check below would
// pass on a guard that rolls back unconditionally.
func TestAHealthyMasterIsNotRolledBack(t *testing.T) {
	probe := withUnitState(t, healthy())
	if err := guardPostStart(nil, 7, "c_tenant", "8.3", 3*fpmPostStartPoll); err != nil {
		t.Errorf("a healthy master was reported as a crash-loop: %v", err)
	}
	requireTheGuardLooked(t, probe)
	if got := probe.rollbackCount(); got != 0 {
		t.Errorf("a healthy master was rolled back %d time(s)", got)
	}
}

// systemd having given up is unambiguous: the site is already 502.
//
// Restarts is deliberately BELOW the threshold, so only ActiveState can convict
// here. With Restarts=5 beside it the count signal decides and this test says
// nothing about the `failed` branch: proven by removing that branch, after which
// the test still passed. It is also the real shape of a master that fails its
// very first start, where systemd never gets to restart anything.
func TestAFailedUnitIsRolledBack(t *testing.T) {
	probe := withUnitState(t,
		healthy(),
		fpmUnitState{ActiveState: "failed", SubState: "failed", Restarts: 0, Known: true})
	err := guardPostStart(nil, 7, "c_tenant", "8.3", guardDecisionWindow)
	if !errors.Is(err, errFPMCrashLoop) {
		t.Errorf("a failed unit was not reported as a crash-loop: %v", err)
	}
	if got := probe.rollbackCount(); got != 1 {
		t.Errorf("the rollback ran %d time(s), want 1", got)
	}
}

// The restart count is the second signal and is not redundant with `failed`.
// Measured: a unit without the StartLimit keys loops for good while reporting
// ActiveState=activating, SubState=auto-restart, so a host still carrying an
// older unit file shows nothing else.
func TestALoopThatNeverReachesFailedIsStillCaught(t *testing.T) {
	looping := fpmUnitState{
		ActiveState: "activating", SubState: "auto-restart",
		Restarts: fpmCrashLoopRestarts, Known: true,
	}
	probe := withUnitState(t, healthy(), looping)
	if err := guardPostStart(nil, 7, "c_tenant", "8.3", guardDecisionWindow); !errors.Is(err, errFPMCrashLoop) {
		t.Errorf("an unbounded loop was not caught: %v", err)
	}
	if got := probe.rollbackCount(); got != 1 {
		t.Errorf("the rollback ran %d time(s), want 1", got)
	}
}

// One restart is a master that died and came back. Taking a tenant's isolation
// away for that is worse than the blip, so the threshold is above one.
func TestASingleRestartIsNotACrashLoop(t *testing.T) {
	probe := withUnitState(t, fpmUnitState{
		ActiveState: "active", SubState: "running", Restarts: 1, Known: true,
	})
	if err := guardPostStart(nil, 7, "c_tenant", "8.3", 3*fpmPostStartPoll); err != nil {
		t.Errorf("a single restart was reported as a crash-loop: %v", err)
	}
	requireTheGuardLooked(t, probe)
	if got := probe.rollbackCount(); got != 0 {
		t.Errorf("a single restart caused %d rollback(s)", got)
	}
	if fpmCrashLoopRestarts < 2 {
		t.Fatal("the threshold is one, so this test cannot measure anything")
	}
}

// A read that FAILED is not evidence. This is the opposite of the fail-closed
// rule the authorization checks follow, and deliberately so: the only thing
// acting here does is remove a working tenant's isolation.
func TestAnUnreadableStateIsNotACrashLoop(t *testing.T) {
	probe := withUnitState(t, fpmUnitState{}) // Known is false
	if err := guardPostStart(nil, 7, "c_tenant", "8.3", 3*fpmPostStartPoll); err != nil {
		t.Errorf("an unreadable state was reported as a crash-loop: %v", err)
	}
	requireTheGuardLooked(t, probe)
	if got := probe.rollbackCount(); got != 0 {
		t.Errorf("an unreadable state caused %d rollback(s)", got)
	}
}

// A rollback that itself failed is reported as the rollback's error, not as the
// crash-loop, because the two leave the server in different states: one is a
// working site without isolation, the other is a site that is still down.
func TestAFailedRollbackIsReportedAsItself(t *testing.T) {
	previousRead, previousRollback := readFPMUnitState, rollbackTenantFPM
	t.Cleanup(func() { readFPMUnitState, rollbackTenantFPM = previousRead, previousRollback })
	previousPoll := fpmPostStartPoll
	fpmPostStartPoll = time.Millisecond
	t.Cleanup(func() { fpmPostStartPoll = previousPoll })
	readFPMUnitState = func(string) fpmUnitState {
		return fpmUnitState{ActiveState: "failed", SubState: "failed", Restarts: 0, Known: true}
	}
	sentinel := errors.New("the shared pool could not be restored")
	rollbackTenantFPM = func(*sql.DB, int64, string, string) error { return sentinel }

	err := guardPostStart(nil, 7, "c_tenant", "8.3", guardDecisionWindow)
	if !errors.Is(err, sentinel) {
		t.Errorf("a failed rollback answered %v, want the rollback's own error", err)
	}
	if errors.Is(err, errFPMCrashLoop) {
		t.Error("a failed rollback reads as a completed one")
	}
}

// Two saves in quick succession must not run two windows over one unit, because
// a rollback is not idempotent with an enable happening beside it.
func TestOnlyOneGuardRunsPerTenant(t *testing.T) {
	if !fpmGuardStart("c_tenant") {
		t.Fatal("the first guard could not start")
	}
	if fpmGuardStart("c_tenant") {
		t.Error("a second guard started for the same tenant")
	}
	if !fpmGuardStart("c_other") {
		t.Error("a different tenant was refused a guard")
	}
	fpmGuardEnd("c_tenant")
	if !fpmGuardStart("c_tenant") {
		t.Error("the tenant could not be guarded again after the first finished")
	}
	fpmGuardEnd("c_tenant")
	fpmGuardEnd("c_other")
}

// The claim above holds under real concurrency, not only in sequence.
func TestOnlyOneOfManyConcurrentGuardsStarts(t *testing.T) {
	const racers = 32
	var started int32
	var wg sync.WaitGroup
	wg.Add(racers)
	for range racers {
		go func() {
			defer wg.Done()
			if fpmGuardStart("c_race") {
				atomic.AddInt32(&started, 1)
			}
		}()
	}
	wg.Wait()
	fpmGuardEnd("c_race")
	if started != 1 {
		t.Errorf("%d guards started for one tenant, want 1", started)
	}
}

// The window has to be wider than the time a crash-loop takes to reach `failed`,
// which was measured at 15 seconds against real systemd. Landing exactly on that
// boundary is what upstream did, and a poll a second early would miss it.
func TestTheWindowLeavesMarginOverTheMeasuredTimeToFailed(t *testing.T) {
	const measuredTimeToFailed = 15 * time.Second
	if fpmPostStartWindow <= measuredTimeToFailed {
		t.Errorf("the window is %s, which does not clear the measured %s",
			fpmPostStartWindow, measuredTimeToFailed)
	}
}

// The startup and drift path keeps the unguarded call. A boot that starts one
// guard per tenant, every one able to remove that tenant's isolation, is a
// different thing from one person saving one domain's settings.
func TestAGuardIsNotWantedWithoutSomethingToRollBack(t *testing.T) {
	handle := &sql.DB{}
	if !guardWanted(handle, 7) {
		t.Error("an ordinary save is not guarded, so the rule refuses everything")
	}
	if guardWanted(nil, 7) {
		t.Error("a caller with no database is guarded by something that cannot roll back")
	}
	if guardWanted(handle, 0) {
		t.Error("a caller with no domain is guarded by something that cannot roll back")
	}
}

// The poll interval is lowered by every test above, so the shipped value is
// asserted on its own or the tests would agree with whatever they set.
func TestTheShippedPollIntervalIsASecond(t *testing.T) {
	if fpmPostStartPoll != time.Second {
		t.Errorf("fpmPostStartPoll is %s, want 1s", fpmPostStartPoll)
	}
}
