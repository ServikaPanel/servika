package antivirus

import (
	"strings"
	"testing"
	"time"
)

// The gap has to be under a day and over half of one, and neither bound is
// arbitrary. At a day or more an hourly tick can skip a whole night when the
// clock drifts across the hour boundary; at half a day or less a panel
// restarted twice in an evening sweeps the server twice.
func TestTheGapBetweenSweepsCannotSkipANightOrDoubleUp(t *testing.T) {
	if scheduleGap >= 24*time.Hour {
		t.Errorf("a gap of %v can skip a night when the clock drifts", scheduleGap)
	}
	if scheduleGap <= 12*time.Hour {
		t.Errorf("a gap of %v lets one evening sweep the server twice", scheduleGap)
	}
}

// The first pass waits for startup to finish. provisioner.Init and the
// migrations are still running in the first seconds, and a sweep of the whole
// filesystem is the last thing a server needs while they are.
func TestTheFirstPassWaitsForStartup(t *testing.T) {
	if scheduleWarmup < time.Minute {
		t.Errorf("the warmup of %v starts a sweep while the panel is still starting", scheduleWarmup)
	}
}

// Every condition that can stop a tick has to be there, and each one closes a
// different failure. This reads the source because the decision needs a live
// database to exercise, and a decision nothing checks is a decision that can be
// deleted by accident.
func TestEveryConditionThatStopsATickIsStillThere(t *testing.T) {
	source := sourceOf(t, "schedule.go")
	for _, guard := range []struct{ code, why string }{
		{"if !settings.ScheduledScan {",
			"the feature being off no longer stops the tick"},
		{"if now().Hour() != settings.ScheduledHour {",
			"the configured hour no longer stops the tick"},
		{"if !settings.RuleEngine && !settings.LocationHeuristics {",
			"a sweep that would inspect nothing is no longer skipped"},
		{"if recent, err := sweptRecently(ctx, db, now()); err != nil {",
			"a sweep that already ran no longer stops the tick"},
		{"slot, err := takeScanSlot(ctx, db)",
			"the tick no longer respects the single scan slot"},
	} {
		if !strings.Contains(source, guard.code) {
			t.Error(guard.why)
		}
	}

	// A failed read is NOT treated as "no sweep yet". That direction starts a
	// sweep of the whole filesystem every hour for as long as the database is
	// unwell, which is the worst hour to be adding load.
	failOpen := strings.Index(source, "log.Printf(\"antivirus: whether a sweep is already due could not be read")
	if failOpen < 0 {
		t.Fatal("the read failure is no longer reported")
	}
	after := source[failOpen:]
	if !strings.HasPrefix(strings.TrimSpace(after[strings.Index(after, "\n"):]), "return") {
		t.Error("a failed read no longer stops the tick, so an unwell database triggers an hourly sweep")
	}
}

// The comparison is in Go with both sides in Unix seconds. The driver writes a
// Go time as UTC while NOW() answers in the session timezone, so a mixed
// comparison is wrong by the offset between them, which for a nightly job is
// hours.
func TestTheRecencyComparisonUsesOneUnitOnBothSides(t *testing.T) {
	source := sourceOf(t, "schedule.go")
	if !strings.Contains(source, "SELECT UNIX_TIMESTAMP(started_at) FROM av_scans") {
		t.Error("the last sweep is no longer read as a Unix timestamp")
	}
	if strings.Contains(source, "INTERVAL") {
		t.Error("the recency test moved into SQL, where it compares two different clocks")
	}
	// A server that has never swept must sweep, not be treated as swept.
	if !strings.Contains(source, "return false, nil // no sweep has ever run") {
		t.Error("a server that has never been swept may no longer be swept")
	}
}

// The scheduler holds the same single slot every other scan takes, and releases
// it however the sweep ends.
func TestTheScheduledSweepReleasesTheSlot(t *testing.T) {
	source := sourceOf(t, "schedule.go")
	lock := strings.Index(source, "slot, err := takeScanSlot(ctx, db)")
	release := strings.Index(source, "defer slot.Release()")
	switch {
	case lock < 0:
		t.Fatal("the tick no longer takes the scan slot")
	case release < 0:
		t.Fatal("the tick no longer releases the scan slot")
	case release < lock:
		t.Error("the slot is released before it is taken")
	}
}

// A nil database must not panic the startup path, which is what wires this.
func TestTheSchedulerSurvivesANilDatabase(t *testing.T) {
	StartScheduler(nil)
}
