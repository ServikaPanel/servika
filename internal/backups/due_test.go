package backups

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

func at(day, hour, minute int) time.Time {
	return time.Date(2026, time.March, day, hour, minute, 0, 0, time.UTC)
}

func backedUpAt(t time.Time) sql.NullInt64 {
	return sql.NullInt64{Int64: t.Unix(), Valid: true}
}

// The ordinary schedule: the domain runs when its hour comes round and not
// again until the next one.
func TestADomainRunsAtItsHourAndNotAgainThatDay(t *testing.T) {
	last := at(10, 3, 0)
	for _, c := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{"an hour later", at(10, 4, 0), false},
		{"the same evening", at(10, 22, 0), false},
		{"just before the next slot", at(11, 2, 59), false},
		{"the next slot", at(11, 3, 0), true},
	} {
		if got := backupDue(c.now, 3, "daily", backedUpAt(last)); got != c.want {
			t.Errorf("%s: backupDue = %t, want %t", c.name, got, c.want)
		}
	}
}

// The case this exists for. The pass is serial and each domain gets its own
// 25-minute budget, so an overrunning 03:00 run swallows the 04:00 and 05:00
// ticks; under an exact-hour match those domains waited a full day and the only
// symptom was a gap in their archive lists.
func TestADomainMissedByAnOverrunningPassIsCaughtUp(t *testing.T) {
	last := at(10, 4, 0) // yesterday's run
	if !backupDue(at(11, 4, 0), 4, "daily", backedUpAt(last)) {
		t.Fatal("the domain was not due at its own hour")
	}
	for _, now := range []time.Time{at(11, 5, 0), at(11, 6, 0), at(11, 20, 0)} {
		if !backupDue(now, 4, "daily", backedUpAt(last)) {
			t.Errorf("at %s the overdue domain was not picked up", now.Format("15:04"))
		}
	}
}

// The same holds for an hour near midnight, where "its hour has already passed
// today" is false for most of the day after a missed run. That is why the test
// is made against the last occurrence of the hour and not against the current
// hour.
func TestALateHourIsCaughtUpAfterMidnight(t *testing.T) {
	// Monday night ran; Tuesday 23:00 was missed; it is now Wednesday morning.
	if !backupDue(at(11, 0, 30), 23, "daily", backedUpAt(at(9, 23, 0))) {
		t.Error("a domain scheduled for 23:00 and missed was not caught up after midnight")
	}
	// With Tuesday's run taken, Wednesday morning is not due.
	if backupDue(at(11, 0, 30), 23, "daily", backedUpAt(at(10, 23, 0))) {
		t.Error("a domain backed up last night was run again this morning")
	}
}

// The frequency floor stays, or a weekly domain is promoted to daily by a slot
// that comes round every day.
func TestAWeeklyDomainIsNotPromotedToDaily(t *testing.T) {
	last := at(9, 3, 0)
	if backupDue(at(12, 3, 0), 3, "weekly", backedUpAt(last)) {
		t.Error("a weekly domain ran three days after its last backup")
	}
	if !backupDue(at(16, 3, 0), 3, "weekly", backedUpAt(last)) {
		t.Error("a weekly domain did not run a week after its last backup")
	}
}

// A domain with no backup at all is the state worth leaving least alone, so it
// runs at the first tick rather than waiting for its hour.
func TestADomainNeverBackedUpIsDueAtOnce(t *testing.T) {
	if !backupDue(at(10, 14, 0), 3, "daily", sql.NullInt64{}) {
		t.Error("a domain that has never been backed up was not due")
	}
}

// The scheduler must not filter by the current hour in SQL any more: that is
// what made a domain eligible during one tick a day with no catch-up.
func TestTheQueryNoLongerMatchesTheHourExactly(t *testing.T) {
	tick := backupsFunction(t, readBackupsSource(t, "schedule.go"), "func dueDomains(")
	if strings.Contains(tick, "COALESCE(backup_hour,3) = ?") {
		t.Error("the due query still matches the backup hour exactly")
	}
	if !strings.Contains(tick, "backupDue(now, d.Hour, d.Frequency, lastTs)") {
		t.Error("the due decision does not go through backupDue")
	}
}

// backupsFunction returns one function's body, from its signature to the
// closing brace in the first column.
func backupsFunction(t *testing.T, source, signature string) string {
	t.Helper()
	index := strings.Index(source, signature)
	if index < 0 {
		t.Fatalf("%q is not defined", signature)
	}
	body, _, found := strings.Cut(source[index:], "\n}\n")
	if !found {
		t.Fatalf("%q has no closing brace", signature)
	}
	return body
}
