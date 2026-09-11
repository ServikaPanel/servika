package backups

import (
	"database/sql"
	"time"
)

// backupDue reports whether a domain needs its scheduled backup taken now.
//
// The rule is "the domain's hour has come round and it has not been backed up
// since", not "it is this domain's hour". Those differ exactly when a tick is
// missed, which is the case this exists for: the pass is serial and unbounded,
// so an overrunning 03:00 run swallows the 04:00 and 05:00 ticks, and a panel
// restarted during a domain's hour loses the same day. Under the old exact-hour
// match the domain then waited a full day with nothing reporting the gap.
//
// The test is made against the LAST OCCURRENCE of the configured hour rather
// than against the current hour, so it is correct at every hour of the day
// including 23, where "the hour has already passed today" is false for most of
// the day after a missed run.
//
// The frequency's minimum interval stays as a floor, so a weekly domain is not
// promoted to daily by a slot that comes round every day. A domain that has
// never been backed up is due at the first tick: a domain with no backup at all
// is the state worth leaving least alone.
func backupDue(now time.Time, hour int, frequency string, lastBackup sql.NullInt64) bool {
	if !lastBackup.Valid {
		return true
	}
	last := time.Unix(lastBackup.Int64, 0)
	if now.Sub(last) < minimumInterval(frequency) {
		return false
	}
	return last.Before(lastHourSlot(now, hour))
}

// minimumInterval is the floor between two backups of the same domain. The
// slack is deliberate: a run that starts a few minutes late must not push the
// next one a whole period out.
func minimumInterval(frequency string) time.Duration {
	if frequency == "weekly" {
		return 6*24*time.Hour + 12*time.Hour
	}
	return 23 * time.Hour
}

// lastHourSlot is the most recent wall-clock moment at the configured hour:
// today's if it has already passed, otherwise yesterday's.
func lastHourSlot(now time.Time, hour int) time.Time {
	slot := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location())
	if slot.After(now) {
		slot = slot.AddDate(0, 0, -1)
	}
	return slot
}
