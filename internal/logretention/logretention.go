// Package logretention decides how long the panel keeps its own log rows, and
// deletes the rows that are older than that.
//
// The three log tables grow with traffic and nothing else ever removes a row, so
// on a busy panel they would be the largest tables in the database within a
// month. How long the rows are worth keeping is a policy question, not a
// technical one: an operator who has to answer an audit needs a year, and an
// operator on a small server needs a week. So the number is a setting, and this
// package is the one place that reads it and the one place that acts on it.
package logretention

import (
	"context"
	"database/sql"
	"sync"
	"time"
)

// The range the write path accepts. A day is the shortest window in which a
// yesterday's incident can still be read, and a year is long enough that the
// table size is the operator's decision rather than an accident.
const (
	MinDays = 1
	MaxDays = 365
)

// settingTTL bounds how long a changed setting takes to reach a running panel
// when it was changed OUTSIDE the panel. Save calls Invalidate, so an operator
// using the screen never waits this out.
const settingTTL = 60 * time.Second

// now is a seam so a test can move time without sleeping.
var now = time.Now

var (
	mu       sync.RWMutex
	cached   int
	cachedAt time.Time
)

// Invalidate drops the cached setting. Every write path calls it.
func Invalidate() {
	mu.Lock()
	cached, cachedAt = 0, time.Time{}
	mu.Unlock()
}

// Valid reports whether days is a value the panel will store.
//
// Out of range is REFUSED on the write path rather than clamped. An operator who
// typed 3000 asked for something this cannot do, and silently storing 365 tells
// them it can. Zero is not "keep for ever" either: a table nothing ever prunes
// is the failure this package exists to prevent, and an operator who wants that
// can say 365 and mean it.
func Valid(days int) bool {
	return days >= MinDays && days <= MaxDays
}

// Days returns the configured retention window.
func Days(ctx context.Context, db *sql.DB) (int, error) {
	mu.RLock()
	if cachedAt.After(now().Add(-settingTTL)) {
		value := cached
		mu.RUnlock()
		return value, nil
	}
	mu.RUnlock()

	var days int
	if err := db.QueryRowContext(ctx,
		`SELECT log_retention_days FROM panel_settings WHERE id=1`).Scan(&days); err != nil {
		return 0, err
	}
	mu.Lock()
	cached, cachedAt = days, now()
	mu.Unlock()
	return days, nil
}
