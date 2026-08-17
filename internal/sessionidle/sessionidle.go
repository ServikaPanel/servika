// Package sessionidle ends a session that has been sitting untouched.
//
// This is a different question from the JWT lifetime. The lifetime is ABSOLUTE:
// it ends the session that many seconds after it was issued, whether or not
// anybody was using it. Idle timeout measures from the LAST REQUEST, so it can
// protect an unattended screen without signing out somebody who is working.
// Both run at once and neither replaces the other.
package sessionidle

import (
	"context"
	"database/sql"
	"log"
	"sync"
	"time"
)

// MaxMinutes is the ceiling the write path enforces. A day is already long
// enough that the feature has stopped protecting anything, and a value past it
// is a typo rather than a policy.
const MaxMinutes = 1440

// touchInterval is how stale the stamp may get before it is rewritten.
//
// Writing on every request would put a row update behind every poll the
// interface makes, which on a dashboard left open is a write per second per
// viewer, for a value nothing reads at that resolution.
const touchInterval = 30 * time.Second

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

	// lastComplaint throttles the log line for a failed read. The check runs on
	// every authenticated request, so an unthrottled log would turn a database
	// outage into a full disk.
	complainMu    sync.Mutex
	lastComplaint time.Time
)

// Invalidate drops the cached setting. Every write path calls it.
func Invalidate() {
	mu.Lock()
	cached, cachedAt = 0, time.Time{}
	mu.Unlock()
}

// Valid reports whether minutes is a value the panel will store. Out of range
// is REFUSED on the write path rather than clamped: an operator who typed 5000
// asked for something this cannot do, and silently storing 1440 tells them it
// can.
func Valid(minutes int) bool {
	return minutes >= 0 && minutes <= MaxMinutes
}

// Minutes returns the configured idle timeout, 0 when the feature is off.
func Minutes(ctx context.Context, db *sql.DB) (int, error) {
	mu.RLock()
	if cachedAt.After(now().Add(-settingTTL)) {
		value := cached
		mu.RUnlock()
		return value, nil
	}
	mu.RUnlock()

	var minutes int
	if err := db.QueryRowContext(ctx,
		`SELECT session_idle_minutes FROM panel_settings WHERE id=1`).Scan(&minutes); err != nil {
		return 0, err
	}
	mu.Lock()
	cached, cachedAt = minutes, now()
	mu.Unlock()
	return minutes, nil
}

// Enforce reports whether the session has been idle longer than the configured
// timeout, and records the current activity when it has not.
//
// It is the ONE place the policy is applied, so the caller decides nothing.
// With the feature off it performs no database work at all: an installation
// that never turns this on pays nothing per request.
//
// A stamp of 0 means the column has never been written for this identity: a
// session opened before the feature existed, or before this column did. That is
// stamped rather than expired, so switching the feature on does not sign
// everybody out at once.
func Enforce(ctx context.Context, db *sql.DB, userID int64) (bool, error) {
	if db == nil || userID <= 0 {
		return false, nil
	}
	minutes, err := Minutes(ctx, db)
	if err != nil {
		return false, err
	}
	if minutes <= 0 {
		return false, nil
	}

	var last int64
	if err := db.QueryRowContext(ctx,
		`SELECT last_activity_ts FROM users WHERE id=?`, userID).Scan(&last); err != nil {
		return false, err
	}

	current := now().Unix()
	if last > 0 && current-last > int64(minutes)*60 {
		return true, nil
	}
	if current-last < int64(touchInterval/time.Second) {
		return false, nil
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE users SET last_activity_ts=? WHERE id=?`, current, userID); err != nil {
		return false, err
	}
	return false, nil
}

// Complain logs a failed check at most once per touchInterval.
//
// The failure is NOT swallowed, and it is not allowed to flood either: this
// runs on every authenticated request, so one line per failure would turn a
// database outage into a full disk.
func Complain(err error) {
	if err == nil {
		return
	}
	complainMu.Lock()
	defer complainMu.Unlock()
	if now().Sub(lastComplaint) < touchInterval {
		return
	}
	lastComplaint = now()
	log.Printf("session idle check: %v", err)
}
