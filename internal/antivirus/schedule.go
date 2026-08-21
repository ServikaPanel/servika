package antivirus

// The nightly sweep.
//
// A scan somebody has to remember to start is a scan that runs after the
// symptom rather than before it, which is the whole reason the sweep exists.
// This is the same shape as internal/backups' scheduler: wake up hourly, act
// only in the configured hour, and do nothing at all when the feature is off.

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"time"

	"servika/internal/avsettings"
)

// scheduleWarmup delays the first pass past startup. provisioner.Init and the
// migrations are still running in the first seconds, and a sweep of the whole
// filesystem is the last thing a server needs while they are.
const scheduleWarmup = 5 * time.Minute

// scheduleGap is how long after the last sweep another may start. It is under a
// day so an hourly tick cannot skip a night when the clock drifts across the
// hour boundary, and over half of one so a panel restarted twice in an evening
// does not sweep twice.
const scheduleGap = 23 * time.Hour

// StartScheduler runs the automatic sweep. It returns immediately.
func StartScheduler(db *sql.DB) {
	if db == nil {
		return
	}
	go func() {
		time.Sleep(scheduleWarmup)
		tickOnce(db, time.Now)
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			tickOnce(db, time.Now)
		}
	}()
}

// TickOnce runs one scheduler pass, for a test or for an operator who wants the
// nightly behaviour rather than a sweep started by hand.
func TickOnce(db *sql.DB) { tickOnce(db, time.Now) }

// tickOnce decides whether a sweep is due and starts one.
//
// The clock is injected so the hour comparison can be exercised without waiting
// for it. The decision is made against the SERVER's local hour, matching what
// the operator picked on a screen that shows their own time.
func tickOnce(db *sql.DB, now func() time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), parentBudget)
	defer cancel()

	// systemd owns the schedule whenever the timer is enabled, and then this
	// scheduler stands down. Two things arming sweeps is the whole reason
	// internal/backups refuses a timer outright: one of them would be reading a
	// fixed OnCalendar and ignoring the hour the operator picked.
	//
	// The question is asked here rather than once at startup, because an
	// operator turns the timer on from the settings screen while the panel is
	// running, and a scheduler that had already decided would keep sweeping.
	if avsettings.ScanTimerEnabled() {
		return
	}
	settings, err := avsettings.Read(ctx, db)
	if err != nil {
		log.Printf("antivirus: the scheduled sweep could not read its settings: %v", err)
		return
	}
	if !settings.ScheduledScan {
		return
	}
	if now().Hour() != settings.ScheduledHour {
		return
	}
	if !settings.RuleEngine && !settings.LocationHeuristics {
		// Every layer is off, so a sweep would inspect nothing and record a
		// finished scan with no findings, which reads exactly like a clean
		// server. The hand-started sweep refuses this too.
		return
	}
	if recent, err := sweptRecently(ctx, db, now()); err != nil {
		// A read that failed is NOT treated as "no sweep yet". That direction
		// starts a sweep of the whole filesystem every hour for as long as the
		// database is unwell, which is the worst hour to be adding load.
		log.Printf("antivirus: whether a sweep is already due could not be read: %v", err)
		return
	} else if recent {
		return
	}

	// The same single slot a hand-started scan takes. A tick that cannot get it
	// simply waits for the next hour: forcing it would mean two sweeps reading
	// the same trees under one resource limit.
	slot, err := takeScanSlot(ctx, db)
	if err != nil {
		log.Printf("antivirus: the scheduled sweep was skipped, another scan is running")
		return
	}
	defer slot.Release()

	req := sweepRequest(settings)
	res, err := db.Exec(
		`INSERT INTO av_scans (domain_id, scope, status, engine) VALUES (NULL,?,?,?)`,
		settings.Scope, "running", engineName())
	if err != nil {
		log.Printf("antivirus: the scheduled sweep could not be recorded: %v", err)
		return
	}
	sid, _ := res.LastInsertId()
	log.Printf("antivirus: scheduled sweep %d starting over %v", sid, req.Roots)
	runSweep(ctx, db, sid, req)
}

// sweptRecently reports whether a sweep already ran inside the gap.
//
// started_at is compared in Go rather than with an SQL interval because the
// driver writes a Go time as UTC while NOW() answers in the session timezone,
// so a mixed comparison is wrong by the offset between them. UNIX_TIMESTAMP
// gives both sides the same unit.
func sweptRecently(ctx context.Context, db *sql.DB, now time.Time) (bool, error) {
	var started sql.NullInt64
	err := db.QueryRowContext(ctx,
		`SELECT UNIX_TIMESTAMP(started_at) FROM av_scans
		  WHERE domain_id IS NULL ORDER BY id DESC LIMIT 1`).Scan(&started)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil // no sweep has ever run
	}
	if err != nil {
		return false, err
	}
	if !started.Valid {
		return false, nil
	}
	return now.Sub(time.Unix(started.Int64, 0)) < scheduleGap, nil
}
