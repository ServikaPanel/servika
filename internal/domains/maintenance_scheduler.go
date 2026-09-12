package domains

import (
	"context"
	"database/sql"
	"time"

	"servika/internal/logx"
)

// The scheduler that lifts maintenance mode when its deadline passes.
//
// nginx has no notion of time, so a mode that ends by itself needs something to
// re-render the vhost at the end of the window. This is that something.
//
// It ticks every minute rather than hourly like the backup scheduler: a
// customer who says "back in thirty minutes" means it, and an hourly pass would
// leave the site closed for up to an hour after the time they published on the
// page in front of it.

// maintenanceTick is how often the deadline is checked. A minute is the
// resolution the screen offers, so a finer tick would buy nothing.
const maintenanceTick = time.Minute

// StartMaintenanceScheduler lifts expired maintenance windows in the background.
func StartMaintenanceScheduler(db *sql.DB) {
	go func() {
		ticker := time.NewTicker(maintenanceTick)
		defer ticker.Stop()
		for range ticker.C {
			MaintenanceTickOnce(db)
		}
	}()
}

// MaintenanceTickOnce runs one pass. Exported so a test or an operator-triggered
// path can drive the same code the ticker does.
func MaintenanceTickOnce(db *sql.DB) {
	if db == nil {
		return
	}
	// Its own deadline, shorter than the tick interval, so a slow pass cannot
	// overlap the next one. The request context is not available here and
	// main's context never cancels.
	ctx, cancel := context.WithTimeout(context.Background(), maintenanceTick-5*time.Second)
	defer cancel()

	// The comparison is made in SQL. maintenance_until was written with
	// DATE_ADD(NOW(), ...), so the clock that set it is the clock that reads
	// it; comparing against a Go time here would reintroduce the timezone
	// difference the write path exists to avoid.
	//
	// The switch is NOT part of the condition. A lift clears the switch first,
	// because the renderer reads it back from the row, and clears the deadline
	// only once the vhost really changed. A panel that stops between the two
	// leaves maintenance_enabled=0 with the deadline still set and the 503
	// fragment still rendered, and the only record of that is the deadline. The
	// write path always clears the deadline together with the switch
	// (internal/domains/maintenance.go saveMaintenance), so a past deadline on a
	// row means one thing: a lift that did not finish.
	rows, err := db.QueryContext(ctx,
		`SELECT id FROM domains
		  WHERE maintenance_until IS NOT NULL
		    AND maintenance_until <= NOW()`)
	if err != nil {
		logx.Errorf("maintenance scheduler: could not read due domains: %v", err)
		return
	}
	var due []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			logx.Errorf("maintenance scheduler: could not read a due row: %v", err)
			continue
		}
		due = append(due, id)
	}
	if err := rows.Err(); err != nil {
		logx.Errorf("maintenance scheduler: could not read due domains: %v", err)
	}
	_ = rows.Close()

	for _, id := range due {
		liftMaintenance(ctx, db, id)
	}
}

// liftMaintenance clears one domain's switch, re-renders its vhost and then
// clears the deadline.
//
// The switch has to be cleared first: the renderer reads maintenance_enabled
// back from the row, so a render made before the write would emit the 503
// fragment again. The DEADLINE is what keeps the lift retryable. It is cleared
// last, so any interruption between the two writes leaves the row due and the
// next tick renders again. Every step is idempotent, so a repeat is free.
//
// The in-process failure branch also puts the switch back. That is not what
// makes the retry happen, it is what stops the panel from reporting the site as
// open while nginx still answers 503 for the minute until the next tick.
func liftMaintenance(ctx context.Context, db *sql.DB, domainID int64) {
	if _, err := db.ExecContext(ctx,
		`UPDATE domains SET maintenance_enabled=0 WHERE id=?`, domainID); err != nil {
		logx.Errorf("maintenance scheduler: could not clear domain %d: %v", domainID, err)
		return
	}
	if err := rerenderVhost(db, domainID); err != nil {
		// Put the switch back, so the panel does not report the site as open
		// for the minute until the next tick. The retry itself rests on the
		// deadline, which is still set.
		if _, restore := db.ExecContext(ctx,
			`UPDATE domains SET maintenance_enabled=1 WHERE id=?`, domainID); restore != nil {
			logx.Errorf("maintenance scheduler: could not restore domain %d after a failed render: %v", domainID, restore)
		}
		logx.Warnf("maintenance scheduler: could not re-render domain %d, will retry: %v", domainID, err)
		return
	}
	// Cleared only after the vhost really changed, so a domain whose render
	// failed still reads as due on the next pass.
	if _, err := db.ExecContext(ctx,
		`UPDATE domains SET maintenance_until=NULL WHERE id=?`, domainID); err != nil {
		logx.Errorf("maintenance scheduler: could not clear the deadline for domain %d: %v", domainID, err)
		return
	}
	logx.Infof("maintenance scheduler: domain %d is open again", domainID)
}
