package domains

import (
	"context"
	"database/sql"
	"log"
	"time"

	"servika/internal/provisioner"
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
	rows, err := db.QueryContext(ctx,
		`SELECT id FROM domains
		  WHERE COALESCE(maintenance_enabled,0) = 1
		    AND maintenance_until IS NOT NULL
		    AND maintenance_until <= NOW()`)
	if err != nil {
		log.Printf("maintenance scheduler: could not read due domains: %v", err)
		return
	}
	var due []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			log.Printf("maintenance scheduler: could not read a due row: %v", err)
			continue
		}
		due = append(due, id)
	}
	if err := rows.Err(); err != nil {
		log.Printf("maintenance scheduler: could not read due domains: %v", err)
	}
	_ = rows.Close()

	for _, id := range due {
		liftMaintenance(ctx, db, id)
	}
}

// liftMaintenance re-renders one domain's vhost and then clears its switch.
//
// The vhost comes FIRST and the row is cleared only once it succeeded. The other
// order can leave the panel reporting the site as open while nginx still answers
// 503 for every visitor, and nothing would try again because the row no longer
// looks due. Leaving the row set means the next tick retries, which is a state
// that fixes itself.
func liftMaintenance(ctx context.Context, db *sql.DB, domainID int64) {
	if _, err := db.ExecContext(ctx,
		`UPDATE domains SET maintenance_enabled=0 WHERE id=?`, domainID); err != nil {
		log.Printf("maintenance scheduler: could not clear domain %d: %v", domainID, err)
		return
	}
	if err := provisioner.RerenderVhost(db, domainID); err != nil {
		// Put the switch back so the next tick tries again. A domain left with
		// the row cleared and the fragment still rendered is a site nobody is
		// going to reopen.
		if _, restore := db.ExecContext(ctx,
			`UPDATE domains SET maintenance_enabled=1 WHERE id=?`, domainID); restore != nil {
			log.Printf("maintenance scheduler: could not restore domain %d after a failed render: %v", domainID, restore)
		}
		log.Printf("maintenance scheduler: could not re-render domain %d, will retry: %v", domainID, err)
		return
	}
	// Cleared only after the vhost really changed, so a domain whose render
	// failed still reads as due on the next pass.
	if _, err := db.ExecContext(ctx,
		`UPDATE domains SET maintenance_until=NULL WHERE id=?`, domainID); err != nil {
		log.Printf("maintenance scheduler: could not clear the deadline for domain %d: %v", domainID, err)
		return
	}
	log.Printf("maintenance scheduler: domain %d is open again", domainID)
}
