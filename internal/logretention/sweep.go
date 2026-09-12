package logretention

import (
	"context"
	"database/sql"
	"time"

	"servika/internal/bgjob"
	"servika/internal/logx"
)

// logTable is one table this package prunes and the column that dates its rows.
//
// The column is carried with the name because the replay tables do not use ts:
// a recording is dated by when it began and a batch by when it arrived.
type logTable struct {
	name   string
	column string
}

// The tables this package prunes. Nothing else ever deletes from them.
//
// replay_sessions is dated by updated_at, which the ingest path bumps on every
// batch, and NOT by started_at. A recording that began 31 days ago and received
// a batch this morning would otherwise lose the row its batches point at, and
// nothing would find them again. With updated_at the row outlives its newest
// batch, so the batches are always gone first. replay_events is still swept
// before it, so one pass never leaves the pair inconsistent.
//
// audit_log is deliberately ABSENT. It records who changed what, which is the
// one log an operator may have to produce months later, and deleting it on a
// timer set for request volume would throw that away as a side effect.
var tables = []logTable{
	{"request_logs", "ts"},
	{"app_logs", "ts"},
	{"ui_events", "ts"},
	{"replay_events", "created_at"},
	{"replay_sessions", "updated_at"},
}

// deleteBatch bounds one DELETE.
//
// A single statement covering a month of rows holds the table's lock for as long
// as it runs, and this table is on the same server as the customer sites. The
// loop below repeats until a pass deletes less than this, so the work still
// finishes; it just yields between batches.
const deleteBatch = 5000

// sweepInterval is an hour. The window is measured in days, so nothing is gained
// by looking more often, and an hourly pass keeps each one small.
const sweepInterval = time.Hour

// maxBatches bounds ONE sweep, so a table that is millions of rows behind (the
// setting was just lowered, or the panel ran for a year without one) cannot hold
// the database for the whole hour. What is left is deleted by the next pass.
const maxBatches = 200

// Sweep deletes the rows that are older than the configured window.
//
// It reads the setting itself rather than taking it as an argument, so the
// caller cannot pass a stale value, and a lowered setting takes effect on the
// next pass with no restart.
func Sweep(ctx context.Context, db *sql.DB) {
	days, err := Days(ctx, db)
	if err != nil {
		logx.Errorf("log retention: the setting could not be read: %v", err)
		return
	}
	if !Valid(days) {
		// A value outside the range cannot come from the panel's own write path,
		// so it was written by hand. Deleting on it would be acting on a number
		// nobody meant.
		logx.Warnf("log retention: %d day(s) is outside %d..%d, so nothing was deleted",
			days, MinDays, MaxDays)
		return
	}
	for _, table := range tables {
		sweepTable(ctx, db, table, days)
	}
}

// sweepTable deletes one table's expired rows, in batches.
func sweepTable(ctx context.Context, db *sql.DB, table logTable, days int) {
	// The table and column names are constants from the list above and never a
	// caller's string, which is why they can be pasted into the statement: an
	// identifier cannot be a placeholder.
	statement := `DELETE FROM ` + table.name +
		` WHERE ` + table.column + ` < UTC_TIMESTAMP() - INTERVAL ? DAY LIMIT ?`
	var total int64
	for range maxBatches {
		result, err := db.ExecContext(ctx, statement, days, deleteBatch) // #nosec G202 -- table is one of this package's own constants.
		if err != nil {
			logx.Errorf("log retention: %s could not be swept: %v", table.name, err)
			return
		}
		deleted, err := result.RowsAffected()
		if err != nil || deleted == 0 {
			break
		}
		total += deleted
		if deleted < deleteBatch {
			break
		}
	}
	if total > 0 {
		logx.Infof("log retention: %d row(s) older than %d day(s) removed from %s", total, days, table.name)
	}
}

// StartSweep prunes the log tables on a timer, and once at startup.
//
// The startup pass matters on its own: a panel stopped for a week comes back
// with rows nothing else would ever delete, and the operator who lowered the
// setting while it was down expects the change to have taken effect.
func StartSweep(ctx context.Context, db *sql.DB) {
	bgjob.Go("log retention sweep", nil, func() {
		Sweep(ctx, db)
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				Sweep(ctx, db)
			}
		}
	})
}
