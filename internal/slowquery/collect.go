package slowquery

import (
	"context"
	"database/sql"
	"io"
	"log"
	"os"
	"syscall"
	"time"

	"servika/internal/config"
)

const (
	// collectInterval is how often the log is drained. Five minutes keeps the
	// screen current without turning the collector into its own load.
	collectInterval = 5 * time.Minute
	// firstPassDelay lets the rest of startup finish first. The collector is a
	// reporting feature and must not compete with provisioning heals.
	firstPassDelay = time.Minute
	// passByteCap bounds one pass. A backlog is drained over several passes
	// instead of one pass reading a multi-gigabyte file into memory.
	passByteCap = 32 << 20
	// digestCap bounds the in-memory aggregate. If the normaliser ever meets an
	// input it cannot reduce, this is what stops one pass from writing a row per
	// query; everything past it is counted under otherDigest.
	digestCap = 5000
	// otherDigest collects whatever did not fit under digestCap, so the total
	// stays true even when the detail is lost.
	otherDigest = "________________________________"
	// retentionDays bounds the table. Long enough to answer "what happened last
	// week", short enough that the table never needs its own maintenance.
	retentionDays = 14
)

// StartCollector drains the slow query log on a timer.
func StartCollector(db *sql.DB) {
	if db == nil {
		return
	}
	go func() {
		time.Sleep(firstPassDelay)
		CollectOnce(db)
		ticker := time.NewTicker(collectInterval)
		defer ticker.Stop()
		for range ticker.C {
			CollectOnce(db)
		}
	}()
}

// CollectOnce runs one pass. Exported so a test or an operator-triggered path
// can drive the same code the ticker does.
func CollectOnce(db *sql.DB) {
	// Its own deadline, shorter than the interval, so a slow pass cannot overlap
	// the next one. main hands this package a context that never cancels.
	ctx, cancel := context.WithTimeout(context.Background(), collectInterval-30*time.Second)
	defer cancel()

	enabled, err := collectionEnabled(ctx, db)
	if err != nil {
		log.Printf("slow query collector: could not read the setting: %v", err)
		return
	}
	if !enabled {
		// Nothing is opened while the feature is off, not even to measure the
		// file: off means off.
		return
	}
	if err := collectPass(ctx, db, config.MariaDBSlowLog()); err != nil {
		log.Printf("slow query collector: %v", err)
		recordCollectorError(ctx, db, err.Error())
		return
	}
	recordCollectorError(ctx, db, "")
}

func collectionEnabled(ctx context.Context, db *sql.DB) (bool, error) {
	var enabled int
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(slow_query_enabled,0) FROM panel_settings WHERE id=1`).Scan(&enabled)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return enabled == 1, nil
}

// recordCollectorError stores the last failure so a screen can say why the table
// is empty instead of showing nothing and implying the server is healthy.
func recordCollectorError(ctx context.Context, db *sql.DB, message string) {
	if len(message) > 255 {
		message = message[:255]
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE panel_settings SET slow_query_last_error=?, slow_query_collected_at=NOW() WHERE id=1`,
		message); err != nil {
		log.Printf("slow query collector: could not record its own state: %v", err)
	}
}

// bucketKey identifies one aggregated row. domain_id is deliberately absent: it
// is derived from db_user, which is globally unique in db_accounts, and a
// nullable column in the key would stop the unattributed rows from merging.
type bucketKey struct {
	digest string
	hour   time.Time
	dbUser string
}

type bucket struct {
	schema        string
	normalized    string
	calls         int64
	totalMS       int64
	maxMS         int64
	lockMS        int64
	rowsSent      int64
	rowsExamined  int64
	fullScanCalls int64
}

func collectPass(ctx context.Context, db *sql.DB, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		// No log file means MariaDB has not written one yet, which is the normal
		// state right after the setting is turned on.
		return nil
	}
	size := info.Size()

	var offset, previousSize int64
	err = db.QueryRowContext(ctx,
		"SELECT `offset`, `size` FROM slow_query_cursor WHERE id = 1").Scan(&offset, &previousSize)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	start := offset
	// A file smaller than the cursor, or smaller than it was, is a new file:
	// logrotate replaced it and the old offset points into the middle of
	// something else.
	if size < offset || size < previousSize {
		start = 0
	}
	if start >= size {
		return nil
	}

	data, err := readFrom(path, start, passByteCap)
	if err != nil {
		return err
	}

	records, consumed := ScanRecords(data)
	if consumed == 0 {
		// The scan found no boundary it could commit. That is normal while a
		// single record is still being written, but a file that has grown far
		// past the cursor with no boundary is a damaged region, and standing
		// still on it would stop collection for good. Skip the window this pass
		// read so the next one starts past the damage.
		if int64(len(data)) < passByteCap {
			return nil
		}
		log.Printf("slow query collector: no record boundary in %d bytes at offset %d, skipping the window",
			len(data), start)
		return storeBuckets(ctx, db, nil, start+int64(len(data)), size)
	}

	buckets := aggregate(records)
	return storeBuckets(ctx, db, buckets, start+int64(consumed), size)
}

// readFrom reads at most limit bytes from offset.
//
// The open is O_NOFOLLOW and O_NONBLOCK and the regular-file check is made on
// the DESCRIPTOR, not on a separate stat of the path. mysqld is not a tenant
// process, but it is a service account executing tenant SQL, and the check costs
// nothing: without O_NOFOLLOW root follows a planted link out of the directory,
// and without O_NONBLOCK a named pipe blocks the open before any check can run.
func readFrom(path string, offset, limit int64) ([]byte, error) {
	// #nosec G304 -- fixed system path from the configuration, never tenant input.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, os.ErrInvalid
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(file, limit))
}

// aggregate folds records into one row per shape, hour and account.
func aggregate(records []Record) map[bucketKey]*bucket {
	buckets := make(map[bucketKey]*bucket)
	var previous time.Time
	for _, record := range records {
		entry, ok := Parse(record, previous)
		if !ok {
			continue
		}
		previous = entry.At
		at := entry.At
		if at.IsZero() {
			at = time.Now()
		}

		normalized, digest := Normalize(entry.SQL)
		key := bucketKey{
			digest: digest,
			hour:   at.Truncate(time.Hour),
			dbUser: entry.DBUser,
		}
		if _, seen := buckets[key]; !seen && len(buckets) >= digestCap {
			key.digest = otherDigest
			normalized = "(more shapes than one pass can hold)"
		}

		row := buckets[key]
		if row == nil {
			row = &bucket{schema: entry.Schema, normalized: normalized}
			buckets[key] = row
		}
		row.calls++
		row.totalMS += entry.QueryMS
		row.lockMS += entry.LockMS
		row.rowsSent += entry.RowsSent
		row.rowsExamined += entry.RowsExamined
		if entry.QueryMS > row.maxMS {
			row.maxMS = entry.QueryMS
		}
		if entry.FullScan {
			row.fullScanCalls++
		}
	}
	return buckets
}

// storeBuckets writes the rows and the cursor in ONE transaction.
//
// Committing the rows first and the cursor second would re-read and re-store
// everything the pass covered whenever the second write failed, which on a busy
// server means the totals climb without any query having run.
func storeBuckets(ctx context.Context, db *sql.DB, buckets map[bucketKey]*bucket, consumed, size int64) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for key, row := range buckets {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO slow_query_stats"+
				" (domain_id, db_user, schema_name, digest, bucket_hour, normalized_sql,"+
				"  calls, total_time_ms, max_time_ms, lock_time_ms, rows_sent, rows_examined, full_scan_calls)"+
				" VALUES ((SELECT domain_id FROM db_accounts WHERE db_user=? LIMIT 1),"+
				"         ?,?,?,?,?,?,?,?,?,?,?,?)"+
				" ON DUPLICATE KEY UPDATE"+
				"  calls=calls+VALUES(calls),"+
				"  total_time_ms=total_time_ms+VALUES(total_time_ms),"+
				"  max_time_ms=GREATEST(max_time_ms, VALUES(max_time_ms)),"+
				"  lock_time_ms=lock_time_ms+VALUES(lock_time_ms),"+
				"  rows_sent=rows_sent+VALUES(rows_sent),"+
				"  rows_examined=rows_examined+VALUES(rows_examined),"+
				"  full_scan_calls=full_scan_calls+VALUES(full_scan_calls)",
			key.dbUser, key.dbUser, row.schema, key.digest, key.hour, row.normalized,
			row.calls, row.totalMS, row.maxMS, row.lockMS, row.rowsSent, row.rowsExamined,
			row.fullScanCalls); err != nil {
			return err
		}
	}

	if _, err := tx.ExecContext(ctx,
		"INSERT INTO slow_query_cursor(id, `offset`, `size`) VALUES(1,?,?)\n"+
			" ON DUPLICATE KEY UPDATE `offset`=VALUES(`offset`), `size`=VALUES(`size`)",
		consumed, size); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM slow_query_stats WHERE bucket_hour < NOW() - INTERVAL ? DAY`,
		retentionDays); err != nil {
		return err
	}
	return tx.Commit()
}
