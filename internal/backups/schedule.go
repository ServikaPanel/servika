// The backup scheduler runs in a background goroutine and checks schedules hourly.
// Each tick: SELECT due domains, run backup, prune old by retention.
package backups

import (
	"context"
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Schedule defines automatic backup timing and retention.
type Schedule struct {
	Frequency    string `json:"frequency"`      // "none" | "daily" | "weekly"
	Hour         int    `json:"hour"`           // 0-23
	Retention    int    `json:"retention"`      // keep last N
	LastBackupAt string `json:"last_backup_at"` // RFC3339 or empty
}

func validFrequency(f string) bool {
	return f == "none" || f == "daily" || f == "weekly"
}

// StartScheduler starts the hourly backup scheduler in a background goroutine.
// At the top of each hour (~ +60s offset) it scans due domains and backs them up.
func StartScheduler(db *sql.DB) {
	go func() {
		// First run: 2 minutes after the panel starts (warmup)
		time.Sleep(2 * time.Minute)
		tickOnce(db)
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			tickOnce(db)
		}
	}()
}

type dueDomain struct {
	ID         int64
	DomainName string
	SystemUser string
	Frequency  string
	Hour       int
	Retention  int
	IsDemo     int
}

// TickOnce runs one scheduler pass for tests or an operator-triggered backup.
func TickOnce(db *sql.DB) { tickOnce(db) }

// tickOnce: find domains due for this hour, back them up, apply retention.
func tickOnce(db *sql.DB) {
	now := time.Now()
	currentHour := now.Hour()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
		SELECT id, domain_name, system_user,
		       COALESCE(backup_freq,'none'), COALESCE(backup_hour,3),
		       COALESCE(backup_retention,7), is_demo,
		       UNIX_TIMESTAMP(last_backup_at)
		FROM domains
		WHERE COALESCE(backup_freq,'none') != 'none'
		  AND COALESCE(backup_hour,3) = ?
		  AND is_demo = 0`,
		currentHour)
	if err != nil {
		log.Printf("backup scheduler tick query: %v", err)
		return
	}
	defer func() { _ = rows.Close() }()

	var due []dueDomain
	for rows.Next() {
		var d dueDomain
		var lastTs sql.NullInt64
		if err := rows.Scan(&d.ID, &d.DomainName, &d.SystemUser, &d.Frequency, &d.Hour, &d.Retention, &d.IsDemo, &lastTs); err != nil {
			log.Printf("backup scheduler scan: %v", err)
			continue
		}
		// Filter: if freq=daily, 23 hours must have passed; if weekly, 6.5 days
		// (slack: to avoid missing when it lands on a day/week boundary)
		minSec := int64(23 * 3600)
		if d.Frequency == "weekly" {
			minSec = int64(6*24*3600 + 12*3600)
		}
		if lastTs.Valid && (now.Unix()-lastTs.Int64) < minSec {
			continue
		}
		due = append(due, d)
	}

	if len(due) == 0 {
		return
	}
	log.Printf("backup scheduler: %d due domain found", len(due))

	// Group the whole nightly run into one 'scheduled' job so the panel shows a single
	// row with progress instead of one unrelated record per domain.
	var jobID int64
	if res, err := db.Exec(
		`INSERT INTO backup_jobs(type, operation, status, total, started_by)
		 VALUES('scheduled','backup','running',?,'system')`, len(due)); err == nil {
		jobID, _ = res.LastInsertId()
	} else {
		log.Printf("backup scheduler: could not open job row: %v", err)
	}

	var totalBytes int64
	succeeded, failed := 0, 0
	for _, d := range due {
		if _, err := db.Exec(`UPDATE backup_jobs SET active_domain=? WHERE id=?`, d.DomainName, jobID); err != nil {
			log.Printf("backup scheduler: progress update failed: %v", err)
		}
		size, err := runOneBackup(db, d, jobID)
		if err != nil {
			failed++
			log.Printf("backup scheduler %s: %v", d.DomainName, err)
		} else {
			succeeded++
			totalBytes += size
		}
		// Retention runs whether or not the archive was written. Keeping it in
		// the success branch stopped the cleanup on exactly the domain that
		// could not be backed up, which is usually the one whose disk is full,
		// so the archives piled up at the moment there was least room for them.
		// Nothing new was written on the failure path, so this only trims the
		// existing ones down to the count the domain asked for.
		if err := pruneOld(db, d.ID, d.SystemUser, d.Retention); err != nil {
			log.Printf("backup retention %s: %v", d.DomainName, err)
		}
		if _, err := db.Exec(
			`UPDATE backup_jobs SET completed=?, succeeded=?, failed=?, size_b=? WHERE id=?`,
			succeeded+failed, succeeded, failed, totalBytes, jobID); err != nil {
			log.Printf("backup scheduler: progress update failed: %v", err)
		}
	}
	finishJob(db, jobID, succeeded, failed)
}

// runOneBackup creates a scheduled backup for one domain, tags it with the nightly
// job, and updates last_backup_at. It returns the archive size so the job can total it.
func runOneBackup(db *sql.DB, d dueDomain, jobID int64) (int64, error) {
	// Package the home directory plus EVERY domain-owned database (main + wp_* etc.)
	// under __db__/ with a manifest, exactly like a manual backup, so a scheduled
	// archive restores to the same state. buildArchive fails closed.
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	sizeBytes, file, err := backupOneDomain(ctx, db, d.ID, d.SystemUser, "scheduled",
		"Scheduled backup ("+d.Frequency+")", jobID)
	if err != nil {
		return 0, err
	}
	if _, err := db.Exec(`UPDATE domains SET last_backup_at=NOW() WHERE id=?`, d.ID); err != nil {
		log.Printf("last_backup_at could not be updated: %v", err)
	}
	log.Printf("scheduled backup %s: file=%s size_bytes=%d", d.DomainName, file, sizeBytes)
	return sizeBytes, nil
}

// pruneOld keeps the newest scheduled backups and preserves manual backups.
func pruneOld(db *sql.DB, domainID int64, systemUser string, retention int) error {
	if retention < 1 {
		retention = 1
	}
	rows, err := db.Query(
		`SELECT id, file FROM backups
		 WHERE domain_id=? AND type='scheduled'
		 ORDER BY id DESC`, domainID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	type item struct {
		ID   int64
		File string
	}
	var all []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.ID, &it.File); err != nil {
			continue
		}
		all = append(all, it)
	}
	_ = rows.Close()
	if len(all) <= retention {
		return nil
	}
	// Keep the newest N backups and delete the rest.
	old := all[retention:]
	sort.Slice(old, func(i, j int) bool { return old[i].ID < old[j].ID })
	for _, it := range old {
		path := filepath.Join(backupRoot(), systemUser, it.File)
		_ = os.Remove(path)
		_, _ = db.Exec(`DELETE FROM backups WHERE id=?`, it.ID)
	}
	log.Printf("backup retention domain=%d: %d old backups deleted (keep %d)", domainID, len(old), retention)
	return nil
}
