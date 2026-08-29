// Backup integrity: catch a stored archive that rotted on disk or disappeared.
//
// A backup's sha256 is computed when it is written. A periodic scan re-computes
// it for the newest archive per domain and compares: a mismatch is silent
// bit-rot (a flipped bit), an unreadable file is a lost backup, and a missing
// file whose copy is off-site by design is neither. None of this was detectable
// before, so a corrupt backup was found only when a restore failed.
package backups

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"servika/internal/notifications"
)

// fileSHA256 streams a file's SHA-256. The archive lives in a root-owned 0700
// directory a tenant cannot write, but the name comes from a database row, so it
// is opened O_NOFOLLOW with IsRegular asserted on the descriptor as defence in
// depth, the same rule the panel follows for any root-run read outside a home.
func fileSHA256(path string) (string, error) {
	// #nosec G304 G703 -- path is BackupRoot/<validSystemUser-checked user>/<db file column>, a root-owned server path, not tenant input.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// classifyIntegrity turns a stored checksum, the current checksum and the read
// outcome into a verification verdict and, when it is a fault, the alert key.
//
// A missing file whose copy is off-site by design is 'remote', NOT 'corrupt':
// delete-local leaves the backup only on the remote server, and marking that a
// fault would raise a critical alert for every healthy off-site backup, which is
// alarm blindness that buries a real bit-rot in the same text.
func classifyIntegrity(stored, current string, readErr error, offsite bool) (verification, alertKey string) {
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) && offsite {
			return "remote", ""
		}
		return "corrupt", "corruptMissing"
	}
	if current != stored {
		return "corrupt", "bitRot"
	}
	return "ok", ""
}

// backupMovedOffSite reports whether a backup's local copy was deleted after a
// verified system-wide off-site upload, so a missing local file is expected
// rather than a fault. It requires the off-site destination to be enabled AND the
// row to carry the moved-off-site note.
func backupMovedOffSite(db *sql.DB, file string) bool {
	s := readBackupSettings(context.Background(), db)
	if !s.RemoteEnabled || strings.TrimSpace(s.RemoteHost) == "" {
		return false
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM backups WHERE file=? AND notes LIKE ?`,
		file, "%"+movedOffSiteMark+"%").Scan(&n)
	return n > 0
}

var (
	integrityMu       sync.Mutex
	lastIntegrityScan time.Time
)

// integrityScanDue rate-limits the scan to once per 20 hours: re-hashing every
// domain's newest archive (each up to gigabytes) is heavy disk I/O, so it runs
// daily rather than on every hourly tick. The window is in memory, so a restart
// runs one scan early, which is harmless.
func integrityScanDue() bool {
	integrityMu.Lock()
	defer integrityMu.Unlock()
	if !lastIntegrityScan.IsZero() && time.Since(lastIntegrityScan) < 20*time.Hour {
		return false
	}
	lastIntegrityScan = time.Now()
	return true
}

// verifyBackupIntegrity re-hashes the newest archive per domain and records the
// verdict on the row. Only a TRANSITION into 'corrupt' raises an alert, so a
// backup that stays corrupt across scans is not re-reported every day.
func verifyBackupIntegrity(db *sql.DB) {
	rows, err := db.Query(`
		SELECT b.id, b.domain_id, d.system_user, b.file, b.sha256
		FROM backups b
		JOIN domains d ON d.id = b.domain_id
		JOIN (SELECT domain_id, MAX(id) AS mid FROM backups WHERE sha256 <> '' GROUP BY domain_id) x
		  ON x.mid = b.id`)
	if err != nil {
		log.Printf("backup integrity scan query: %v", err)
		return
	}
	type record struct {
		id, domainID int64
		user, file   string
		storedSHA    string
	}
	var list []record
	for rows.Next() {
		var k record
		if rows.Scan(&k.id, &k.domainID, &k.user, &k.file, &k.storedSHA) == nil {
			list = append(list, k)
		}
	}
	_ = rows.Close()

	corrupt, remote := 0, 0
	for _, k := range list {
		if !validSystemUser(k.user) {
			continue
		}
		path := filepath.Join(backupRoot(), k.user, k.file)
		current, rerr := fileSHA256(path)
		offsite := errors.Is(rerr, os.ErrNotExist) && backupMovedOffSite(db, k.file)
		verification, alertKey := classifyIntegrity(k.storedSHA, current, rerr, offsite)
		switch verification {
		case "remote":
			remote++
			// Do not overwrite a corrupt verdict with 'remote'.
			_, _ = db.Exec(`UPDATE backups SET verification='remote' WHERE id=? AND verification<>'corrupt'`, k.id)
		case "corrupt":
			corrupt++
			res, _ := db.Exec(`UPDATE backups SET verification='corrupt' WHERE id=? AND verification<>'corrupt'`, k.id)
			if res != nil {
				if n, _ := res.RowsAffected(); n > 0 {
					notifyIntegrity(db, k.domainID, k.id, k.file, alertKey)
				}
			}
		default:
			_, _ = db.Exec(`UPDATE backups SET verification='ok' WHERE id=?`, k.id)
		}
	}
	if corrupt > 0 {
		log.Printf("backup integrity scan: %d/%d newest backups CORRUPT (%d off-site, not scanned)", corrupt, len(list), remote)
	} else {
		log.Printf("backup integrity scan: %d clean (%d off-site, not scanned)", len(list)-remote, remote)
	}
}

// notifyIntegrity writes one domain-scoped critical alert when a backup turns
// corrupt or is lost, so the failure reaches a signed-in operator instead of only
// a database column.
func notifyIntegrity(db *sql.DB, domainID, backupID int64, file, alertKey string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	name := backupDomainName(ctx, db, domainID)
	title := "Backup lost or unreadable"
	message := fmt.Sprintf("The newest backup for %s could not be read (%s); it may be invalid for recovery.", name, file)
	if alertKey == "bitRot" {
		title = "Backup corrupted (bit-rot)"
		message = fmt.Sprintf("The newest backup for %s (%s) no longer matches its checksum from when it was written; restoring from it may fail.", name, file)
	}
	event := notifications.Event{
		Level:    notifications.LevelCritical,
		Category: backupNotifyCategory,
		Title:    title,
		Message:  message,
		Key:      "backup." + alertKey,
		Params:   map[string]any{"domain": name, "file": file},
		DomainID: &domainID,
		RefType:  "backup",
		RefID:    backupID,
	}
	if err := notifications.Write(ctx, db, event); err != nil {
		// #nosec G706 -- logged values are integer IDs and error output; no raw tenant string with CR/LF reaches the log.
		log.Printf("backup integrity: alert for domain %d could not be written: %v", domainID, err)
	}
}
