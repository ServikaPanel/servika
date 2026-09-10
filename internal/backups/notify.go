package backups

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"

	"servika/internal/notifications"
)

// backupNotifyCategory tags every alert this package writes.
const backupNotifyCategory = "backup"

// notifyUploadFailed writes one critical notification when an off-site upload
// fails, so the failure reaches a signed-in operator instead of only the row's
// last_error field, which nobody watches.
//
// It is DOMAIN-scoped: the customer, the reseller who owns them, and an admin
// all see it, because the backup that did not reach off-site storage is theirs
// to worry about. A write failure is logged and never returned, or a backup
// upload would fail because the alert about it could not be written.
func notifyUploadFailed(ctx context.Context, db *sql.DB, domainID, backupID int64, reason string) {
	id := domainID
	name := backupDomainName(ctx, db, domainID)
	event := notifications.Event{
		Level:    notifications.LevelCritical,
		Category: backupNotifyCategory,
		Title:    "Off-site backup upload failed",
		Message:  fmt.Sprintf("The off-site backup upload for %s failed: %s", name, reason),
		Key:      "backup.uploadFailed",
		Params:   map[string]any{"domain": name, "reason": reason},
		DomainID: &id,
		RefType:  "backup",
		RefID:    backupID,
	}
	if err := notifications.Write(ctx, db, event); err != nil {
		// #nosec G706 -- logged values are an integer ID and error output; no raw tenant string with CR/LF reaches the log.
		log.Printf("backup: the upload-failure alert for domain %d could not be written: %v", domainID, err)
	}
}

// backupDomainName resolves a domain's name for an alert, falling back to a
// generic label so the alert is still readable when the lookup fails.
func backupDomainName(ctx context.Context, db *sql.DB, domainID int64) string {
	var name string
	if err := db.QueryRowContext(ctx, `SELECT domain_name FROM domains WHERE id=?`, domainID).Scan(&name); err != nil || name == "" {
		return "a domain"
	}
	return name
}

// notifyDumpsFailed writes one warning when a backup could not dump every
// database the domain owns.
//
// The gap used to be recorded only in the archive's OWN manifest, a file inside
// the artefact that no restore path, endpoint or screen ever reads. Every
// surface an operator or customer looks at is fed from the backups and
// backup_jobs rows, so a checksum-verified archive of the expected size (the
// tenant home dominates it) reported a green backup whose database was never
// captured, every night, until somebody tried to restore.
//
// It is DOMAIN-scoped like the upload-failure alert, and a write failure is
// logged rather than returned, or a backup would fail because the alert about it
// could not be written.
func notifyDumpsFailed(ctx context.Context, db *sql.DB, domainID, backupID int64, failed []string) {
	if len(failed) == 0 {
		return
	}
	id := domainID
	name := backupDomainName(ctx, db, domainID)
	list := strings.Join(failed, ", ")
	event := notifications.Event{
		Level:    notifications.LevelWarning,
		Category: backupNotifyCategory,
		Title:    "Backup is missing a database",
		Message: fmt.Sprintf("The backup of %s does not contain %d database(s) whose dump failed: %s",
			name, len(failed), list),
		Key:      "backup.dumpFailed",
		Params:   map[string]any{"domain": name, "count": len(failed), "databases": list},
		DomainID: &id,
		RefType:  "backup",
		RefID:    backupID,
	}
	if err := notifications.Write(ctx, db, event); err != nil {
		// #nosec G706 -- logged values are an integer ID and error output; no raw tenant string with CR/LF reaches the log.
		log.Printf("backup: the failed-dump alert for domain %d could not be written: %v", domainID, err)
	}
}

// backupNotes records the gap on the backups row itself, so the backup LIST
// carries it and not only the notification somebody may already have dismissed.
func backupNotes(base string, failed []string) string {
	if len(failed) == 0 {
		return base
	}
	return fmt.Sprintf("%s | database dump failed: %s", base, strings.Join(failed, ", "))
}
