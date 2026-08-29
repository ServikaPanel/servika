package backups

import (
	"context"
	"database/sql"
	"fmt"
	"log"

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
