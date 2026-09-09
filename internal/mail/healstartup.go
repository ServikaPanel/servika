// Package mail manages domain-scoped virtual mailboxes for Postfix and Dovecot.
package mail

import (
	"context"
	"database/sql"
	"log"
	"os"
)

// HealMailOnStartup checks mail service SQL-map prerequisites and repairs active Maildir roots.
func HealMailOnStartup(ctx context.Context, db *sql.DB) {
	required := []string{
		"/etc/postfix/mysql-virtual-domains.cf",
		"/etc/dovecot/dovecot-sql.conf.ext",
	}
	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			log.Printf("mail heal: %s is missing; mail service setup may not have run", path)
		}
	}

	rows, err := db.QueryContext(ctx,
		`SELECT system_user, uid_n, gid_n, maildir_root FROM mail_domains WHERE status='active'`)
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var systemUser, root string
		var uid, gid int
		if err := rows.Scan(&systemUser, &uid, &gid, &root); err != nil {
			// A dropped row is a tenant whose Maildir root is never created, so
			// delivery for that domain fails with nothing here saying why.
			log.Printf("mail heal: skipping an unreadable Maildir row: %v", err)
			continue
		}
		if _, err := os.Stat(root); err != nil {
			_ = os.MkdirAll(root, 0o750)
			_ = os.Chown(root, uid, gid)
		}
	}
	if err := rows.Err(); err != nil {
		// A tenant missing from this list keeps no Maildir root, and delivery for
		// that domain fails until the next start happens to read the whole list.
		log.Printf("mail heal: could not read the Maildir root list: %v", err)
	}
}

// EnsureInfra is kept as a boot-time extension point for mail infrastructure checks.
func EnsureInfra() {}
