package mail

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"servika/internal/dns"
	"servika/internal/files"
)

// requiredMailServices must be running before mail can be enabled for a domain.
//
// Dovecot is on the list because it is on the DELIVERY path, not merely serving
// IMAP: assets/mail/postfix/main.cf.append sets
// `virtual_transport = lmtp:unix:private/dovecot-lmtp`, so with Dovecot down
// Postfix has nowhere to hand a message.
//
// Rspamd and OpenDKIM are deliberately absent. The same file sets
// `milter_default_action = accept`, so Postfix still accepts a message when the
// milters are unreachable; without them mail flows, it just loses spam filtering
// and DKIM signing. Requiring them would refuse a server that works.
var requiredMailServices = []string{"postfix", "dovecot"}

// mailServiceActive is a variable because a check that shells out to systemd
// would answer differently on every machine a unit test runs on.
var mailServiceActive = func(ctx context.Context, unit string) bool {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); the unit comes from requiredMailServices, never from a request.
	output, err := exec.CommandContext(ctx, "systemctl", "is-active", unit).Output()
	return err == nil && strings.TrimSpace(string(output)) == "active"
}

// MissingMailServices names the mail services that are not running, in the order
// they are required. An empty result means the stack is ready.
//
// EnableDomain writes a database row, a Maildir and the MX, SPF, DKIM and DMARC
// records, but it installs nothing and starts nothing. An administrator who
// turned the stack off (a fair choice once the last mail customer leaves) would
// otherwise see the panel accept the request, publish MX to the world, and
// report success for a service that never runs. The first sign of that is
// messages disappearing.
func MissingMailServices(ctx context.Context) []string {
	var missing []string
	for _, unit := range requiredMailServices {
		if !mailServiceActive(ctx, unit) {
			missing = append(missing, unit)
		}
	}
	return missing
}

// EnableDomain enables mail for a domain and prepares its Maildir root.
func EnableDomain(ctx context.Context, db *sql.DB, domainID int64) error {
	var domainName, systemUser, ipv4 string
	if err := db.QueryRowContext(ctx,
		`SELECT domain_name, system_user, COALESCE(ipv4,'') FROM domains WHERE id=?`, domainID).
		Scan(&domainName, &systemUser, &ipv4); err != nil {
		return fmt.Errorf("read domain: %w", err)
	}
	uid, gid, err := uidGid(systemUser)
	if err != nil {
		return fmt.Errorf("lookup system user: %w", err)
	}
	maildirRoot := filepath.Join("/home", systemUser, "mail")
	if err := os.MkdirAll(maildirRoot, 0o750); err != nil {
		return fmt.Errorf("create Maildir root: %w", err)
	}
	_ = os.Chown(maildirRoot, uid, gid)

	if _, err := db.ExecContext(ctx,
		`INSERT INTO mail_domains(domain_id, domain_name, system_user, uid_n, gid_n, maildir_root)
		 VALUES(?,?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE system_user=VALUES(system_user), uid_n=VALUES(uid_n),
		   gid_n=VALUES(gid_n), maildir_root=VALUES(maildir_root), status='active'`,
		domainID, domainName, systemUser, uid, gid, maildirRoot); err != nil {
		return fmt.Errorf("write mail domain: %w", err)
	}

	if _, err := dns.SeedDefaults(ctx, db, domainID, domainName, ipv4); err != nil {
		log.Printf("mail: dns seed %s: %v", domainName, err)
	}
	if err := dns.WriteZone(ctx, db, domainID); err != nil {
		log.Printf("mail: write DNS zone %s: %v", domainName, err)
	}
	return nil
}

// DisableDomain soft-disables mail for a domain without deleting mailbox rows or Maildir data.
func DisableDomain(ctx context.Context, db *sql.DB, domainID int64) error {
	_, err := db.ExecContext(ctx, `UPDATE mail_domains SET status='suspended' WHERE domain_id=?`, domainID)
	if err != nil {
		return err
	}
	// mail_domains.status is an input to the cached passdb answer, so every
	// mailbox of this domain keeps authenticating until the cache is dropped.
	FlushAllAuthCache(ctx)
	return nil
}

// removeMailFiles deletes the domain's Maildir root. It is a variable so a test
// can exercise both the success and the failure path: the real implementation is
// Linux-only (safeio_stub.go returns an error on macOS), which would otherwise
// make every local run take the failure branch.
var removeMailFiles = func(systemUser string) error {
	return files.RemoveAllBeneath(filepath.Join("/home", systemUser), "mail")
}

// nonCascadingMailTables are the per-domain mail tables that hang off domains(id)
// rather than mail_domains(id), so deleting the mail domain does NOT take them
// with it. Verified against the migrations rather than assumed: mailboxes cascade
// from mail_domains, and mail_autoresponders and mail_filters cascade from
// mailboxes, but these five do not cascade from anything being deleted here.
//
// Missing one would leave the rows behind and hand them straight back the next
// time the domain enabled mail: old forwarders, old spam thresholds, and
// single-use webmail sign-on tokens for mailboxes that no longer exist.
var nonCascadingMailTables = []string{
	"mail_aliases",
	"mail_send_log",
	"mail_spam_settings",
	"mail_delivery_log",
	"webmail_tokens",
}

// PurgeDomain is the destructive opposite of EnableDomain: it removes mail
// hosting for a domain outright. Mailboxes, forwarders, filters, autoresponders
// and the stored messages on disk are all deleted, and none of it comes back.
// DisableDomain is the reversible one; the two must not be confused.
//
// The DNS records EnableDomain seeded (MX, SPF, DKIM, DMARC) are deliberately
// left in place. The customer may have pointed MX at an outside provider, and
// those records are managed from the DNS page; deleting them silently would be
// worse than leaving them.
//
// ORDER MATTERS, database first and disk second. Losing the disk step leaves
// orphaned files behind a service that is already gone, which is the harmless
// direction. The other way round, Dovecot would be pointed at Maildirs that no
// longer exist.
//
// diskFailed reports that the database is clean but some files survived. The
// caller has to surface that: the service really is gone, yet the space is not.
func PurgeDomain(ctx context.Context, db *sql.DB, domainID int64, systemUser string) (diskFailed bool, err error) {
	transaction, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = transaction.Rollback() }()

	for _, table := range nonCascadingMailTables {
		// #nosec G202 -- table comes from the package-level allowlist above, never from a request.
		if _, err := transaction.ExecContext(ctx, `DELETE FROM `+table+` WHERE domain_id=?`, domainID); err != nil {
			return false, fmt.Errorf("delete %s: %w", table, err)
		}
	}
	// Last, because this is what cascades: mailboxes go with it, and their
	// autoresponders and filters go with them.
	if _, err := transaction.ExecContext(ctx,
		`DELETE FROM mail_domains WHERE domain_id=?`, domainID); err != nil {
		return false, fmt.Errorf("delete mail_domains: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	// The rows are gone, but Dovecot answers a login from its cached passdb
	// result, so every purged mailbox keeps authenticating until it is dropped.
	FlushAllAuthCache(ctx)

	// /home/<system_user>/mail holds every mailbox's Maildir and the .dovecot.sieve
	// compiled into it, so one removal covers both, plus any Maildir left behind by
	// a mailbox deleted earlier.
	//
	// Through files.RemoveAllBeneath, never os.RemoveAll: the panel runs as root
	// inside a tenant's home, and a tenant who replaced "mail" with a symlink could
	// otherwise redirect the deletion anywhere on the host.
	if err := removeMailFiles(systemUser); err != nil && !errors.Is(err, os.ErrNotExist) {
		// #nosec G706 -- logged values are integer IDs, validated identifiers (^c_[A-Za-z0-9_]+$), template-derived names, or error/command output; no raw tenant string with CR/LF reaches the log.
		log.Printf("purge mail domain=%d: mail files not removed: %v", domainID, err)
		return true, nil
	}
	return false, nil
}

// CleanupDomain is a domain-deletion hook for future non-cascading mail side effects.
func CleanupDomain(_ *sql.DB, _ int64, _ string) {}

func uidGid(name string) (int, int, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}
