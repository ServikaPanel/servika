package mail

import (
	"context"
	"database/sql"
	"os/exec"
	"strings"
	"time"

	"servika/internal/logx"
)

// Dovecot caches the SQL passdb answer, the password hash included, and serves a
// later login from that cache (`auth_cache_size` / `auth_cache_ttl` in
// assets/mail/dovecot/10-servika-mail.conf.tmpl). The cached answer is derived
// from mailboxes.password_hash, mailboxes.status AND mail_domains.status, all
// three of which this panel writes.
//
// So a row change alone does not revoke anything: for up to the cache TTL the
// OLD password still authenticates over IMAP and over Postfix's Dovecot SASL
// listener, which is exactly the window a rotated password exists to close. The
// cache itself is not dropped instead, because Roundcube opens a new IMAP
// session per HTTP request and the cache is what stops a passdb query per click.

// authCacheTimeout bounds one doveadm call. It runs on the request path, so a
// hung daemon must not hold the handler.
const authCacheTimeout = 10 * time.Second

// authCommand runs a mail-stack tool. It is a variable so tests can observe the
// commands without a Dovecot installation.
var authCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- a fixed tool name and a validated address; no shell.
}

// FlushAuthCache drops the cached passdb answer for one address.
//
// A failure is LOGGED and never returned: the row is already written, so failing
// the caller would report a revocation that did happen as not done. The message
// names what the failure costs, because until the entry expires the previous
// password still opens the mailbox.
func FlushAuthCache(ctx context.Context, email string) {
	email = strings.TrimSpace(email)
	if email == "" || strings.ContainsAny(email, " \t\r\n\x00") {
		return
	}
	runAuthCacheFlush(ctx, []string{"auth", "cache", "flush", "-u", email},
		"the previous password still opens "+email+" until the Dovecot auth cache entry expires")
}

// FlushAllAuthCache drops every cached passdb answer.
//
// It is what a DOMAIN-level change uses: doveadm takes a user, not a domain, and
// enumerating a domain's mailboxes to flush them one by one would miss exactly
// the rows a purge has already deleted.
func FlushAllAuthCache(ctx context.Context) {
	runAuthCacheFlush(ctx, []string{"auth", "cache", "flush"},
		"previous mail passwords still authenticate until the Dovecot auth cache expires")
}

func runAuthCacheFlush(ctx context.Context, args []string, cost string) {
	if _, err := exec.LookPath("doveadm"); err != nil {
		return // Dovecot is not installed on this host; there is no cache to flush.
	}
	flushCtx, cancel := context.WithTimeout(ctx, authCacheTimeout)
	defer cancel()
	if out, err := authCommand(flushCtx, "doveadm", args...); err != nil {
		// #nosec G706 -- the operands are doveadm's own output and a message this package composed.
		logx.Errorf("mail: could not flush the Dovecot auth cache (%s): %s", cost, strings.TrimSpace(string(out)))
	}
}

// flushMailboxAuthCache drops the cached answer for one mailbox, looking its
// address up itself so a caller that never read it needs no extra branch.
func (h *Handlers) flushMailboxAuthCache(ctx context.Context, domainID, mailboxID int64) {
	var email string
	if err := h.DB.QueryRowContext(ctx,
		`SELECT email FROM mailboxes WHERE id=? AND domain_id=?`, mailboxID, domainID).Scan(&email); err != nil {
		if err == sql.ErrNoRows {
			return // The row is gone; its caller flushed by address instead.
		}
		// #nosec G706 -- logged values are integer IDs and driver error text.
		logx.Errorf("mail: could not read mailbox %d of domain %d to flush its auth cache: %v", mailboxID, domainID, err)
		return
	}
	FlushAuthCache(ctx, email)
}
