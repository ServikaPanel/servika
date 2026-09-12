package mail

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"servika/internal/logx"
)

// Dovecot configuration paths. They are package variables so tests can point the
// repair at a temporary directory. They are deliberately not config.* overrides:
// servika-mail-setup writes these two paths literally, and a second source of
// truth could disagree with the script that installs the drop-in.
var (
	dovecotAuthConf    = "/etc/dovecot/conf.d/10-auth.conf"
	dovecotServikaConf = "/etc/dovecot/conf.d/10-servika-mail.conf"
)

// pamIncludePattern matches the ACTIVE stock include that registers the PAM
// passdb. A line that is already commented out (`#!include`) does not match,
// which is what makes the repair idempotent.
//
// The trailing class is `[ \t]*` rather than `\s*`: in multiline mode `\s` also
// matches newlines, so a greedy `\s*$` would swallow the blank lines that follow
// the include and delete them from the operator's file.
var pamIncludePattern = regexp.MustCompile(`(?m)^!include auth-system\.conf\.ext[ \t]*$`)

const pamIncludeReplacement = "#!include auth-system.conf.ext  # Servika: mailboxes are virtual (SQL passdb); " +
	"PAM delayed every login and exposed system accounts over IMAP"

// authCacheBlock is appended to the Servika drop-in when it predates the setting.
const authCacheBlock = `
# --- Servika: authentication cache ---
# Roundcube opens a NEW IMAP session on every HTTP request, so without a cache
# every request repeats the passdb query.
auth_cache_size = 10M
auth_cache_ttl = 1 hours
auth_cache_negative_ttl = 1 mins
`

// HealDovecotAuth disables the stock PAM passdb that slows virtual mailbox
// logins down and exposes system accounts to IMAP, and turns the authentication
// cache on.
//
// Dovecot loads conf.d ALPHABETICALLY, so the stock 10-auth.conf is read before
// 10-servika-mail.conf and registers `passdb { driver = pam }` first through
// `!include auth-system.conf.ext`. Passdbs are tried in order, so every virtual
// mailbox login queries PAM first; the account does not exist on the system, so
// pam_unix applies its failure delay and the login takes seconds. Roundcube
// opens a new IMAP session per HTTP request, which means the delay is paid on
// every click.
//
// It is also a security fix: while PAM is active, an IMAP client can guess
// passwords for system accounts, root included. Every mailbox here is virtual
// and authenticated against SQL, so PAM has no function at all.
//
// It runs at panel startup rather than from servika-update, for the reason
// documented on HealRoundcubeSMTP: the updater replaces itself, so a repair
// added there takes effect one update late.
//
// GUARD: it only acts when Servika's own drop-in is present. Without that check
// the panel would silently break a Dovecot someone installed for a different
// purpose, namely giving system users IMAP.
func HealDovecotAuth(ctx context.Context) {
	if _, err := os.Stat(dovecotServikaConf); err != nil {
		return // the Servika mail setup never ran here; leave this host alone
	}

	changed := disableStockPAM()
	if appendAuthCache() {
		changed = true
	}
	if !changed {
		return
	}

	reloadCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	if _, err := exec.CommandContext(reloadCtx, "systemctl", "reload", "dovecot").CombinedOutput(); err != nil {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		out, restartErr := exec.CommandContext(reloadCtx, "systemctl", "restart", "dovecot").CombinedOutput()
		if restartErr != nil {
			// #nosec G706 -- the operand is systemctl output, not client-controlled input.
			logx.Errorf("dovecot auth heal: could not reload dovecot: %v: %s", restartErr, strings.TrimSpace(string(out)))
			return
		}
	}
	logx.Infof("dovecot auth heal applied; the PAM delay on virtual mailbox logins is gone")
}

// disableStockPAM comments the stock PAM include out. It reports whether it
// changed the file.
func disableStockPAM() bool {
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	content, err := os.ReadFile(dovecotAuthConf)
	if err != nil {
		return false // no stock file, so no stock PAM passdb
	}
	if !pamIncludePattern.Match(content) {
		return false // already commented out
	}
	patched := pamIncludePattern.ReplaceAll(content, []byte(pamIncludeReplacement))

	// The mode is 0 because O_CREATE is deliberately absent: the file was read
	// above, so it exists, and its own mode and ownership are preserved.
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file-manager paths use safeio (openat2) instead.
	file, err := os.OpenFile(dovecotAuthConf, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		logx.Errorf("dovecot auth heal: could not open %s: %v", dovecotAuthConf, err)
		return false
	}
	if _, err := file.Write(patched); err != nil {
		_ = file.Close()
		logx.Errorf("dovecot auth heal: could not write %s: %v", dovecotAuthConf, err)
		return false
	}
	if err := file.Close(); err != nil {
		logx.Errorf("dovecot auth heal: could not close %s: %v", dovecotAuthConf, err)
		return false
	}
	return true
}

// appendAuthCache adds the authentication cache settings to the Servika drop-in
// on hosts installed before the template carried them. It reports whether it
// changed the file.
func appendAuthCache() bool {
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	content, err := os.ReadFile(dovecotServikaConf)
	if err != nil {
		return false
	}
	if strings.Contains(string(content), "auth_cache_size") {
		return false // written from the current template, or already repaired
	}

	// Mode 0 for the same reason as above: no O_CREATE, so the file's own
	// permissions stay in place.
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file-manager paths use safeio (openat2) instead.
	file, err := os.OpenFile(dovecotServikaConf, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		logx.Errorf("dovecot auth heal: could not open %s: %v", dovecotServikaConf, err)
		return false
	}
	// Keep the appended block off the end of an unterminated last line, which
	// would otherwise merge the two settings into one unparsable line.
	prefix := ""
	if n := len(content); n > 0 && content[n-1] != '\n' {
		prefix = "\n"
	}
	if _, err := file.WriteString(prefix + authCacheBlock); err != nil {
		_ = file.Close()
		logx.Errorf("dovecot auth heal: could not append the auth cache: %v", err)
		return false
	}
	if err := file.Close(); err != nil {
		logx.Errorf("dovecot auth heal: could not close %s: %v", dovecotServikaConf, err)
		return false
	}
	return true
}
