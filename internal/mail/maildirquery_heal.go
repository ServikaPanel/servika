package mail

import (
	"context"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// SQL map paths written by servika-mail-setup. Package variables so a test can
// point the repair at a temporary directory, for the reason given on
// dovecotAuthConf: the script writes these literally, and a second source of
// truth could disagree with it.
var (
	dovecotSQLConf     = "/etc/dovecot/dovecot-sql.conf.ext"
	postfixMailboxMap  = "/etc/postfix/mysql-virtual-mailboxes.cf"
	maildirQueryTarget = []*string{&dovecotSQLConf, &postfixMailboxMap}
)

// oldMaildirConcat matches a path REBUILT from the system user and the local
// part, in either map. That form is the defect: uniqueness on mailboxes is
// (domain_id, local_part) while the rebuilt path is per system user, and an
// addon domain carries its parent's system_user, so two mailboxes with two
// passwords resolved to one directory.
//
// Three forms are matched, and they are told apart by what surrounds the same
// middle: Dovecot's home ('/home/' first), Dovecot's mail location
// ('maildir:/home/' first) and Postfix's map, which starts at md.system_user
// because its value is relative to virtual_mailbox_base and ends with the
// trailing slash a Maildir path carries.
var oldMaildirConcat = regexp.MustCompile(
	`CONCAT\(\s*(?:'(maildir:)?/home/'\s*,\s*)?md\.system_user\s*,\s*'/mail/'\s*,\s*m\.local_part\s*(,\s*'/'\s*)?\)`)

// rewriteMaildirQuery replaces every rebuilt path with a read of m.maildir, the
// column the panel writes. It reports whether it changed anything, so a file
// that is already current is left byte-for-byte alone.
func rewriteMaildirQuery(text string) (string, bool) {
	out := oldMaildirConcat.ReplaceAllStringFunc(text, func(match string) string {
		groups := oldMaildirConcat.FindStringSubmatch(match)
		switch {
		case groups[1] != "":
			return "CONCAT('maildir:', m.maildir)"
		case groups[2] != "":
			// Postfix's map is relative to virtual_mailbox_base (/home), so the
			// leading '/home/' is dropped; the trailing slash is already in the
			// column.
			return "SUBSTRING(m.maildir, 7)"
		default:
			return "TRIM(TRAILING '/' FROM m.maildir)"
		}
	})
	return out, out != text
}

// HealMaildirQuery points an existing host's SQL maps at mailboxes.maildir.
//
// It is not cosmetic. The templates only reach a NEW installation, so without
// this an upgraded host keeps rebuilding the path from the local part while the
// panel writes the new per-domain path into the column: a mailbox created after
// the upgrade would be unreachable, and two mailboxes created before it would go
// on sharing one store.
//
// GUARD: it acts only where Servika's own mail drop-in is present, so a Dovecot
// somebody installed for another purpose is left alone.
func HealMaildirQuery(ctx context.Context) {
	if _, err := os.Stat(dovecotServikaConf); err != nil {
		return // the Servika mail setup never ran here; leave this host alone
	}
	dovecotChanged, postfixChanged := false, false
	for _, path := range maildirQueryTarget {
		changed, err := healOneMaildirQuery(*path)
		if err != nil {
			log.Printf("maildir query heal: %s not updated: %v", *path, err)
			continue
		}
		if !changed {
			continue
		}
		if path == &postfixMailboxMap {
			postfixChanged = true
		} else {
			dovecotChanged = true
		}
	}
	if !dovecotChanged && !postfixChanged {
		return
	}
	reloadCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if dovecotChanged {
		reloadMailService(reloadCtx, "dovecot")
	}
	if postfixChanged {
		reloadMailService(reloadCtx, "postfix")
	}
	log.Printf("maildir query heal applied; the mail SQL maps now read mailboxes.maildir")
}

// healOneMaildirQuery rewrites one map in place, preserving its mode and owner:
// the Dovecot map holds the read-only database password and is installed
// root:dovecot 0640, which O_CREATE would not reproduce.
func healOneMaildirQuery(path string) (bool, error) {
	// #nosec G304 -- path is a fixed system config path from the package variables above, never request data.
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // this map was never installed here
		}
		return false, err
	}
	patched, changed := rewriteMaildirQuery(string(content))
	if !changed {
		return false, nil
	}
	// Mode 0 because O_CREATE is deliberately absent: the file was read above, so
	// it exists, and its own mode and ownership are preserved.
	// #nosec G304 -- path is a fixed system config path from the package variables above, never request data.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return false, err
	}
	if _, err := file.WriteString(patched); err != nil {
		_ = file.Close()
		return false, err
	}
	return true, file.Close()
}

// reloadMailService reloads one unit, falling back to a restart, in the same
// shape HealDovecotAuth uses.
func reloadMailService(ctx context.Context, unit string) {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); unit is a literal from the caller.
	if _, err := exec.CommandContext(ctx, "systemctl", "reload", unit).CombinedOutput(); err == nil {
		return
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); unit is a literal from the caller.
	out, err := exec.CommandContext(ctx, "systemctl", "restart", unit).CombinedOutput()
	if err != nil {
		// #nosec G706 -- the operand is systemctl output, not client-controlled input.
		log.Printf("maildir query heal: could not reload %s: %v: %s", unit, err, strings.TrimSpace(string(out)))
	}
}
