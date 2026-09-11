package mail

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// Dovecot master user.
//
// The panel stores only a SHA512-CRYPT hash of a mailbox password, so it cannot
// replay a customer's password to open their webmail. Dovecot's master user is
// the mechanism for exactly this: one credential that may authenticate as any
// mailbox, used with a login of the form "mailbox@domain*master".
//
// It is a deliberate authentication bypass and is treated as one. The password
// lives only in the panel's own environment file, the passwd-file is 0600 and
// root-owned, the master passdb is written so it does NOT chain to the user's own
// passdb (chaining would defeat the point but is worth stating, since the
// difference is one directive), and nothing outside the internal redeem endpoint
// ever sees the credential.

const (
	masterUserName    = "servika-webmail"
	masterPasswdFile  = "/etc/dovecot/servika-master-users" // #nosec G101 -- filesystem path, not a credential; the file it names is written 0600 root-owned
	masterConfPath    = "/etc/dovecot/conf.d/25-servika-master.conf"
	masterPassEnvName = "SERVIKA_MAIL_MASTER_PASS" // #nosec G101 -- the name of an environment variable, not a credential
	// masterSeparator is what joins the mailbox and the master user in a login.
	// It has to match Dovecot's auth_master_user_separator and Roundcube's login
	// string, so it is defined once here.
	masterSeparator = "*"
)

// MasterPassword returns the configured master password, or empty when the
// feature is not set up on this host.
func MasterPassword() string {
	return strings.TrimSpace(os.Getenv(masterPassEnvName))
}

// MasterLogin builds the IMAP username Roundcube authenticates with.
func MasterLogin(email string) string {
	return email + masterSeparator + masterUserName
}

// masterConf is the Dovecot drop-in.
//
// `pass` is deliberately absent. With `pass = yes` Dovecot would consult the
// mailbox's own passdb after the master password matched, which would require
// the customer's password as well and make the whole mechanism pointless. That
// is also why this file is the only place the behaviour is decided.
const masterConf = `# Managed by Servika. DO NOT EDIT.
# Master user for panel-initiated webmail sessions. The login form is
# "mailbox@domain` + masterSeparator + masterUserName + `" with the master password.
auth_master_user_separator = ` + masterSeparator + `

passdb {
  driver = passwd-file
  args = ` + masterPasswdFile + `
  master = yes
}
`

// masterPasswdTarget and masterConfTarget are the two files writeMasterUser
// installs. They are variables so a test can point the write at a temporary
// directory; the constants stay the source of truth, because masterConf names
// the password file inside its own text.
var (
	masterPasswdTarget = masterPasswdFile
	masterConfTarget   = masterConfPath
)

// chownFile hands a file to an owner. It is a variable because only root may give
// a file to uid 0, and a test does not run as root.
var chownFile = os.Chown

// HealMasterUser writes the master passdb and its password file when a master
// password is configured, and removes both when it is not.
//
// Removal matters as much as creation: an operator who clears the environment
// variable has withdrawn the bypass, and leaving the passdb behind would keep a
// credential valid that the panel no longer believes in.
func HealMasterUser(ctx context.Context) {
	password := MasterPassword()
	if password == "" {
		removeMasterUser()
		return
	}
	hash, err := HashPassword(password)
	if err != nil {
		log.Printf("mail master user: could not hash the master password: %v", err)
		return
	}
	if err := writeMasterUser(ctx, hash); err != nil {
		log.Printf("mail master user: %v", err)
	}
}

func writeMasterUser(ctx context.Context, hash string) error {
	if _, err := lookPath("doveconf"); err != nil {
		return nil // Dovecot is not installed on this host
	}
	line := masterUserName + ":" + hash + "\n"

	// The password file is the credential. 0600 and root-owned, written through a
	// temporary file so Dovecot can never read a half-written one.
	tmp := masterPasswdTarget + ".new"
	// #nosec G306 G703 -- fixed system path from a constant; this file holds the master credential, hence 0600.
	if err := os.WriteFile(tmp, []byte(line), 0o600); err != nil {
		return fmt.Errorf("write the master password file: %w", err)
	}
	if err := chownFile(tmp, 0, 0); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("set the master password file ownership: %w", err)
	}
	if err := os.Rename(tmp, masterPasswdTarget); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install the master password file: %w", err)
	}

	// #nosec G304 -- fixed system path from a constant, not from any request value.
	previous, previousErr := os.ReadFile(masterConfTarget)
	if previousErr == nil && string(previous) == masterConf {
		return nil // already in place; nothing to validate or reload
	}
	// #nosec G306 G703 -- fixed system path from a constant; the Dovecot daemon must read it and it names a file rather than holding the credential.
	if err := os.WriteFile(masterConfTarget, []byte(masterConf), 0o644); err != nil {
		return fmt.Errorf("write the master passdb drop-in: %w", err)
	}
	if out, err := execCommandContext(ctx, "doveconf", "-n").CombinedOutput(); err != nil {
		// Roll back rather than leave Dovecot with a file it refuses: that would
		// stop authentication for every mailbox on the server, not just webmail.
		if previousErr == nil {
			// #nosec G306 G703 -- restoring the file this function just replaced, at the same fixed system path.
			_ = os.WriteFile(masterConfTarget, previous, 0o644)
		} else {
			_ = os.Remove(masterConfTarget)
		}
		return fmt.Errorf("doveconf rejected the master passdb, it was rolled back: %s", strings.TrimSpace(string(out)))
	}
	if out, err := execCommandContext(ctx, "systemctl", "reload", "dovecot").CombinedOutput(); err != nil {
		return fmt.Errorf("reload dovecot: %s", strings.TrimSpace(string(out)))
	}
	log.Printf("mail master user configured for panel-initiated webmail sessions")
	return nil
}

// removeMasterUser withdraws the bypass.
func removeMasterUser() {
	_, confErr := os.Stat(masterConfPath)
	_ = os.Remove(masterPasswdFile)
	if confErr != nil {
		return // nothing was installed
	}
	if err := os.Remove(masterConfPath); err != nil {
		log.Printf("mail master user: could not remove the master passdb: %v", err)
		return
	}
	if out, err := exec.Command("systemctl", "reload", "dovecot").CombinedOutput(); err != nil {
		log.Printf("mail master user: removed but dovecot did not reload: %s", strings.TrimSpace(string(out)))
		return
	}
	log.Printf("mail master user removed; panel-initiated webmail sessions are disabled")
}
