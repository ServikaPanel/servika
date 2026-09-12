package provisioner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/logx"
)

// letsEncryptDirectory is the acme.sh per-CA config directory for the Let's Encrypt
// production endpoint; its ca.conf holds the registered contact address (CA_EMAIL).
const letsEncryptDirectory = "ca/acme-v02.api.letsencrypt.org/directory"

// IsACMERenewSkip reports whether an acme.sh command failed with RENEW_SKIP (exit code 2),
// which means a valid certificate is already in the store and no renewal was due. That is a
// success for every caller: the certificate exists and must still be deployed with
// --install-cert. Treating it as a failure makes a second issuance attempt report an error
// while a perfectly good certificate sits unused in the acme store.
func IsACMERenewSkip(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 2
}

// RunACMEIssue runs an acme.sh command and recovers from a permanently broken account
// contact address.
//
// Root problem: installation accepts any address that merely looks like an email (for
// example admin@test.local, whose TLD is not a public suffix). Let's Encrypt rejects it
// with invalidContact, but acme.sh still persists the value in BOTH account.conf
// (ACCOUNT_EMAIL) and the per-CA ca.conf (CA_EMAIL) even though registration failed.
// acme.sh reads CA_EMAIL first, so every later --issue call reuses the broken address and
// fails again with invalidContact, even for a perfectly valid domain and even when no -m
// flag is passed. Once a host lands in this state it can never obtain a certificate.
//
// Recovery: clear the stored contact in both files, register a contact-less account, and
// retry the command once. This also self-heals hosts already stuck in that state, without
// needing shell access.
func RunACMEIssue(args ...string) ([]byte, error) {
	out, err := runACME(args...)
	if err == nil || !strings.Contains(string(out), "invalidContact") {
		return out, err
	}
	logx.Warnf("acme: invalidContact, clearing the stored account contact and re-registering")
	clearACMEContact()
	_, _ = runACME("--register-account", "--server", "letsencrypt")
	return runACME(args...)
}

// acmeTimeout bounds one acme.sh invocation. Issuance waits on Let's Encrypt to
// validate the challenge, so an unreachable or rate-limiting CA would otherwise
// leave the process running for the life of the panel. Each invocation gets its
// own budget: RunACMEIssue may run three of them when it recovers a locked-out
// account, and the recovery must not be cut short by the first attempt's spend.
const acmeTimeout = 5 * time.Minute

// runACME executes one acme.sh command under acmeTimeout.
func runACME(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), acmeTimeout)
	defer cancel()
	return acmeCommandContext(ctx, args...).CombinedOutput()
}

// clearACMEContact empties the persisted acme.sh contact address in account.conf and in
// the Let's Encrypt ca.conf. Both must be cleared: acme.sh resolves the account email from
// the ACCOUNT_EMAIL environment variable, then CA_EMAIL, then account.conf, so clearing
// only one of them leaves the broken address in effect.
func clearACMEContact() {
	home := config.ACMEHome()
	emptyACMEKey(filepath.Join(home, "account.conf"), "ACCOUNT_EMAIL")
	emptyACMEKey(filepath.Join(home, letsEncryptDirectory, "ca.conf"), "CA_EMAIL")
}

func emptyACMEKey(path, key string) {
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	body, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(body), "\n")
	changed := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), key+"=") {
			lines[i] = key + "=''"
			changed = true
		}
	}
	if !changed {
		return
	}
	// #nosec G703 -- path is built from a validated identifier (systemUser ^c_[A-Za-z0-9_]+$ / validated domainName), a fixed system path, or a server-internal temp path; tenant file-manager paths use safeio (openat2) instead.
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		logx.Errorf("acme: clear %s in %s: %v", key, path, err)
	}
}

// RunACMECommand runs an acme.sh command with the panel's environment under the same
// deadline as issuance, for callers outside this package. It replaced an exported
// constructor that handed back an *exec.Cmd, because a caller holding the command
// cannot be given a deadline that is still meaningful when it finally runs it.
func RunACMECommand(args ...string) error {
	_, err := runACME(args...)
	return err
}
