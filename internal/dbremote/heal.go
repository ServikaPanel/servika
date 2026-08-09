package dbremote

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"
)

// dropInPath is a SEPARATE file from the installer's
// /etc/my.cnf.d/zz-servika-security.cnf, and its name sorts after it so MariaDB
// reads it last and its bind-address wins.
//
// Editing the installer's file instead would mean rewriting a hardening file to
// undo one of its own settings, and turning the feature off again would have to
// reconstruct it. Removing this file restores the loopback bind exactly as
// shipped, and `local-infile = 0` in the earlier file is untouched either way.
// Both were measured on 10.11.
//
// A variable so a test can exercise the writes under a temporary directory.
var dropInPath = "/etc/my.cnf.d/zzz-servika-remote-db.cnf"

// setDropInPath redirects the managed file. Test-only.
func setDropInPath(path string) { dropInPath = path }

// bindAllInterfaces is the only value that produces BOTH an IPv4 and an IPv6
// listener, measured on MariaDB 10.11.
//
// The MariaDB documentation shows 0.0.0.0 for "all interfaces"; that gives an
// IPv4 listener ONLY. `::` gives an IPv6 listener only. The panel is dual stack
// everywhere, so a customer on an IPv6-only network must not silently be unable
// to connect to a feature the screen says is on.
const bindAllInterfaces = "*"

// restartTimeout bounds the verification that follows the restart. A MariaDB
// restart on a busy server is not instant, but it is not minutes either, and an
// admin waiting on this screen needs an answer.
//
// A variable so a test can prove the rollback without waiting out the real one.
var restartTimeout = 90 * time.Second

// ErrBindVerifyFailed means MariaDB came back but the panel could not talk to
// it, so the drop-in was rolled back.
var ErrBindVerifyFailed = errors.New("the panel could not reach MariaDB after the restart")

// healCommand is a variable so a test can substitute a stub and inspect what the
// process actually receives.
var healCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args and no shell; nothing here is caller input.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
	}
	return cmd
}

// HealBind aligns the drop-in with what the database says the switch is.
//
// It runs at startup and does NOT restart MariaDB: a server that just booted
// already read whatever the file says, so a restart here would drop every site's
// connections to change nothing. Only Apply, driven by an admin, restarts.
func HealBind(db *sql.DB) {
	if db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	enabled, err := readSwitch(ctx, db)
	if err != nil {
		log.Printf("remote db: could not read the switch: %v", err)
		return
	}
	changed, err := writeDropIn(enabled)
	if err != nil {
		log.Printf("remote db: could not write %s: %v", dropInPath, err)
		return
	}
	if changed {
		log.Printf("remote db: %s realigned with the stored setting; it takes effect on the next MariaDB restart", dropInPath)
	}
}

// Apply turns remote access on or off: it writes the drop-in, restarts MariaDB,
// and verifies the panel can still reach it.
//
// The verification is the point. bind-address is not a dynamic variable, so the
// only way to apply it is a restart, and a restart that brings MariaDB back in a
// state the panel cannot use would take every site down with it. On any failure
// the drop-in goes back to what it was and MariaDB is restarted again, so the
// server is left in the state the caller found it in rather than half open.
func Apply(ctx context.Context, db *sql.DB, enable bool) error {
	previous, hadPrevious := readDropIn()

	if _, err := writeDropIn(enable); err != nil {
		return fmt.Errorf("could not write %s: %w", dropInPath, err)
	}
	if err := restartAndVerify(ctx, db); err != nil {
		// Put the file back exactly as it was, then bring MariaDB back to the
		// configuration it was running before this call.
		if hadPrevious {
			// #nosec G306 -- a MariaDB configuration file the server must read; it carries no secret.
			_ = os.WriteFile(dropInPath, previous, 0o644)
		} else {
			_ = os.Remove(dropInPath)
		}
		if restartErr := restart(ctx); restartErr != nil {
			// Worth its own line: the rollback itself failed, which is the one
			// case where an operator has to look at the host.
			log.Printf("remote db: ROLLBACK RESTART FAILED after %v: %v", err, restartErr)
		}
		return err
	}
	return nil
}

// writeDropIn renders the file for the requested state and reports whether
// anything changed. Turning the feature off REMOVES the file rather than writing
// the loopback address into it, so the installer's own hardening line is what
// takes effect again and there is only ever one place the bind is decided.
func writeDropIn(enable bool) (changed bool, err error) {
	if !enable {
		if _, statErr := os.Stat(dropInPath); os.IsNotExist(statErr) {
			return false, nil
		}
		if removeErr := os.Remove(dropInPath); removeErr != nil && !os.IsNotExist(removeErr) {
			return false, removeErr
		}
		return true, nil
	}

	body := []byte("# Managed by Servika. Remote database access is ON.\n" +
		"#\n" +
		"# This file sorts after zz-servika-security.cnf, so this bind-address is the\n" +
		"# one MariaDB uses. Removing the file restores the loopback bind that file\n" +
		"# sets. `*` rather than 0.0.0.0 because only `*` listens on IPv4 AND IPv6.\n" +
		"[mysqld]\n" +
		"bind-address = " + bindAllInterfaces + "\n")
	if current, readErr := os.ReadFile(dropInPath); readErr == nil && string(current) == string(body) {
		return false, nil
	}
	// #nosec G306 -- a MariaDB configuration file the server must read; it carries no secret.
	if err := os.WriteFile(dropInPath, body, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// readDropIn returns the file's current contents, if it exists at all.
func readDropIn() ([]byte, bool) {
	// #nosec G304 -- a package-level constant naming a system config file; no caller supplies it.
	data, err := os.ReadFile(dropInPath)
	if err != nil {
		return nil, false
	}
	return data, true
}

// restartAndVerify restarts MariaDB and then proves the panel can use it.
//
// "systemctl restart returned 0" is not proof: the unit can be active while the
// server refuses the panel's own connection, and that is precisely the state
// this feature could create by writing a bind address MariaDB cannot use.
func restartAndVerify(ctx context.Context, db *sql.DB) error {
	if err := restart(ctx); err != nil {
		return err
	}
	if db == nil {
		return nil
	}
	// The pool holds connections to a server that has just gone away, so the
	// first attempts are expected to fail. Retry until the deadline rather than
	// declaring failure on a connection that was already doomed.
	deadline := time.Now().Add(restartTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		lastErr = db.PingContext(pingCtx)
		cancel()
		if lastErr == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ErrBindVerifyFailed, ctx.Err())
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("%w: %w", ErrBindVerifyFailed, lastErr)
}

func restart(ctx context.Context) error {
	out, err := healCommand(ctx, "systemctl", "restart", "mariadb").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart mariadb: %s: %w", trimOutput(out), err)
	}
	return nil
}

func trimOutput(out []byte) string {
	const limit = 200
	text := string(out)
	if len(text) > limit {
		return text[:limit]
	}
	return text
}

// readSwitch reports whether remote access is meant to be on.
func readSwitch(ctx context.Context, db *sql.DB) (bool, error) {
	var enabled int
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(db_remote_enabled,0) FROM panel_settings WHERE id=1`).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return enabled == 1, nil
}
