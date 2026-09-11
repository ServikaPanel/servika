package backups

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// SFTP backup destinations are verified trust-on-first-use. The first
// connection scans the host key and stores it on the destination row; every
// connection after that is verified against exactly that key.
//
// The alternative in place before this was StrictHostKeyChecking=no plus
// UserKnownHostsFile=/dev/null on the ssh side and sftp:auto-confirm on the
// lftp side, which accepts any key on every connection. Anything on the path
// could then answer in the destination's place, collect the password the client
// offers it, and receive the backup archive.
//
// TOFU does not protect the very first connection. It does mean a host that
// changes key afterwards fails loudly instead of silently, and the operator has
// to clear the stored key to accept the new one.

// hostKeyScanTimeout bounds ssh-keyscan. It talks to a remote host, so it needs
// a deadline of its own; the value is short because a key scan is one round
// trip and the caller is an interactive connection test.
const hostKeyScanTimeout = 20 * time.Second

// errHostKeyUnavailable means the scan produced nothing usable. The caller must
// refuse the connection rather than fall back to accepting any key.
var errHostKeyUnavailable = errors.New("the destination's SSH host key could not be read")

// scanHostKey asks the destination for its host keys. The output is one
// known_hosts line per key type, which is exactly the format the ssh clients
// consume, so it is stored verbatim.
func scanHostKey(ctx context.Context, host string, port int) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, hostKeyScanTimeout)
	defer cancel()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); host passed validHost and netguard, port is an int.
	command := exec.CommandContext(ctx, "ssh-keyscan", "-p", strconv.Itoa(port), "-T", "10", host)
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("%w: %v", errHostKeyUnavailable, err)
	}
	var lines []string
	for line := range strings.SplitSeq(string(output), "\n") {
		line = strings.TrimSpace(line)
		// ssh-keyscan writes its progress to stderr, but comments can still
		// reach stdout; keep only real key lines.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return "", errHostKeyUnavailable
	}
	return strings.Join(lines, "\n"), nil
}

// ensureHostKey returns the pinned key for the destination, scanning and storing
// it on first use. A destination that already carries a key is never rescanned,
// which is what makes the pin meaningful.
func ensureHostKey(ctx context.Context, db *sql.DB, d *Destination) (string, error) {
	if strings.TrimSpace(d.HostKey) != "" {
		return d.HostKey, nil
	}
	key, err := scanHostKey(ctx, d.Host, d.Port)
	if err != nil {
		return "", err
	}
	if db != nil && d.DomainID != 0 {
		// Only fill an empty pin. The connection test can be driven with a form
		// body, which carries no stored key, so without this an operator testing
		// an already-pinned destination while something sits on the path would
		// replace the good key with whatever answered. A deliberate host change
		// clears the pin through PutDestination instead.
		if _, err := db.ExecContext(ctx,
			`UPDATE backup_destinations SET host_key=? WHERE domain_id=? AND host_key=''`,
			key, d.DomainID); err != nil {
			return "", fmt.Errorf("the host key could not be stored: %w", err)
		}
	}
	d.HostKey = key
	return key, nil
}

// knownHostsFile writes the pinned key where an ssh client can read it. The
// caller removes the file when the connection finishes.
func knownHostsFile(key string) (string, func(), error) {
	file, err := os.CreateTemp("", "servika-knownhosts-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.Remove(file.Name()) }
	if _, err := file.WriteString(strings.TrimRight(key, "\n") + "\n"); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return file.Name(), cleanup, nil
}

// hostKeyAlias spells the pinned name exactly as ssh-keyscan wrote it.
//
// ssh uses HostKeyAlias VERBATIM and applies no bracketing of its own. Measured
// against OpenSSH 10.3p1: on port 22 ssh-keyscan writes the bare name and a bare
// alias verifies; on any other port it writes `[host]:port`, and a bare alias
// there fails with "No ED25519 host key is known for <host> and you have
// requested strict checking", which refuses every connection to a destination on
// a non-default port.
func hostKeyAlias(host string, port int) string {
	if port == 22 {
		return host
	}
	return "[" + host + "]:" + strconv.Itoa(port)
}

// sshHostKeyOptions are the ssh flags that turn the pinned file into the only
// key the client will accept.
//
// hostAlias is the NAME the key was pinned under, as hostKeyAlias spells it. The
// caller connects to the address netguard vetted rather than to the name, so
// that the name is not resolved a second time; ssh-keyscan wrote the pin under
// the name, so without the alias ssh would look the address up in known_hosts,
// find nothing, and refuse.
func sshHostKeyOptions(knownHosts, hostAlias string) []string {
	return []string{
		"-o", "HostKeyAlias=" + hostAlias,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + knownHosts,
		// Without this ssh also consults the root account's known_hosts, which
		// would let a key trusted for some unrelated purpose satisfy the check.
		"-o", "GlobalKnownHostsFile=/dev/null",
	}
}
