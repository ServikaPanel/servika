// Site migration from a live cPanel / Plesk / DirectAdmin server.
//
// SECURITY NOTE (this file is the centre of the attack surface):
// This code connects to a REMOTE server with operator-supplied credentials and
// pulls data from it. EVERYTHING the remote side returns (account name, domain,
// database name, zone content) is HOSTILE and is never embedded in a command
// unescaped.
//
//  1. No shell locally: every local process runs through newTransferCommand
//     (exec.CommandContext with separate args) — never "sh -c".
//  2. Remote commands are FIXED templates. A variable value is wrapped by
//     shellQuote() because a shell is unavoidable on the remote side.
//  3. Host and user names pass an allowlist regexp and a leading '-' is
//     REJECTED, otherwise ssh/rsync reads the value as a FLAG (arg injection).
//  4. ssh is always called as "-l <user> -- <host>" (no user@host parsing).
//  5. The password never reaches argv (visible in ps) — sshpass -e reads it
//     from an environment variable.
//  6. Credentials are stored with AES-256-GCM (internal/secret) and cleared
//     when the job finishes.
package transfers

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// RemoteSource holds the connection details of the server to migrate from.
type RemoteSource struct {
	Type     string // cpanel | plesk | directadmin
	Host     string
	Port     int
	User     string
	Password string // plaintext ONLY in memory; written encrypted to the database
	Key      string // SSH private key (optional alternative to the password)
}

// MigrationSettings controls migration behaviour and is stored as JSON in
// migration_jobs.settings.
type MigrationSettings struct {
	Files      bool   `json:"files"`
	Databases  bool   `json:"databases"`
	DNS        bool   `json:"dns"`
	SSL        bool   `json:"ssl"`
	Overwrite  bool   `json:"overwrite"` // write over an existing target domain
	TargetPHP  string `json:"target_php"`
	PlanID     int64  `json:"plan_id"`
	CustomerID int64  `json:"customer_id"` // 0 = no customer

	Accounts []string `json:"accounts"` // accounts picked in bulk mode (empty = all)
}

const (
	sshConnectSeconds = 15
	discoveryTimeout  = 90 * time.Second
	// Upper bound for one account so a stuck rsync/mysqldump cannot hold the
	// single migration slot forever.
	accountTimeout = 3 * time.Hour
	// knownHostsFile keeps host keys learned during migrations apart from the
	// panel's own SSH state.
	knownHostsFile = "/var/lib/servika/known_hosts_migration"
)

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

var (
	// RFC1123 host name; no leading or trailing dash, cannot START with '-'.
	reRemoteHost = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$`)
	// Unix user name; cannot start with '-'.
	reRemoteUser = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$`)
	// Account names returned by the remote panel (cpanel/plesk/DA users).
	reRemoteAccount = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$`)
	// Domain name.
	reRemoteDomain = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	// MySQL identifier.
	reRemoteDBName = regexp.MustCompile(`^[A-Za-z0-9_$-]{1,64}$`)
)

var validSourceTypes = map[string]bool{"cpanel": true, "plesk": true, "directadmin": true}

// Validate fully checks the source input before it is accepted. The leading '-'
// check matters most: "-oProxyCommand=..." is an ssh FLAG, not a host name.
func (s *RemoteSource) Validate() error {
	if !validSourceTypes[s.Type] {
		return fmt.Errorf("invalid source panel type")
	}
	host := strings.TrimSpace(s.Host)
	if host == "" || len(host) > 253 || strings.HasPrefix(host, "-") {
		return fmt.Errorf("source server address is invalid")
	}
	// Must be an IP address or a host name.
	if net.ParseIP(host) == nil && !reRemoteHost.MatchString(host) {
		return fmt.Errorf("source server address is invalid")
	}
	s.Host = host

	if s.Port <= 0 || s.Port > 65535 {
		return fmt.Errorf("SSH port is invalid")
	}
	user := strings.TrimSpace(s.User)
	if user == "" {
		user = "root"
	}
	if strings.HasPrefix(user, "-") || !reRemoteUser.MatchString(user) {
		return fmt.Errorf("SSH user name is invalid")
	}
	s.User = user

	if s.Password == "" && strings.TrimSpace(s.Key) == "" {
		return fmt.Errorf("a password or an SSH key is required")
	}
	// A line break or NUL in the password breaks the sshpass environment value.
	if strings.ContainsAny(s.Password, "\x00\r\n") {
		return fmt.Errorf("the password contains an invalid character")
	}
	return nil
}

// shellQuote wraps a value in single quotes for the remote shell. Nothing is
// interpreted inside single quotes; an embedded single quote is closed and
// escaped. Hostile remote values enter a command only through this helper.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// mysqlAdminAuth returns the REMOTE-shell prefix that authenticates the source
// MySQL admin client, per panel type. cPanel returns empty because root reads
// its own ~/.my.cnf; Plesk and DirectAdmin keep the MySQL admin account
// PASSWORD-PROTECTED, so a credential-less client is refused with 1045
// "Access denied ... (using password: NO)" (measured on a live Plesk source),
// which for mysqldump then reads as an empty database rather than a failure.
// The password is read on the REMOTE side with $(...), so it never enters an
// argument list here or the remote host's `ps`; only the command reading it is
// visible. Both returned fragments already carry a trailing space.
func (s *RemoteSource) mysqlAdminAuth() (env, userArg string) {
	switch s.Type {
	case "plesk":
		return `MYSQL_PWD="$(cat /etc/psa/.psa.shadow 2>/dev/null)" `, "-uadmin "
	case "directadmin":
		return `MYSQL_PWD="$(sed -n 's/^passwd=//p' /usr/local/directadmin/conf/mysql.conf 2>/dev/null)" `,
			`-u"$(sed -n 's/^user=//p' /usr/local/directadmin/conf/mysql.conf 2>/dev/null)" `
	}
	return "", ""
}

// ---------------------------------------------------------------------------
// Remote execution
// ---------------------------------------------------------------------------

// sshCommonArgs returns the hardened options used by every ssh and rsync call.
func (s *RemoteSource) sshCommonArgs(keyFile string) []string {
	args := []string{
		"-p", fmt.Sprintf("%d", s.Port),
		"-o", fmt.Sprintf("ConnectTimeout=%d", sshConnectSeconds),
		// Accept the host key on the first connection but REJECT it when it
		// changes later (MITM protection). A migration is a one-off task, so
		// this is the right balance.
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + knownHostsFile,
		// Stop the source server from pushing commands or an agent back to us.
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "PermitLocalCommand=no",
	}
	if keyFile != "" {
		// Key path: no interactive prompt, so the process cannot hang.
		args = append(args, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-i", keyFile)
	} else {
		// Password path: BatchMode=yes MUST NOT be used because it turns off the
		// password prompt and sshpass then has nothing to answer, which breaks
		// every password-based migration. Force password auth with a single
		// prompt instead (no retry loop or hang on a wrong password).
		args = append(args, "-o", "PubkeyAuthentication=no",
			"-o", "PreferredAuthentications=password,keyboard-interactive",
			"-o", "NumberOfPasswordPrompts=1")
	}
	return args
}

// writeKeyFile writes the SSH private key to a 0600 temporary file. The caller
// must call the returned cleanup function.
func (s *RemoteSource) writeKeyFile() (path string, cleanup func(), err error) {
	if strings.TrimSpace(s.Key) == "" {
		return "", func() {}, nil
	}
	f, err := os.CreateTemp("", ".servika_migration_key_*")
	if err != nil {
		return "", func() {}, err
	}
	name := f.Name()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", func() {}, err
	}
	content := s.Key
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", func() {}, err
	}
	_ = f.Close()
	return name, func() { _ = os.Remove(name) }, nil
}

// sshCommand builds the ssh (or sshpass+ssh) process for a remote command with
// an explicit environment, so panel secrets in os.Environ() are never inherited.
func (s *RemoteSource) sshCommand(ctx context.Context, keyFile, remoteCommand string) *exec.Cmd {
	args := s.sshCommonArgs(keyFile)
	// "-l <user> -- <host>": no user@host parsing, and the host cannot be read
	// as a flag.
	args = append(args, "-l", s.User, "--", s.Host, remoteCommand)
	if keyFile == "" {
		// The password stays out of argv: sshpass -e reads it from SSHPASS.
		command := newTransferCommand(ctx, "sshpass", append([]string{"-e", "ssh"}, args...)...)
		command.Env = append(command.Env, "SSHPASS="+s.Password)
		return command
	}
	return newTransferCommand(ctx, "ssh", args...)
}

// Run executes a command on the remote server and returns stdout. remoteCommand
// is a FIXED template produced by this package; any variable value inside it
// must already have gone through shellQuote().
func (s *RemoteSource) Run(ctx context.Context, remoteCommand string) (string, error) {
	keyFile, cleanup, err := s.writeKeyFile()
	if err != nil {
		return "", fmt.Errorf("could not write the SSH key: %w", err)
	}
	defer cleanup()

	cmd := s.sshCommand(ctx, keyFile, remoteCommand)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("remote command failed: %s",
			truncate(sanitizeRemoteError(stderr.String(), s.Password), 300))
	}
	return stdout.String(), nil
}

// RsyncPull copies a remote directory to a local path. The caller validates
// remotePath and localPath.
func (s *RemoteSource) RsyncPull(ctx context.Context, remotePath, localPath string, extra ...string) (string, error) {
	keyFile, cleanup, err := s.writeKeyFile()
	if err != nil {
		return "", err
	}
	defer cleanup()

	// ssh command string for rsync -e. The values are allowlisted, so there is
	// no whitespace or quoting risk here, but the template still stays fixed.
	sshArgs := append([]string{"ssh"}, s.sshCommonArgs(keyFile)...)

	args := []string{
		// NO DELETION. --delete-excluded IMPLIES --delete: everything present on
		// the target but missing on the source is removed. In overwrite mode the
		// target is the customer's LIVE directory, so uploads/ and public/ would
		// be destroyed with no way back.
		"-a", "--numeric-ids",
		"--timeout=120", "--partial",
		// Tenant isolation: setuid and setgid bits are never carried over.
		"--no-perms", "--chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r",
		// Symlinks cannot point outside the target.
		"--safe-links",
		"-e", strings.Join(sshArgs, " "),
	}
	args = append(args, extra...)
	// Source: user@host:path — the user and host passed the allowlist.
	args = append(args, s.User+"@"+s.Host+":"+remotePath, localPath)

	var cmd *exec.Cmd
	if keyFile == "" {
		cmd = newTransferCommand(ctx, "sshpass", append([]string{"-e", "rsync"}, args...)...)
		cmd.Env = append(cmd.Env, "SSHPASS="+s.Password)
	} else {
		cmd = newTransferCommand(ctx, "rsync", args...)
	}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("rsync failed: %s",
			truncate(sanitizeRemoteError(stderr.String(), s.Password), 300))
	}
	return stdout.String(), nil
}

// TestConnection checks whether the credentials work and reports the remote
// host name.
func (s *RemoteSource) TestConnection(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	out, err := s.Run(ctx, "echo SERVIKA_OK; uname -n")
	if err != nil {
		return "", err
	}
	if !strings.Contains(out, "SERVIKA_OK") {
		return "", fmt.Errorf("the source server did not return the expected response")
	}
	fields := strings.Fields(out)
	name := ""
	if len(fields) > 1 {
		name = fields[len(fields)-1]
	}
	return name, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// sanitizeRemoteError collapses remote stderr to one line AND masks known
// secrets. This text reaches migration_items.error_text and the API response,
// so a password echoed by ssh/sshpass/rsync must never leak out.
func sanitizeRemoteError(s string, secrets ...string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	for _, secret := range secrets {
		if len(secret) >= 4 {
			s = strings.ReplaceAll(s, secret, "******")
		}
	}
	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// migrationSourceIPv4 returns the public IPv4 the migrated site must resolve to.
func migrationSourceIPv4(db *sql.DB) string {
	var ip string
	_ = db.QueryRow(`SELECT ipv4 FROM domains WHERE ipv4 IS NOT NULL AND ipv4<>'' LIMIT 1`).Scan(&ip)
	if ip != "" {
		return ip
	}
	out, err := newTransferCommand(context.Background(), "hostname", "-I").Output()
	if err == nil {
		if fields := strings.Fields(string(out)); len(fields) > 0 {
			return fields[0]
		}
	}
	return "127.0.0.1"
}
