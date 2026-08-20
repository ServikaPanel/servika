package passwordprotect

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const sentinelPassword = "SentinelProtect234"

// argv is world-readable through /proc/<pid>/cmdline and a tenant reaches that
// window with arbitrary shell from a cron entry, so the directory password must
// arrive on stdin.
func TestHtpasswdCommandKeepsThePasswordOutOfArgv(t *testing.T) {
	cmd := htpasswdCommand("/etc/nginx/htpasswd/d1_private", "alice", sentinelPassword, false)

	joined := strings.Join(cmd.Args, " ")
	if strings.Contains(joined, sentinelPassword) {
		t.Fatalf("the directory password reached argv: %q", joined)
	}
	if !strings.Contains(joined, "alice") || !strings.Contains(joined, "d1_private") {
		t.Errorf("argv %q lost the user or the file", joined)
	}

	stdin, err := io.ReadAll(cmd.Stdin)
	if err != nil {
		t.Fatalf("read stdin: %v", err)
	}
	if string(stdin) != sentinelPassword+"\n" {
		t.Errorf("stdin = %q, want the password and one terminator", stdin)
	}
}

// -c creates the file and would truncate an existing one, so it must appear
// only when the file is new.
func TestHtpasswdCommandAddsCreateFlagOnlyForANewFile(t *testing.T) {
	appendArgs := strings.Join(htpasswdCommand("/f", "alice", "p", false).Args, " ")
	if strings.Contains(appendArgs, "-ciB") {
		t.Errorf("append run uses %q, which would truncate the existing users out of the file", appendArgs)
	}
	if !strings.Contains(appendArgs, "-iB") {
		t.Errorf("append run uses %q, which does not read the password from stdin", appendArgs)
	}
	if createArgs := strings.Join(htpasswdCommand("/f", "alice", "p", true).Args, " "); !strings.Contains(createArgs, "-ciB") {
		t.Errorf("create run uses %q, which does not create the file", createArgs)
	}
}

// The flags are bundled and the password never touches the file the way the
// command line spells it, so run the real binary end to end where it exists and
// verify htpasswd both accepts the form and stores the password unchanged.
func TestHtpasswdStoresThePasswordItReadsFromStdin(t *testing.T) {
	if _, err := exec.LookPath("htpasswd"); err != nil {
		t.Skip("htpasswd is not installed on this host")
	}
	file := filepath.Join(t.TempDir(), "htpasswd")

	if out, err := htpasswdCommand(file, "alice", sentinelPassword, true).CombinedOutput(); err != nil {
		t.Fatalf("create run failed: %v: %s", err, out)
	}
	if out, err := htpasswdCommand(file, "bob", "SecondPass234", false).CombinedOutput(); err != nil {
		t.Fatalf("append run failed: %v: %s", err, out)
	}

	for _, user := range []struct{ name, password string }{
		{name: "alice", password: sentinelPassword},
		{name: "bob", password: "SecondPass234"},
	} {
		// #nosec G204 -- test-owned temp path and literal credentials.
		if out, err := exec.Command("htpasswd", "-vb", file, user.name, user.password).CombinedOutput(); err != nil {
			t.Errorf("%s cannot log in with the password that was sent: %v: %s", user.name, err, out)
		}
	}
	// The append run must not have dropped the first user.
	// #nosec G204 -- test-owned temp path and literal credentials.
	if out, err := exec.Command("htpasswd", "-vb", file, "alice", sentinelPassword).CombinedOutput(); err != nil {
		t.Errorf("the append run truncated the file: %v: %s", err, out)
	}
}

// A password file holds bcrypt hashes, so no account other than nginx may read
// it. The file used to be left at 0644 inside a 0755 directory, which every
// tenant on the host could read.
func TestTheSecuredFileIsClosedToEveryOtherAccount(t *testing.T) {
	file := filepath.Join(t.TempDir(), "d1_private")
	if err := os.WriteFile(file, []byte("alice:$2y$05$hash\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The current account's own ids, because a non-root test cannot give a file
	// away. What is being asserted is the mode the call leaves behind.
	if err := secureHtpasswd(file, os.Getuid(), os.Getgid(), htpasswdFileMode); err != nil {
		t.Fatalf("secureHtpasswd: %v", err)
	}

	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != htpasswdFileMode {
		t.Errorf("mode is %04o, want %04o", got, htpasswdFileMode)
	}
	if info.Mode().Perm()&0o007 != 0 {
		t.Errorf("mode %04o still grants something to other, so any tenant can read the hashes", info.Mode().Perm())
	}
	if htpasswdDirMode&0o007 != 0 {
		t.Errorf("directory mode %04o still grants something to other", htpasswdDirMode)
	}
}

// A chown that fails must leave the mode exactly as it was. Tightening it anyway
// produces a file nginx cannot read, which takes the protected directory down
// instead of merely leaving it readable.
func TestAFailedChownLeavesTheModeAlone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can give a file to any group, so the failure cannot be produced here")
	}
	file := filepath.Join(t.TempDir(), "d1_private")
	if err := os.WriteFile(file, []byte("alice:$2y$05$hash\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Group 0 is one an unprivileged account cannot chown to.
	if err := secureHtpasswd(file, os.Getuid(), 0, htpasswdFileMode); err == nil {
		t.Fatal("the failed chown was reported as success")
	}

	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("the mode was changed to %04o after the chown failed; it must stay 0644", got)
	}
}
