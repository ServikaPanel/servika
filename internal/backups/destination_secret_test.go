package backups

import (
	"context"
	"slices"
	"strings"
	"testing"
)

const sentinelPassword = "SentinelDestPass234"

func sentinelDestination() *Destination {
	return &Destination{
		Type: "sftp", Host: "backup.example.com", Port: 22,
		Username: "alice", Password: sentinelPassword, RemoteDir: "/backups",
	}
}

// argv is world-readable through /proc/<pid>/cmdline and a tenant reaches that
// window with arbitrary shell from a cron entry, so a destination password must
// travel in the environment instead.
func TestLFTPCommandKeepsThePasswordOutOfArgv(t *testing.T) {
	d := sentinelDestination()
	cmd := lftpCommand(context.Background(), d, "set net:timeout 15; "+lftpOpen(d)+"; bye")

	joined := strings.Join(cmd.Args, " ")
	if strings.Contains(joined, sentinelPassword) {
		t.Fatalf("the destination password reached argv: %q", joined)
	}
	if !containsEnv(cmd.Env, "LFTP_PASSWORD="+sentinelPassword) {
		t.Fatal("LFTP_PASSWORD is missing, so --env-password has nothing to read and every upload would fail")
	}
	assertEnvAllowlist(t, cmd.Env, "LFTP_PASSWORD")
}

func TestSSHPassCommandKeepsThePasswordOutOfArgv(t *testing.T) {
	d := sentinelDestination()
	cmd := sshpassCommand(context.Background(), d, "-e", "ssh", "-l", d.Username, "--", d.Host, "true")

	joined := strings.Join(cmd.Args, " ")
	if strings.Contains(joined, sentinelPassword) {
		t.Fatalf("the destination password reached argv: %q", joined)
	}
	if !containsEnv(cmd.Env, "SSHPASS="+sentinelPassword) {
		t.Fatal("SSHPASS is missing, so sshpass -e has nothing to answer the prompt with")
	}
	assertEnvAllowlist(t, cmd.Env, "SSHPASS")
}

// A guard against reviving `open -u user,password`, which is what put the
// password into the lftp -c argument.
func TestLFTPOpenCarriesNoPassword(t *testing.T) {
	got := lftpOpen(sentinelDestination())
	if strings.Contains(got, sentinelPassword) {
		t.Fatalf("lftpOpen() = %q, which embeds the password in the script", got)
	}
	if !strings.Contains(got, "--env-password") {
		t.Fatalf("lftpOpen() = %q, which does not tell lftp to read LFTP_PASSWORD", got)
	}
	if !strings.Contains(got, `-u "alice"`) {
		t.Errorf("lftpOpen() = %q, which lost the username", got)
	}
}

// Verified against curl 8.7.1: `\\` reads back as one backslash and `\"` as one
// double quote, so an unescaped value would end the credential early.
func TestCurlCredentialConfigEscapesQuotesAndBackslashes(t *testing.T) {
	tests := []struct{ user, password, want string }{
		{user: "alice", password: "plain234", want: "user = \"alice:plain234\"\n"},
		{user: "alice", password: `pa\ss"wo rd`, want: "user = \"alice:pa\\\\ss\\\"wo rd\"\n"},
		{user: `bo"b`, password: "p234", want: "user = \"bo\\\"b:p234\"\n"},
	}
	for _, test := range tests {
		if got := curlCredentialConfig(test.user, test.password); got != test.want {
			t.Errorf("curlCredentialConfig(%q, %q) = %q, want %q", test.user, test.password, got, test.want)
		}
	}
}

// A line break would end the curl config line and a NUL cannot go into an
// environment value, so both must fail loudly rather than authenticate with a
// truncated secret. Rows stored before validDestinationInput existed can still
// hold either one.
func TestCredentialSafeRejectsUndeliverablePasswords(t *testing.T) {
	for _, password := range []string{"pass\nword", "pass\rword", "pass\x00word"} {
		if err := credentialSafe(password); err == nil {
			t.Errorf("credentialSafe(%q) = nil, want a refusal", password)
		}
	}
	if err := credentialSafe(sentinelPassword); err != nil {
		t.Errorf("credentialSafe(%q) = %v, want nil", sentinelPassword, err)
	}
}

func containsEnv(env []string, entry string) bool {
	return slices.Contains(env, entry)
}

// The command must carry the package's allowlist and nothing else, so panel
// secrets in the server environment are never handed to a remote-facing tool.
func assertEnvAllowlist(t *testing.T, env []string, credentialKey string) {
	t.Helper()
	for _, e := range env {
		key, _, _ := strings.Cut(e, "=")
		switch key {
		case "PATH", "HOME", credentialKey:
		default:
			t.Errorf("environment carries %q, which is outside the allowlist", key)
		}
	}
}
