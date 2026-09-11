package mail

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// mainCfAt points the repair at a temporary main.cf, absent when content is
// empty.
func mainCfAt(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "main.cf")
	if content != "" {
		writeTestFile(t, path, content)
	}
	setForTest(t, &postfixMainCf, path)
}

// The repair runs nothing on a host it must leave alone or has nothing to do on.
func TestHealPostfixIPv6LeavesAHostAlone(t *testing.T) {
	cases := []struct {
		name, content string
		tools         []string
	}{
		{"no main.cf", "", []string{"postconf"}},
		{"a Postfix this panel did not configure", "inet_protocols = ipv4\n", []string{"postconf"}},
		{"no postconf", "# servika-mail\n", nil},
		{"every setting in place", "# servika-mail\ninet_protocols = all\nsmtp_address_preference = any\nsmtp_balance_inet_protocols = yes\n", []string{"postconf"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mainCfAt(t, c.content)
			withLookPath(t, c.tools...)
			commands := withCommands(t)
			healPostfixIPv6(context.Background())
			if argv := commands.argvs(); len(argv) != 0 {
				t.Fatalf("commands ran: %q", argv)
			}
		})
	}
}

// Only the missing settings are written, then Postfix is checked and restarted,
// because a reload does not rebind its listeners.
func TestHealPostfixIPv6WritesOnlyTheMissingSettings(t *testing.T) {
	mainCfAt(t, "# ===== servika-mail =====\ninet_protocols = all\n")
	withLookPath(t, "postconf")
	commands := withCommands(t)
	logged := captureApplyLog(t)

	healPostfixIPv6(context.Background())

	want := [][]string{
		{"postconf", "-e", "smtp_address_preference = any"},
		{"postconf", "-e", "smtp_balance_inet_protocols = yes"},
		{"postfix", "check"},
		{"systemctl", "restart", "postfix"},
	}
	if !slices.EqualFunc(commands.argvs(), want, slices.Equal) {
		t.Fatalf("commands = %q, want %q", commands.argvs(), want)
	}
	if !strings.Contains(logged.String(), "(smtp_address_preference = any; smtp_balance_inet_protocols = yes)") {
		t.Fatalf("log = %q", logged.String())
	}
}

// A refusal at any step stops the repair there and says which step it was.
func TestHealPostfixIPv6StopsAtTheFirstRefusal(t *testing.T) {
	cases := []struct {
		name   string
		fail   []string
		ran    int
		logged string
	}{
		{"postconf refuses a setting", []string{"postconf"}, 1, `could not set "smtp_address_preference = any"`},
		{"postfix refuses the result", []string{"postfix", "check"}, 3, "postfix refused the settings"},
		{"postfix does not restart", []string{"systemctl"}, 4, "could not restart postfix"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mainCfAt(t, "# servika-mail\ninet_protocols = all\n")
			withLookPath(t, "postconf")
			commands := withCommands(t, c.fail)
			logged := captureApplyLog(t)
			healPostfixIPv6(context.Background())
			if len(commands.argvs()) != c.ran || !strings.Contains(logged.String(), c.logged) {
				t.Fatalf("commands = %q, log = %q", commands.argvs(), logged.String())
			}
		})
	}
}
