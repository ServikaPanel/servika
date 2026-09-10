package redis

import (
	"os"
	"strings"
	"testing"
)

// /proc/<pid>/cmdline is mode 444 on Linux while /proc/<pid>/environ is 400, so
// an argument is readable by every other account on the host. Each c_* tenant has
// a shell, cron and PHP, so a neighbour only has to be looking while the command
// runs to take the victim's Valkey ACL credential and read their whole key space.
//
// These walk the sources rather than listing call sites, so a NEW command built
// with the password in argv fails here instead of shipping the same exposure.

// The ACL rule carries the tenant's password, so its command line goes on stdin.
func TestTheACLPasswordDoesNotReachArgv(t *testing.T) {
	body := readSource(t, "redis.go")

	// HealScanACL also builds an ACL SETUSER through argv, and that one is fine:
	// it carries a username and two command denials and no credential at all.
	// What may never be an argument is the ">"+password token.
	if strings.Contains(body, `cli("ACL", "SETUSER", systemUser, "on", ">"+password`) {
		t.Error("the ACL password is still a valkey-cli argument")
	}
	if !strings.Contains(body, "cliInput(strings.Join") {
		t.Error("the ACL rule no longer travels on stdin")
	}
	if !strings.Contains(body, "cmd.Stdin = strings.NewReader(command") {
		t.Error("cliInput does not write the command to stdin")
	}
}

// The wp-config constant's VALUE is the credential, so it uses wp-cli's own
// --prompt mechanism. --quiet is required, because wp-cli otherwise echoes the
// whole command line it assembled, prompted value included.
func TestTheWordPressConstantDoesNotReachArgv(t *testing.T) {
	body := readSource(t, "redis.go")

	if strings.Contains(body, `set("WP_REDIS_PASSWORD"`) {
		t.Error("WP_REDIS_PASSWORD is still passed as a wp-cli argument")
	}
	if !strings.Contains(body, `"--quiet", "--prompt=value"`) {
		t.Error("the secret constant is not written through --prompt with --quiet")
	}
	if !strings.Contains(body, "setSecretConstant(systemUser, dir, \"WP_REDIS_PASSWORD\"") {
		t.Error("WP_REDIS_PASSWORD is not written through the secret path")
	}
}

// The ops script repairs the same two things on an existing host, so it carries
// the same rule or the repair reintroduces the exposure on every run.
func TestTheOpsScriptKeepsThePasswordOffArgv(t *testing.T) {
	body := readSource(t, "../../assets/ops/servika-wp-redis.sh")

	if strings.Contains(body, `vc ACL SETUSER`) {
		t.Error("the script still passes the ACL password as an argument")
	}
	if !strings.Contains(body, "vc_in \"ACL SETUSER") {
		t.Error("the script no longer sets the ACL rule through stdin")
	}
	if strings.Contains(body, `set_ WP_REDIS_PASSWORD`) {
		t.Error("the script still passes WP_REDIS_PASSWORD as an argument")
	}
	if !strings.Contains(body, "--prompt=value") {
		t.Error("the script does not write WP_REDIS_PASSWORD through --prompt")
	}
}

// valkey-cli parses the stdin command line with its own tokenizer, so whitespace
// or a quote in the password would split the token and change the rule being set.
func TestAPasswordThatWouldSplitTheCommandIsRefused(t *testing.T) {
	for _, password := range []string{"", "two words", "quote'inside", `double"inside`, "line\nbreak", "tab\there"} {
		if aclSafePassword(password) {
			t.Errorf("%q was accepted as an ACL password", password)
		}
	}
	if !aclSafePassword(genPass()) {
		t.Error("a generated password was refused")
	}
}

func readSource(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}
