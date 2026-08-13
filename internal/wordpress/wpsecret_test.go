package wordpress

import (
	"os"
	"strings"
	"testing"
)

// /proc/<pid>/cmdline is mode 444 and readable by every account on the host,
// while /proc/<pid>/environ is 400 (measured on AlmaLinux 10). A password built
// into a wp-cli argument is therefore readable by a neighbouring c_* tenant for
// as long as the command runs.
//
// The check is on the source text because the alternative is executing wp-cli,
// which this suite has no way to do. It looks for the argument being ASSEMBLED,
// which is what puts the value in argv; the same spelling inside a comment or a
// prompt name is not.
func TestNoPasswordIsBuiltIntoAWPArgument(t *testing.T) {
	for _, file := range []string{"wordpress.go", "toolkit.go"} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for _, flag := range []string{"--dbpass=", "--admin_password=", "--user_pass="} {
			// An assembled argument is the flag immediately followed by a Go
			// concatenation: `"--dbpass="+dbPass`.
			needle := `"` + flag + `"+`
			if strings.Contains(string(source), needle) {
				t.Errorf("%s builds %s into an argv value; feed it through runWPSecret instead", file, flag)
			}
		}
	}
}

// wp-cli echoes the prompt line with the value it read even under --quiet
// ("1/10 [--dbpass=<dbpass>]: <secret>"), and Install's fail() puts the tail of
// that output into an HTTP error body.
func TestTheSecretIsRemovedFromReturnedOutput(t *testing.T) {
	const secret = "s3cr3tPassw0rd"
	out := []byte("1/10 [--dbpass=<dbpass>]: " + secret + "\nError: something went wrong\n")

	got := string(redact(out, secret))
	if strings.Contains(got, secret) {
		t.Fatalf("the secret survived redaction: %q", got)
	}
	if !strings.Contains(got, "Error: something went wrong") {
		t.Fatalf("redaction removed the diagnostic too: %q", got)
	}
}

// A secret appearing more than once must go entirely: wp-cli prints it on the
// prompt line and, without --quiet, again in the command line it echoes.
func TestEveryOccurrenceOfTheSecretIsRemoved(t *testing.T) {
	const secret = "abc123"
	out := []byte(secret + " middle " + secret + " end " + secret)
	if strings.Contains(string(redact(out, secret)), secret) {
		t.Fatal("an occurrence of the secret survived")
	}
}

// Redaction must not corrupt output when there is nothing to remove, because
// every runWPSecret result passes through it.
func TestRedactionLeavesUnrelatedOutputAlone(t *testing.T) {
	out := []byte("Error: This does not seem to be a WordPress installation.")
	if got := string(redact(out, "")); got != string(out) {
		t.Fatalf("empty secret changed the output: %q", got)
	}
	if got := string(redact(out, "notpresent")); got != string(out) {
		t.Fatalf("absent secret changed the output: %q", got)
	}
}

// wpCheckPasswordPHP reads two lines with fgets, so a line break in either value
// makes it compare a different pair than the caller asked about. On the reset
// path the password is customer-supplied, so this is reachable input.
func TestALineBreakCannotShiftThePasswordCheckProtocol(t *testing.T) {
	shifted := []struct {
		name     string
		login    string
		password string
	}{
		{"newline in login", "admin\nother", "pw"},
		{"carriage return in login", "admin\rother", "pw"},
		{"newline in password", "admin", "pw\nOK"},
		{"null in password", "admin", "pw\x00"},
	}
	for _, tc := range shifted {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := checkPasswordStdin(tc.login, tc.password); ok {
				t.Fatal("accepted a value that would shift the two-line protocol")
			}
		})
	}

	stdin, ok := checkPasswordStdin("admin", "pw")
	if !ok {
		t.Fatal("refused an ordinary login and password")
	}
	if stdin != "admin\npw\n" {
		t.Fatalf("payload is %q, want the login and the password on their own lines", stdin)
	}
}

// The exit code proves nothing: wp-cli silently ignores a --prompt name it does
// not know, exiting 0 with an empty stderr. Measured consequences are an empty
// DB_PASSWORD, an administrator account that is never created, and a password
// reset that leaves the old password working. Every call site must therefore
// read the result back.
func TestEveryPromptedSecretIsVerifiedAfterwards(t *testing.T) {
	calls := map[string]struct {
		file   string
		verify string
	}{
		"dbpass":         {"wordpress.go", "configPasswordMatches("},
		"admin_password": {"wordpress.go", "passwordWorks("},
		"user_pass":      {"toolkit.go", "passwordWorks("},
	}
	for prompt, want := range calls {
		t.Run(prompt, func(t *testing.T) {
			source, err := os.ReadFile(want.file)
			if err != nil {
				t.Fatalf("read %s: %v", want.file, err)
			}
			body := string(source)
			at := strings.Index(body, `runWPSecret(systemUser, "`+prompt+`"`)
			if at < 0 {
				t.Fatalf("%s no longer feeds %s through runWPSecret", want.file, prompt)
			}
			// The verification belongs to the same handler, so look only at
			// what follows the call rather than anywhere in the file.
			rest := body[at:]
			if end := strings.Index(rest, "\nfunc "); end > 0 {
				rest = rest[:end]
			}
			if !strings.Contains(rest, want.verify) {
				t.Fatalf("%s runs %s but never calls %s to check the result", want.file, prompt, want.verify)
			}
		})
	}
}

// --quiet is what suppresses the full command line wp-cli would otherwise echo
// with the prompted value in it. It does not hide real errors: a failing command
// still exits non-zero with its message on stderr (measured).
func TestTheQuietFlagIsAlwaysPaired(t *testing.T) {
	source, err := os.ReadFile("wordpress.go")
	if err != nil {
		t.Fatalf("read wordpress.go: %v", err)
	}
	body := string(source)
	at := strings.Index(body, "func runWPSecret(")
	if at < 0 {
		t.Fatal("runWPSecret is gone")
	}
	rest := body[at:]
	if end := strings.Index(rest, "\nfunc "); end > 0 {
		rest = rest[:end]
	}
	if !strings.Contains(rest, `"--quiet"`) {
		t.Fatal("runWPSecret no longer passes --quiet, so wp-cli echoes the assembled command line with the secret in it")
	}
	if !strings.Contains(rest, `"--prompt="+promptArg`) {
		t.Fatal("runWPSecret no longer names the prompted argument")
	}
	if !strings.Contains(rest, "redact(out, secret)") {
		t.Fatal("runWPSecret returns wp-cli's output unredacted, and the prompt line carries the secret")
	}
}
