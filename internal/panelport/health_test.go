package panelport

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A listen address that names no host, or names a wildcard, still has to produce
// a URL something can connect to. An empty host is not a URL at all and 0.0.0.0
// is not a portable destination, so both become loopback, which is where the
// panel answers in every one of those forms.
func TestTheHealthURLIsDialableForEveryListenForm(t *testing.T) {
	for _, tc := range []struct {
		host string
		want string
	}{
		{"", "http://127.0.0.1:8080/healthz"},
		{"0.0.0.0", "http://127.0.0.1:8080/healthz"},
		{"::", "http://127.0.0.1:8080/healthz"},
		{"[::]", "http://127.0.0.1:8080/healthz"},
		{"*", "http://127.0.0.1:8080/healthz"},
		{"127.0.0.1", "http://127.0.0.1:8080/healthz"},
		{"::1", "http://[::1]:8080/healthz"},
		{"[::1]", "http://[::1]:8080/healthz"},
	} {
		if got := HealthURL(tc.host, 8080); got != tc.want {
			t.Errorf("HealthURL(%q, 8080) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

// The four states the heal has to tell apart. Getting any of them wrong is worse
// than doing nothing: adding an absent line makes a setting the installer drops
// again on the next update, and rewriting a value this does not understand
// destroys something an operator wrote deliberately.
func TestSetEnvHealthPort(t *testing.T) {
	for _, tc := range []struct {
		name        string
		text        string
		wantChanged bool
		wantLine    string
	}{
		{
			name:        "a stale port is corrected",
			text:        "SERVIKA_LISTEN=127.0.0.1:9080\nSERVIKA_HEALTH=http://127.0.0.1:8080/healthz\n",
			wantChanged: true,
			wantLine:    "SERVIKA_HEALTH=http://127.0.0.1:9080/healthz",
		},
		{
			name:        "a matching port is left byte for byte",
			text:        "SERVIKA_HEALTH=\"http://127.0.0.1:9080/healthz\"\n",
			wantChanged: false,
			wantLine:    "SERVIKA_HEALTH=\"http://127.0.0.1:9080/healthz\"",
		},
		{
			name:        "an absent assignment is not added",
			text:        "SERVIKA_LISTEN=127.0.0.1:9080\n",
			wantChanged: false,
		},
		{
			name:        "a commented assignment is not an assignment",
			text:        "# SERVIKA_HEALTH=http://127.0.0.1:8080/healthz\n",
			wantChanged: false,
			wantLine:    "# SERVIKA_HEALTH=http://127.0.0.1:8080/healthz",
		},
		{
			name:        "an unparsable value is left alone",
			text:        "SERVIKA_HEALTH=not a url\n",
			wantChanged: false,
			wantLine:    "SERVIKA_HEALTH=not a url",
		},
		{
			name:        "a URL with no explicit port is left alone",
			text:        "SERVIKA_HEALTH=http://127.0.0.1/healthz\n",
			wantChanged: false,
			wantLine:    "SERVIKA_HEALTH=http://127.0.0.1/healthz",
		},
		{
			name:        "an IPv6 host keeps its brackets and its address",
			text:        "SERVIKA_HEALTH=http://[::1]:8080/healthz\n",
			wantChanged: true,
			wantLine:    "SERVIKA_HEALTH=http://[::1]:9080/healthz",
		},
		{
			name:        "a deliberate host and path survive the port change",
			text:        "SERVIKA_HEALTH=http://127.0.0.2:8080/some/other/path\n",
			wantChanged: true,
			wantLine:    "SERVIKA_HEALTH=http://127.0.0.2:9080/some/other/path",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, changed, err := SetEnvHealthPort(tc.text, 9080)
			if err != nil {
				t.Fatal(err)
			}
			if changed != tc.wantChanged {
				t.Fatalf("changed = %v, want %v\n%s", changed, tc.wantChanged, out)
			}
			if tc.wantLine != "" && !strings.Contains(out, tc.wantLine+"\n") {
				t.Errorf("the result does not carry %q:\n%s", tc.wantLine, out)
			}
			if !tc.wantChanged && !strings.Contains(out, envHealthName) &&
				strings.Contains(tc.text, envHealthName) {
				t.Errorf("an assignment disappeared:\n%s", out)
			}
			if !strings.Contains(tc.text, envHealthName) && strings.Contains(out, envHealthName) {
				t.Errorf("an absent assignment was added:\n%s", out)
			}
		})
	}
}

// The last assignment wins, matching what systemd's EnvironmentFile does and
// what ReadEnvListen already does for the setting beside it. Reading the first
// would report a URL the tools are not using whenever an old line sits above.
func TestReadEnvHealthTakesTheLastAssignment(t *testing.T) {
	text := "SERVIKA_HEALTH=http://127.0.0.1:8080/healthz\n" +
		"# SERVIKA_HEALTH=http://127.0.0.1:1/healthz\n" +
		"SERVIKA_HEALTH=http://127.0.0.1:9080/healthz\n"
	if got := ReadEnvHealth(text); got != "http://127.0.0.1:9080/healthz" {
		t.Errorf("ReadEnvHealth = %q", got)
	}
	if got := ReadEnvHealth("SERVIKA_LISTEN=127.0.0.1:8080\n"); got != "" {
		t.Errorf("ReadEnvHealth on a file without the setting = %q", got)
	}
}

// The heal end to end, against a real file, because the part that can go wrong
// on a live host is the replacement rather than the string work: this file holds
// every panel secret and the server refuses to boot without three of them.
func TestTheHealRepairsAStalePortAndLeavesTheRestAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env")
	original := "SERVIKA_LISTEN=127.0.0.1:9080\n" +
		"SERVIKA_JWT_SECRET=not-a-real-secret\n" +
		"SERVIKA_HEALTH=http://127.0.0.1:8080/healthz\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SERVIKA_ENV_FILE", path)

	HealHealthURL()

	healed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(healed), "SERVIKA_HEALTH=http://127.0.0.1:9080/healthz\n") {
		t.Errorf("the stale port was not corrected:\n%s", healed)
	}
	if !strings.Contains(string(healed), "SERVIKA_JWT_SECRET=not-a-real-secret\n") {
		t.Errorf("an unrelated setting was lost:\n%s", healed)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the replacement widened the mode to %04o", mode)
	}

	// A second run must write nothing, or every boot would rewrite the file that
	// holds the secrets for no reason.
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	HealHealthURL()
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Errorf("a second run rewrote a file that was already correct")
	}
}

// An installation that never had the setting must not gain one. The installer
// rewrites this file from a managed list, so a line it does not write is dropped
// on the next update, and a setting that vanishes weeks later is worse than one
// that was never added.
func TestTheHealDoesNotCreateTheSetting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env")
	original := "SERVIKA_LISTEN=127.0.0.1:9080\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SERVIKA_ENV_FILE", path)

	HealHealthURL()

	healed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(healed) != original {
		t.Errorf("the heal touched a file with no %s:\n%s", envHealthName, healed)
	}
}

// An installation with nothing to repair says nothing. The heal runs on every
// boot, so a complaint about SERVIKA_LISTEN for a file that carries no health
// setting at all would be a line in the journal forever, describing a problem
// that does not exist.
func TestTheHealIsSilentWhenThereIsNothingToRepair(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env")
	if err := os.WriteFile(path, []byte("SERVIKA_LISTEN=not-an-address\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SERVIKA_ENV_FILE", path)

	var captured strings.Builder
	log.SetOutput(&captured)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	HealHealthURL()

	if captured.Len() != 0 {
		t.Errorf("the heal complained about a file it had no reason to touch: %s", captured.String())
	}
}
