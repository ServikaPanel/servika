package mail

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The config file the old template produced: correct PHP, but with the option
// names Roundcube 1.7 ignores.
const legacyRoundcubeConfig = `<?php
$config = [];
$config['db_dsnw'] = 'mysql://roundcube:secret@localhost/roundcube';
$config['default_host'] = 'localhost';
$config['default_port'] = 143;
$config['smtp_server']  = 'localhost';
$config['smtp_port']    = 587;
$config['smtp_user']    = '%u';
$config['smtp_pass']    = '%p';
`

func writeRoundcubeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.inc.php")
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatalf("write config: %v", err)
	}
	previous := roundcubeConfigPath
	roundcubeConfigPath = func() string { return path }
	t.Cleanup(func() { roundcubeConfigPath = previous })
	return path
}

// A config written by the old template must gain smtp_host. The old lines stay:
// Roundcube already ignores them, and rewriting an operator's file is a larger
// risk than leaving a dead assignment behind.
func TestHealRoundcubeSMTPAddsTheMissingSetting(t *testing.T) {
	path := writeRoundcubeConfig(t, legacyRoundcubeConfig)
	HealRoundcubeSMTP(context.Background())

	repaired, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	body := string(repaired)
	for _, want := range []string{
		"$config['smtp_host'] = 'tls://localhost:587';",
		"$config['imap_host'] = 'localhost:143';",
		"verify_peer_name",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the repaired config does not contain %q", want)
		}
	}
	if !strings.Contains(body, "$config['smtp_server']") {
		t.Error("the repair removed the old assignment instead of overriding it")
	}
	// The patch has to come AFTER the old assignments or it cannot override them.
	if strings.Index(body, "smtp_host") < strings.LastIndex(body, "smtp_server") {
		t.Error("the patch was placed before the old assignments, so they would win")
	}
}

func TestHealRoundcubeSMTPIsIdempotent(t *testing.T) {
	path := writeRoundcubeConfig(t, legacyRoundcubeConfig)
	HealRoundcubeSMTP(context.Background())
	afterFirst, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	HealRoundcubeSMTP(context.Background())
	afterSecond, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(afterFirst) != string(afterSecond) {
		t.Errorf("a second run changed the file again (%d bytes then %d)", len(afterFirst), len(afterSecond))
	}
	if count := strings.Count(string(afterSecond), "$config['smtp_host']"); count != 1 {
		t.Errorf("smtp_host is assigned %d times, want 1", count)
	}
}

// A host installed from the corrected template must not be touched at all.
func TestHealRoundcubeSMTPLeavesACorrectConfigAlone(t *testing.T) {
	const current = `<?php
$config = [];
$config['imap_host'] = 'localhost:143';
$config['smtp_host'] = 'tls://localhost:587';
`
	path := writeRoundcubeConfig(t, current)
	HealRoundcubeSMTP(context.Background())

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(after) != current {
		t.Errorf("a correct config was modified:\n%s", after)
	}
}

// Roundcube may not be installed. The heal runs during startup, so it must not
// disturb it.
func TestHealRoundcubeSMTPIsSilentWithoutRoundcube(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent", "config.inc.php")
	previous := roundcubeConfigPath
	roundcubeConfigPath = func() string { return missing }
	t.Cleanup(func() { roundcubeConfigPath = previous })

	HealRoundcubeSMTP(context.Background())

	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("the heal created a config where Roundcube is not installed: %v", err)
	}
}

// A file that does not end in a newline would otherwise have its last line
// joined to the first line of the patch, producing a syntax error that takes
// webmail down entirely.
func TestHealRoundcubeSMTPDoesNotJoinAnUnterminatedLastLine(t *testing.T) {
	path := writeRoundcubeConfig(t, "<?php\n$config = [];\n$config['smtp_server'] = 'localhost';")
	HealRoundcubeSMTP(context.Background())

	repaired, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for line := range strings.SplitSeq(string(repaired), "\n") {
		if strings.Contains(line, "smtp_server") && strings.Contains(line, "Servika repair") {
			t.Errorf("the last line was joined to the patch: %q", line)
		}
	}
	if !strings.Contains(string(repaired), "'localhost';\n") {
		t.Error("the last line lost its own terminator")
	}
}

// The repaired file is executed by PHP, so a syntax error takes webmail down
// entirely. Both the terminated and the unterminated last-line case are checked.
func TestHealRoundcubeSMTPProducesValidPHP(t *testing.T) {
	if _, err := exec.LookPath("php"); err != nil {
		t.Skip("php is unavailable")
	}
	for name, start := range map[string]string{
		"terminated":   legacyRoundcubeConfig,
		"unterminated": "<?php\n$config = [];\n$config['smtp_server'] = 'localhost';",
	} {
		t.Run(name, func(t *testing.T) {
			path := writeRoundcubeConfig(t, start)
			HealRoundcubeSMTP(context.Background())
			if out, err := exec.Command("php", "-l", path).CombinedOutput(); err != nil {
				body, _ := os.ReadFile(path)
				t.Fatalf("the repaired config is not valid PHP: %s\n%s", out, body)
			}
			// Evaluate it and check the values Roundcube would actually read.
			script := filepath.Join(t.TempDir(), "check.php")
			if err := os.WriteFile(script, []byte(
				`<?php require $argv[1]; echo $config['smtp_host'], "|", $config['imap_host'], "|",`+
					` var_export($config['smtp_conn_options']['ssl']['verify_peer_name'], true);`), 0o600); err != nil {
				t.Fatalf("write checker: %v", err)
			}
			out, err := exec.Command("php", script, path).CombinedOutput()
			if err != nil {
				t.Fatalf("evaluate the repaired config: %v\n%s", err, out)
			}
			if got, want := string(out), "tls://localhost:587|localhost:143|false"; got != want {
				t.Errorf("the repaired config evaluates to %q, want %q", got, want)
			}
		})
	}
}
