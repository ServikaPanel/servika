package provisioner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withNginxTree points the heal at a temporary nginx.conf and conf.d, and
// records the commands it runs.
func withNginxTree(t *testing.T, mainConf string, fail ...[]string) (dir string, commands *commandRecorder) {
	t.Helper()
	root := t.TempDir()
	confDir := filepath.Join(root, "conf.d")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(root, "nginx.conf")
	if err := os.WriteFile(main, []byte(mainConf), 0o644); err != nil {
		t.Fatal(err)
	}
	setForTest(t, &nginxConfDir, confDir)
	setForTest(t, &nginxMainConf, main)
	return confDir, withCommands(t, fail...)
}

// nginx defaults server_tokens to on, and the directive was written only by the
// opt-in servika-optimize pass, so a stock installation told every visitor of
// the panel and of every hosted site the exact nginx build.
func TestTheVersionBannerIsTurnedOffOnAStockInstallation(t *testing.T) {
	confDir, commands := withNginxTree(t, "http {\n    client_max_body_size 10240m;\n}\n")

	HealServerTokens()

	body, err := os.ReadFile(filepath.Join(confDir, serverTokensFile))
	if err != nil {
		t.Fatalf("the drop-in was not written: %v", err)
	}
	if !strings.Contains(string(body), "server_tokens off;") {
		t.Errorf("the drop-in does not turn the banner off:\n%s", body)
	}
	if !commands.ran("nginx", "-t") || !commands.ran("systemctl", "reload", "nginx") {
		t.Errorf("the change was not validated and reloaded: %q", commands.argvs())
	}
}

// nginx refuses a duplicate server_tokens, and refusing is fatal to the whole
// server, so a host that already carries the directive is left alone. Verified
// against nginx 1.29: a second definition in a conf.d file answers
// `"server_tokens" directive is duplicate` and the test fails.
func TestADeclaredDirectiveIsNotDuplicated(t *testing.T) {
	cases := []struct {
		name     string
		mainConf string
		existing map[string]string
	}{
		{
			name:     "the optimize pass wrote it",
			mainConf: "http {\n}\n",
			existing: map[string]string{"00-servika-perf.conf": "server_tokens off;\ntcp_nodelay on;\n"},
		},
		{
			name:     "the operator wrote it in nginx.conf",
			mainConf: "http {\n    server_tokens build;\n}\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			confDir, commands := withNginxTree(t, tc.mainConf)
			for name, body := range tc.existing {
				if err := os.WriteFile(filepath.Join(confDir, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			HealServerTokens()

			if _, err := os.Stat(filepath.Join(confDir, serverTokensFile)); err == nil {
				t.Error("a second server_tokens definition was written; nginx refuses to start on that")
			}
			if len(commands.argvs()) != 0 {
				t.Errorf("nginx was touched although nothing changed: %q", commands.argvs())
			}
		})
	}
}

// A commented mention is not a directive. The installer's own notes name the
// directive in a comment, and reading that as "already set" would leave the
// banner on for ever.
func TestACommentedMentionDoesNotCountAsDeclared(t *testing.T) {
	confDir, _ := withNginxTree(t, "http {\n    # server_tokens is written by servika-optimize\n}\n")

	HealServerTokens()

	if _, err := os.Stat(filepath.Join(confDir, serverTokensFile)); err != nil {
		t.Errorf("a commented mention stopped the heal: %v", err)
	}
}

// A second boot must not rewrite the file or reload nginx.
func TestASecondBootLeavesNginxAlone(t *testing.T) {
	confDir, commands := withNginxTree(t, "http {\n}\n")
	HealServerTokens()
	if _, err := os.Stat(filepath.Join(confDir, serverTokensFile)); err != nil {
		t.Fatalf("the first pass wrote nothing: %v", err)
	}
	before := len(commands.argvs())

	HealServerTokens()

	if got := len(commands.argvs()); got != before {
		t.Errorf("the second pass ran %d more commands: %q", got-before, commands.argvs())
	}
}

// A drop-in nginx refuses must not be left behind: it would stop nginx from
// starting at all, which is worse than the banner it removes.
func TestADropInNginxRefusesIsRemoved(t *testing.T) {
	confDir, _ := withNginxTree(t, "http {\n}\n", []string{"nginx", "-t"})

	HealServerTokens()

	if _, err := os.Stat(filepath.Join(confDir, serverTokensFile)); err == nil {
		t.Error("a drop-in that failed validation was left in place")
	}
}
