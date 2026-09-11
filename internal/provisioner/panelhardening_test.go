package provisioner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// HealPanelProxyTrustOnStartup injects the proxy secret into the panel vhost and
// writes the secret file only after nginx has accepted the vhost. Every path in
// which the header might not reach nginx leaves the secret file unwritten, so
// ClientIP keeps trusting loopback and nobody is locked out.

const panelVhostFixture = `server {
    listen 8443 ssl;
    client_body_timeout 3600s;
    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
`

type panelHardeningFixture struct{ vhost, limits, secret string }

// withPanelHardening points the heal at temporary files. An empty vhost body
// leaves the vhost absent.
func withPanelHardening(t *testing.T, vhost string) panelHardeningFixture {
	t.Helper()
	dir := t.TempDir()
	f := panelHardeningFixture{
		vhost:  filepath.Join(dir, "_panel.conf"),
		limits: filepath.Join(dir, "00-servika-seclimits.conf"),
		secret: filepath.Join(dir, "proxy.secret"),
	}
	previousVhost, previousLimits, previousSecret := panelVhostPath, panelSecLimitsPath, proxySecretPath
	panelVhostPath, panelSecLimitsPath, proxySecretPath = f.vhost, f.limits, f.secret
	t.Cleanup(func() {
		panelVhostPath, panelSecLimitsPath, proxySecretPath = previousVhost, previousLimits, previousSecret
	})
	if vhost != "" {
		if err := os.WriteFile(f.vhost, []byte(vhost), 0o640); err != nil {
			t.Fatalf("write the panel vhost: %v", err)
		}
	}
	return f
}

func readString(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	return string(body)
}

func TestAHostWithoutThePanelVhostIsLeftAlone(t *testing.T) {
	f := withPanelHardening(t, "")
	commands := withCommands(t)

	HealPanelProxyTrustOnStartup()

	assertPathsGone(t, f.secret)
	assertArgvs(t, commands.argvs(), [][]string{})
}

func TestThePanelVhostIsHardenedAndTheSecretWrittenAfterNginxAccepts(t *testing.T) {
	f := withPanelHardening(t, panelVhostFixture)
	commands := withCommands(t)

	HealPanelProxyTrustOnStartup()

	secret := strings.TrimSpace(readString(t, f.secret))
	if len(secret) != 64 {
		t.Fatalf("the secret is %d characters, want a 64-character hex secret", len(secret))
	}
	if info, err := os.Stat(f.secret); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the secret file mode is not 0600: %v, %v", info, err)
	}
	vhost := readString(t, f.vhost)
	for _, want := range []string{
		`proxy_set_header X-Servika-Proxy "` + secret + `";`,
		"location = /api/v1/internal/pma-redeem { deny all; return 403; }",
		"client_body_timeout 60s;",
		"limit_conn servika_panel 50;",
		panelProxyTrustSentinel,
	} {
		if !strings.Contains(vhost, want) {
			t.Errorf("the hardened vhost does not carry %q:\n%s", want, vhost)
		}
	}
	if !strings.Contains(readString(t, f.limits), "zone=servika_panel") {
		t.Error("the limit_conn zone was not written")
	}
	for _, argv := range [][]string{{"chgrp", "nginx", f.vhost}, {"nginx", "-t"}, {"systemctl", "reload", "nginx"}} {
		if !commands.ran(argv...) {
			t.Errorf("%q was not run: %q", argv, commands.argvs())
		}
	}
}

func TestAnExistingProxySecretIsKept(t *testing.T) {
	f := withPanelHardening(t, panelVhostFixture)
	existing := strings.Repeat("a1", 20)
	if err := os.WriteFile(f.secret, []byte(existing+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withCommands(t)

	HealPanelProxyTrustOnStartup()

	if !strings.Contains(readString(t, f.vhost), `"`+existing+`"`) {
		t.Error("the vhost does not carry the existing secret")
	}
	if got := strings.TrimSpace(readString(t, f.secret)); got != existing {
		t.Errorf("the secret was rotated to %q", got)
	}
}

func TestARejectedPanelVhostIsRestoredAndNoSecretIsWritten(t *testing.T) {
	f := withPanelHardening(t, panelVhostFixture)
	commands := withCommands(t, []string{"nginx", "-t"})

	HealPanelProxyTrustOnStartup()

	if got := readString(t, f.vhost); got != panelVhostFixture {
		t.Errorf("the vhost was not restored:\n%s", got)
	}
	assertPathsGone(t, f.secret)
	if commands.ran("systemctl", "reload", "nginx") {
		t.Error("nginx was reloaded after it rejected the vhost")
	}
}

// Without an X-Real-IP line the header is never injected, so writing the secret
// would make ClientIP distrust nginx itself.
func TestWithoutAnXRealIPAnchorTheSecretIsNotWritten(t *testing.T) {
	vhost := strings.Replace(panelVhostFixture, "        proxy_set_header X-Real-IP $remote_addr;\n", "", 1)
	f := withPanelHardening(t, vhost)
	commands := withCommands(t)

	HealPanelProxyTrustOnStartup()

	assertPathsGone(t, f.secret)
	if !strings.Contains(readString(t, f.vhost), "client_body_timeout 60s;") {
		t.Error("the other hardening edits were not applied")
	}
	if !commands.ran("nginx", "-t") || commands.ran("systemctl", "reload", "nginx") {
		t.Errorf("want nginx -t without a reload, ran %q", commands.argvs())
	}
}

func TestASecretThatCannotBeWrittenRollsTheVhostBack(t *testing.T) {
	f := withPanelHardening(t, panelVhostFixture)
	proxySecretPath = filepath.Join(filepath.Dir(f.secret), "missing-directory", "proxy.secret")
	commands := withCommands(t)

	HealPanelProxyTrustOnStartup()

	if got := readString(t, f.vhost); got != panelVhostFixture {
		t.Errorf("the vhost was not rolled back:\n%s", got)
	}
	if !commands.ran("systemctl", "reload", "nginx") {
		t.Error("nginx was not reloaded onto the rolled-back vhost")
	}
}

// A reload that fails after the secret is written leaves both in place.
func TestAFailedReloadKeepsTheSecretAndTheHardenedVhost(t *testing.T) {
	f := withPanelHardening(t, panelVhostFixture)
	withCommands(t, []string{"systemctl", "reload", "nginx"})

	HealPanelProxyTrustOnStartup()

	secret := strings.TrimSpace(readString(t, f.secret))
	if !strings.Contains(readString(t, f.vhost), `"`+secret+`"`) {
		t.Error("the hardened vhost was not kept")
	}
}

func TestASecondRunChangesNothingAndReloadsNothing(t *testing.T) {
	f := withPanelHardening(t, panelVhostFixture)
	withCommands(t)
	HealPanelProxyTrustOnStartup()
	hardened, secret := readString(t, f.vhost), readString(t, f.secret)

	commands := withCommands(t)
	HealPanelProxyTrustOnStartup()

	if readString(t, f.vhost) != hardened || readString(t, f.secret) != secret {
		t.Error("a second run changed the vhost or the secret")
	}
	if commands.ran("nginx", "-t") || commands.ran("systemctl", "reload", "nginx") {
		t.Errorf("a second run validated or reloaded nginx: %q", commands.argvs())
	}
}
