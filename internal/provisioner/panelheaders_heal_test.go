package provisioner

import (
	"os"
	"strings"
	"testing"
)

// healPanelVhostHeadersOnStartup repairs the panel's own vhost in three ways: a
// hardened vhost still answering to `_` gets the panel's own server name, one
// with the old strict policy gains frame-src and object-src, and one never
// hardened gets the header block after its server name. Every rewrite is
// validated and reloaded, and a refusal puts the previous file back. These tests
// pin each repair and each rollback.

const (
	oldPanelStrictCSP = "script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: blob:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'self'"
	panelCacheHeader  = "        add_header Cache-Control \"public\";"
)

// panelVhost builds a panel vhost with the given server_name line, with or
// without the hardening sentinel, and with a strict policy when csp is set.
func panelVhost(serverName string, hardened bool, csp string) string {
	var body strings.Builder
	body.WriteString("server {\n    listen 8443 ssl;\n    ")
	body.WriteString(serverName)
	body.WriteString("\n")
	if hardened {
		body.WriteString("    " + panelSecSentinel + "\n")
	}
	if csp != "" {
		body.WriteString("    add_header Content-Security-Policy \"default-src 'self'; ")
		body.WriteString(csp)
		body.WriteString("; base-uri 'self'\" always;\n")
	}
	body.WriteString("    location /assets/ {\n" + panelCacheHeader + "\n    }\n}\n")
	return body.String()
}

var (
	hardenedUnderBareName = panelVhost("server_name _;", true, "")
	hardenedWithOldPolicy = panelVhost("server_name _servika_panel_;", true, oldPanelStrictCSP)
	neverHardened         = panelVhost("server_name _servika_panel_;", false, "")
	panelReloaded         = [][]string{{"nginx", "-t"}, {"systemctl", "reload", "nginx"}}
)

func TestThePanelVhostIsRepairedAndReloaded(t *testing.T) {
	cases := []struct {
		name  string
		vhost string
		want  []string
	}{
		{"a hardened vhost answering to _ gets the panel's own server name", hardenedUnderBareName,
			[]string{"    server_name _servika_panel_;\n"}},
		{"a hardened vhost with the old strict policy gains frame-src and object-src", hardenedWithOldPolicy,
			[]string{"connect-src 'self'; frame-src https: http:; frame-ancestors 'self'; object-src 'none'; base-uri 'self'"}},
		{"a vhost never hardened gets the header block after its server name", neverHardened,
			[]string{"server_name _servika_panel_;\n    " + panelSecSentinel + "\n",
				"add_header Content-Security-Policy \"" + panelStrictCSP + "\" always;",
				panelCacheHeader + "\n        add_header X-Content-Type-Options \"nosniff\" always;"}},
		{"the bare server name anchors the block when the panel's own is absent", panelVhost("server_name _;", false, ""),
			[]string{"server_name _;\n    " + panelSecSentinel + "\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withPanelHardening(t, tc.vhost)
			commands := withCommands(t)

			healPanelVhostHeadersOnStartup()

			assertVhostCarries(t, readString(t, f.vhost), tc.want, nil)
			assertArgvs(t, commands.argvs(), panelReloaded)
		})
	}
}

func TestAPanelVhostWithNothingToRepairIsLeftAlone(t *testing.T) {
	cases := []struct {
		name  string
		vhost string
	}{
		{"there is no panel vhost", ""},
		{"the hardened vhost is current", panelVhost("server_name _servika_panel_;", true, "")},
		{"the vhost has neither server name", panelVhost("server_name panel.example.com;", false, "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withPanelHardening(t, tc.vhost)
			commands := withCommands(t)

			healPanelVhostHeadersOnStartup()

			if tc.vhost != "" && readString(t, f.vhost) != tc.vhost {
				t.Errorf("the vhost was rewritten:\n%s", readString(t, f.vhost))
			}
			assertArgvs(t, commands.argvs(), [][]string{})
		})
	}
}

// The header block is the one repair whose failed reload does not put the old
// file back: nginx accepted the new file, so the next reload serves it.
func TestAPanelRepairNginxRefusesIsRolledBack(t *testing.T) {
	cases := []struct {
		name     string
		vhost    string
		fail     []string
		restored bool
	}{
		{"the server name fails validation", hardenedUnderBareName, []string{"nginx", "-t"}, true},
		{"the server name fails to reload", hardenedUnderBareName, []string{"systemctl", "reload", "nginx"}, true},
		{"the policy fails validation", hardenedWithOldPolicy, []string{"nginx", "-t"}, true},
		{"the policy fails to reload", hardenedWithOldPolicy, []string{"systemctl", "reload", "nginx"}, true},
		{"the header block fails validation", neverHardened, []string{"nginx", "-t"}, true},
		{"the header block fails to reload", neverHardened, []string{"systemctl", "reload", "nginx"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withPanelHardening(t, tc.vhost)
			withCommands(t, tc.fail)

			healPanelVhostHeadersOnStartup()

			if restored := readString(t, f.vhost) == tc.vhost; restored != tc.restored {
				t.Errorf("the previous vhost is back = %v, want %v", restored, tc.restored)
			}
		})
	}
}

func TestAPanelVhostThatCannotBeRewrittenRunsNoCommand(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only file")
	}
	for name, vhost := range map[string]string{
		"the server name":  hardenedUnderBareName,
		"the policy":       hardenedWithOldPolicy,
		"the header block": neverHardened,
	} {
		t.Run(name, func(t *testing.T) {
			f := withPanelHardening(t, vhost)
			if err := os.Chmod(f.vhost, 0o444); err != nil {
				t.Fatal(err)
			}
			commands := withCommands(t)

			healPanelVhostHeadersOnStartup()

			if readString(t, f.vhost) != vhost {
				t.Error("a read-only vhost changed")
			}
			assertArgvs(t, commands.argvs(), [][]string{})
		})
	}
}
