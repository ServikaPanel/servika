package provisioner

import (
	"log"
	"os"
	"strings"

	"servika/internal/httpx"
)

const (
	panelProxyTrustSentinel = "# SERVIKA-PANEL-PROXY-TRUST v1"
	panelSecLimitsPath      = "/etc/nginx/conf.d/00-servika-seclimits.conf"
)

// readProxySecret returns the persistent secret (>=32 chars), or "".
func readProxySecret() string {
	b, err := os.ReadFile(httpx.ProxySecretPath)
	if err != nil {
		return ""
	}
	if t := strings.TrimSpace(string(b)); len(t) >= 32 {
		return t
	}
	return ""
}

// HealPanelProxyTrustOnStartup hardens the panel vhost (skips silently when it
// is not present on this host):
//  1. append the shared X-Servika-Proxy "<secret>" after every X-Real-IP line,
//     so a tenant reaching :8080 directly cannot forge X-Real-IP (see ClientIP),
//  2. deny /api/v1/internal/pma-redeem from outside (pma-signon hits :8080 directly),
//  3. slowloris: client_body_timeout 3600s -> 60s,
//  4. limit_conn: per-IP concurrent-connection ceiling.
//
// FAIL-SAFE: if nginx -t fails everything is rolled back and the secret file is
// NOT written, so ClientIP keeps its old loopback-trust behaviour and nobody is
// locked out.
func HealPanelProxyTrustOnStartup() {
	original, err := os.ReadFile(panelVhostPath)
	if err != nil {
		return // panel is not installed on this host
	}
	content := string(original)
	hardenSecretVhostPerms() // secret must not leak: _panel.conf 0640 root:nginx

	// Preserve an existing secret (no rotation on reboot); otherwise generate one.
	secret := readProxySecret()
	if secret == "" {
		secret = httpx.NewProxySecret()
	}
	if secret == "" {
		log.Printf("panel proxy-trust heal: could not generate a secret, skipped")
		return
	}
	wanted := `proxy_set_header X-Servika-Proxy "` + secret + `";`

	content = injectProxyTrust(content, wanted)

	nginxChanged := content != string(original)
	if nginxChanged {
		// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
		if e := os.WriteFile(panelVhostPath, []byte(content), 0o640); e != nil {
			log.Printf("panel proxy-trust heal: could not write vhost: %v", e)
			return
		}
		hardenSecretVhostPerms()
		if output, e := tenantCommand("nginx", "-t").CombinedOutput(); e != nil {
			// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
			_ = os.WriteFile(panelVhostPath, original, 0o640) // ROLL BACK
			log.Printf("panel proxy-trust heal: nginx -t failed, vhost restored: %s", strings.TrimSpace(string(output)))
			return
		}
	}

	// FAIL-SAFE: if X-Servika-Proxy was not actually injected (no X-Real-IP
	// anchor), do NOT write the secret, so ClientIP keeps loopback-trust and
	// nobody is locked out.
	if !strings.Contains(content, wanted) {
		log.Printf("panel proxy-trust heal: no X-Real-IP anchor, secret not written (fail-safe)")
		return
	}
	if e := os.WriteFile(httpx.ProxySecretPath, []byte(secret+"\n"), 0o600); e != nil {
		log.Printf("panel proxy-trust heal: could not write secret: %v", e)
		if nginxChanged {
			// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
			_ = os.WriteFile(panelVhostPath, original, 0o640)
			_, _ = tenantCommand("systemctl", "reload", "nginx").CombinedOutput()
		}
		return
	}
	_ = os.Chmod(httpx.ProxySecretPath, 0o600)

	if nginxChanged {
		if output, e := tenantCommand("systemctl", "reload", "nginx").CombinedOutput(); e != nil {
			log.Printf("panel proxy-trust heal: nginx reload failed: %s", strings.TrimSpace(string(output)))
			return
		}
	}
	log.Printf("panel proxy-trust heal: X-Servika-Proxy + pma-redeem deny + slowloris timeout applied")
}

// injectProxyTrust applies the four vhost edits and returns the new content.
//
// The secret is not a parameter: `wanted` is the whole `proxy_set_header` line
// with the secret already in it, and rotation safety comes from dropping every
// existing X-Servika-Proxy line rather than from comparing secrets. Passing the
// bare secret as well invited a second, unchecked place for it to be written.
func injectProxyTrust(content, wanted string) string {
	// (1) X-Servika-Proxy injection (idempotent + secret-rotation safe).
	if !strings.Contains(content, wanted) {
		var out []string
		for line := range strings.SplitSeq(content, "\n") {
			if strings.Contains(line, "X-Servika-Proxy") {
				continue // drop the old secret line
			}
			out = append(out, line)
			if strings.Contains(line, "proxy_set_header X-Real-IP $remote_addr;") {
				indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
				out = append(out, indent+wanted)
			}
		}
		content = strings.Join(out, "\n")
	}
	// (2) pma-redeem denied from outside.
	if !strings.Contains(content, "location = /api/v1/internal/pma-redeem") {
		deny := "    # internal only: reachable only by the local pma-signon (direct :8080); denied from outside\n" +
			"    location = /api/v1/internal/pma-redeem { deny all; return 403; }\n\n"
		if i := strings.Index(content, "    location /api/ {"); i >= 0 {
			content = content[:i] + deny + content[i:]
		}
	}
	// (3) slowloris timeout.
	content = strings.Replace(content, "client_body_timeout 3600s;", "client_body_timeout 60s;", 1)
	// (4) limit_conn: per-IP concurrent-connection ceiling.
	ensureLimitZone()
	if !strings.Contains(content, "limit_conn servika_panel") {
		if i := strings.Index(content, "client_body_timeout 60s;"); i >= 0 {
			end := i + len("client_body_timeout 60s;")
			content = content[:end] + "\n    limit_conn servika_panel 50;  # per-IP concurrent-connection ceiling (slowloris defense)" + content[end:]
		}
	}
	// Stamp the sentinel so future runs stay idempotent.
	if !strings.Contains(content, panelProxyTrustSentinel) {
		content = panelProxyTrustSentinel + "\n" + content
	}
	return content
}

// hardenSecretVhostPerms: _panel.conf carries the X-Servika-Proxy secret, so it
// must not be world-readable (a tenant could read and forge it). 0640 root:nginx
// lets the nginx master (root) read it while a tenant (other) cannot. Applied
// unconditionally on every startup (idempotent).
func hardenSecretVhostPerms() {
	_, _ = tenantCommand("chgrp", "nginx", panelVhostPath).CombinedOutput()
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	_ = os.Chmod(panelVhostPath, 0o640)
}

// ensureLimitZone writes the http-context zone that limit_conn needs into its
// own conf.d file (00- prefix so it loads before _panel.conf). The zone alone is
// valid nginx.
func ensureLimitZone() {
	wanted := "limit_conn_zone $binary_remote_addr zone=servika_panel:10m;\n"
	if b, err := os.ReadFile(panelSecLimitsPath); err == nil && strings.Contains(string(b), "zone=servika_panel") {
		return
	}
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	_ = os.WriteFile(panelSecLimitsPath, []byte("# Servika security limits (managed)\n"+wanted), 0o644)
}
