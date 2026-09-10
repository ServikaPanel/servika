package panelsettings

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"servika/internal/provisioner"
)

const panelDomainVhostPath = "/etc/nginx/conf.d/_panel_domain.conf"

const panelDomainVhostTemplate = `# Servika custom panel domain. Managed by the panel settings API.
server {
    listen 80;
    listen [::]:80;
    server_name %s;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name %s;

    ssl_certificate     ` + panelCertPath + `;
    ssl_certificate_key ` + panelKeyPath + `;
    ssl_protocols TLSv1.2 TLSv1.3;

    client_max_body_size 10240m;

    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 3600s;
    }

    location = /healthz {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
        proxy_pass https://127.0.0.1:8443;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
`

func writePortlessPanelVhost(domain string) error {
	// Serialised with every other nginx writer: `nginx -t` validates the whole
	// conf.d tree, so this sequence and a domain render at once each observe the
	// other's half-written file. See internal/provisioner/nginxlock.go.
	provisioner.LockNginx()
	defer provisioner.UnlockNginx()

	content := fmt.Sprintf(panelDomainVhostTemplate, domain, domain)
	backup, backupErr := os.ReadFile(panelDomainVhostPath)
	hadBackup := backupErr == nil

	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(panelDomainVhostPath, []byte(content), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
		if hadBackup {
			// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
			_ = os.WriteFile(panelDomainVhostPath, backup, 0o644)
		} else {
			_ = os.Remove(panelDomainVhostPath)
		}
		return fmt.Errorf("nginx configuration test failed: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
		return fmt.Errorf("nginx reload failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func removePortlessPanelVhost() {
	if _, err := os.Stat(panelDomainVhostPath); err != nil {
		return
	}
	provisioner.LockNginx()
	defer provisioner.UnlockNginx()

	_ = os.Remove(panelDomainVhostPath)
	_, _ = exec.Command("nginx", "-t").CombinedOutput()
	_, _ = exec.Command("systemctl", "reload", "nginx").CombinedOutput()
}
