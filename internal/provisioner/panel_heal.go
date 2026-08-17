package provisioner

import (
	"log"
	"os"
	"regexp"
	"strings"
)

const (
	panelIndexNoCacheSentinel   = "# SERVIKA-PANEL-INDEX-NO-CACHE v1"
	panelLoginRateLimitSentinel = "# SERVIKA-LOGIN-RATELIMIT v1"
)

// panelStrictCSP is the policy the panel's own SPA is served under.
//
// It exists once because it was written three times and one copy had already
// drifted: the block healPanelVhostHeadersOnStartup inserts on a fresh install
// was missing object-src 'none', so until the next panel restart the retrofit
// pass had not yet put it back. assets/nginx/_panel.conf cannot import this, so
// TestTheTemplateAndTheHealServeTheSamePolicy holds the template to it instead.
//
// The relaxed variants in the template belong to phpMyAdmin and Roundcube,
// which need 'unsafe-inline' and 'unsafe-eval'. They have no Go copy and so no
// way to drift.
const panelStrictCSP = "default-src 'self'; script-src 'self'; " +
	"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
	"img-src 'self' data: blob:; font-src 'self' data: https://fonts.gstatic.com; " +
	"connect-src 'self'; frame-src https: http:; frame-ancestors 'self'; " +
	"object-src 'none'; base-uri 'self'; form-action 'self'"

var panelIndexLocationPattern = regexp.MustCompile(`(?m)    location / \{\s*\n\s*try_files \$uri \$uri/ /index\.html;\s*\n\s*\}`)

const panelLoginRateLimitHTTPBlock = `# SERVIKA-LOGIN-RATELIMIT v1
# Login endpoint defense at the nginx layer. The application also enforces
# a per-IP failed-login lockout in middleware.LoginRateLimit.
limit_req_zone $binary_remote_addr zone=servika_login:10m rate=20r/m;
`

const panelLoginRateLimitLocations = `    location = /api/v1/auth/login {
        limit_req zone=servika_login burst=8 nodelay;
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
    }

    location = /api/v1/customer/login {
        limit_req zone=servika_login burst=8 nodelay;
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
    }
`

func healPanelLoginRateLimitOnStartup() {
	original, err := os.ReadFile(panelVhostPath)
	if err != nil {
		return
	}
	content := string(original)
	if strings.Contains(content, panelLoginRateLimitSentinel) {
		return
	}
	apiAnchor := "    location /api/ {"
	apiIndex := strings.Index(content, apiAnchor)
	if apiIndex < 0 {
		log.Printf("panel login rate limit repair: canonical API location was not found")
		return
	}
	updated := panelLoginRateLimitHTTPBlock + "\n" + content[:apiIndex] + panelLoginRateLimitLocations + "\n" + content[apiIndex:]
	// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(panelVhostPath, []byte(updated), 0644); err != nil {
		log.Printf("panel login rate limit repair: could not write vhost: %v", err)
		return
	}
	if output, err := tenantCommand("nginx", "-t").CombinedOutput(); err != nil {
		// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
		_ = os.WriteFile(panelVhostPath, original, 0644)
		log.Printf("panel login rate limit repair: nginx configuration failed, vhost restored: %s", strings.TrimSpace(string(output)))
		return
	}
	if output, err := tenantCommand("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
		log.Printf("panel login rate limit repair: nginx reload failed: %s", strings.TrimSpace(string(output)))
	}
}

func healPanelIndexNoCacheOnStartup() {
	original, err := os.ReadFile(panelVhostPath)
	if err != nil {
		return
	}
	content := string(original)
	if strings.Contains(content, panelIndexNoCacheSentinel) {
		return
	}
	if !panelIndexLocationPattern.MatchString(content) {
		log.Printf("panel cache repair: canonical SPA location was not found")
		return
	}

	replacement := `    location / {
        ` + panelIndexNoCacheSentinel + `
        try_files $uri $uri/ /index.html;
        add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
        add_header Pragma "no-cache" always;
        add_header Expires 0 always;
        # This location defines add_header, so repeat inherited security headers.
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), interest-cohort=()" always;
        add_header Content-Security-Policy "` + panelStrictCSP + `" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    }`
	updated := panelIndexLocationPattern.ReplaceAllStringFunc(content, func(string) string { return replacement })
	// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(panelVhostPath, []byte(updated), 0644); err != nil {
		log.Printf("panel cache repair: could not write vhost: %v", err)
		return
	}
	if output, err := tenantCommand("nginx", "-t").CombinedOutput(); err != nil {
		// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
		_ = os.WriteFile(panelVhostPath, original, 0644)
		log.Printf("panel cache repair: nginx configuration failed, vhost restored: %s", strings.TrimSpace(string(output)))
		return
	}
	if output, err := tenantCommand("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
		log.Printf("panel cache repair: nginx reload failed: %s", strings.TrimSpace(string(output)))
	}
}
