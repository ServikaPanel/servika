package provisioner

import (
	"net"
	"strings"

	"servika/internal/config"
)

// panelFrameAncestors builds the CSP frame-ancestors allowlist that authorizes the
// Servika panel to iframe-preview a tenant site. It always includes 'self', the
// panel's public IPv4 on :8443, and a custom panel domain with active TLS over
// HTTPS. X-Frame-Options is not used: it cannot grant a different origin (the
// panel) permission to frame the tenant.
func panelFrameAncestors() string {
	sources := []string{"'self'"}
	seen := map[string]bool{"'self'": true}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			sources = append(sources, s)
		}
	}
	// config answers the environment-and-interfaces half; the database fallback
	// below stays here because config cannot reach the database.
	ip := config.PublicIPv4()
	if net.ParseIP(ip).To4() == nil {
		ip = ""
		if packageDB != nil {
			var dbIP string
			if err := packageDB.QueryRow(`SELECT COALESCE(ipv4,'') FROM domains WHERE ipv4<>'' ORDER BY id LIMIT 1`).Scan(&dbIP); err == nil {
				if dbIP = strings.TrimSpace(dbIP); net.ParseIP(dbIP).To4() != nil {
					ip = dbIP
				}
			}
		}
	}
	if ip != "" {
		add("https://" + ip + ":8443")
	}
	if packageDB != nil {
		var domain, sslStatus string
		if err := packageDB.QueryRow(`SELECT COALESCE(custom_domain,''), ssl_status FROM panel_settings WHERE id=1`).Scan(&domain, &sslStatus); err == nil {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if domain != "" && sslStatus == "active" && ValidateDomain(domain) == nil {
				add("https://" + domain)
				add("https://" + domain + ":8443")
			}
		}
	}
	return strings.Join(sources, " ")
}

// framePolicyHeader emits the enforced clickjacking policy as an nginx add_header
// line at the given indent. frame-ancestors is always enforced; when upgradeHTTPS
// is set (TLS vhost with HdrCSPUpgrade) it also folds in upgrade-insecure-requests,
// replacing the previously separate CSP header.
func framePolicyHeader(indent string, upgradeHTTPS bool) string {
	policy := "frame-ancestors " + panelFrameAncestors()
	if upgradeHTTPS {
		policy += "; upgrade-insecure-requests"
	}
	return indent + "add_header Content-Security-Policy \"" + policy + "\" always;\n"
}
