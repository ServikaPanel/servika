package provisioner

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"servika/internal/config"
)

// A tenant application listens on a loopback port and is published here. The
// panel owns both sides of that contract: internal/apps validates the mount path
// and allocates the port, and this file turns the pair into nginx locations.

// upgradeMapConf is loaded before any domain vhost by the 00- prefix, matching
// how the cache zone and its log format are shipped.
func upgradeMapConf() string { return config.NginxUpgradeMapConf() }

// upgradeMapBody defines the variable a proxy needs to pass a WebSocket upgrade
// through. Without it `proxy_set_header Connection $connection_upgrade` names an
// undefined variable and nginx refuses the whole configuration.
func upgradeMapBody() string {
	return `# Managed automatically by Servika. DO NOT EDIT.
# Application proxies pass "Connection: upgrade" only when the client asked for
# an upgrade; on an ordinary request the header must be "close" instead.
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
`
}

// ensureUpgradeMap writes the map file when it is missing or has drifted.
func ensureUpgradeMap() error {
	path := upgradeMapConf()
	body := upgradeMapBody()
	// #nosec G304 -- a fixed system configuration path this package owns.
	if current, err := os.ReadFile(path); err == nil && string(current) == body {
		return nil
	}
	// #nosec G306 -- root-owned nginx configuration its daemon must read; it holds no secret.
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		return fmt.Errorf("write the upgrade map: %w", err)
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell).
	_, _ = systemCommand("restorecon", path).CombinedOutput()
	return nil
}

// appProxy is one published application.
type appProxy struct {
	Name  string
	Mount string
	Port  int
}

// reProxyMount repeats internal/apps' own mount rule at the point the directive
// is EMITTED. The stored value was validated when it was written, but a render
// happens later and from a different code path, and a guard at the store is
// advisory: the state it checked is not the state that ends up serving.
var reProxyMount = regexp.MustCompile(`^/([A-Za-z0-9._~-]+/)*$`)

// appProxyPort is the range internal/apps allocates from. A row outside it is
// not rendered, so a hand-edited port cannot make nginx proxy to a service the
// panel does not manage.
const (
	appProxyPortMin = 30000
	appProxyPortMax = 30999
)

// readAppProxies returns the applications published on one scope: subdomainID 0
// is the domain itself.
//
// A row that fails the checks here is SKIPPED and logged rather than failing the
// whole render, because one bad application must not take the domain's own site
// off the air.
func readAppProxies(db *sql.DB, domainID, subdomainID int64) []appProxy {
	if db == nil || domainID <= 0 {
		return nil
	}
	rows, err := db.Query(
		`SELECT name, mount_path, port FROM apps
		 WHERE domain_id=? AND COALESCE(subdomain_id,0)=? AND enabled=1
		 ORDER BY LENGTH(mount_path) DESC, id`, domainID, subdomainID)
	if err != nil {
		log.Printf("app proxy: read applications of domain %d: %v", domainID, err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	var out []appProxy
	for rows.Next() {
		var proxy appProxy
		if err := rows.Scan(&proxy.Name, &proxy.Mount, &proxy.Port); err != nil {
			log.Printf("app proxy: read an application row of domain %d: %v", domainID, err)
			return nil
		}
		if !reProxyMount.MatchString(proxy.Mount) {
			log.Printf("app proxy: skipping application %q of domain %d: invalid mount %q", proxy.Name, domainID, proxy.Mount)
			continue
		}
		if proxy.Port < appProxyPortMin || proxy.Port > appProxyPortMax {
			log.Printf("app proxy: skipping application %q of domain %d: port %d is outside the managed range", proxy.Name, domainID, proxy.Port)
			continue
		}
		out = append(out, proxy)
	}
	if err := rows.Err(); err != nil {
		log.Printf("app proxy: read applications of domain %d: %v", domainID, err)
		return nil
	}
	return out
}

// renderAppProxies builds the location blocks for a scope.
//
// The prefix is `^~`, which beats both `location /` and every regular-expression
// location. That is what stops a request under the mount falling through to the
// PHP handler: without it, `/api/index.php` would be served by PHP-FPM out of the
// document root instead of reaching the application.
func renderAppProxies(proxies []appProxy) string {
	if len(proxies) == 0 {
		return ""
	}
	var body strings.Builder
	body.WriteString("\n    # ---- Applications (managed by the panel) ----\n")
	for _, proxy := range proxies {
		fmt.Fprintf(&body, `    location ^~ %[1]s {
        proxy_pass http://127.0.0.1:%[2]d;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 60s;
        proxy_buffering off;
    }
`, proxy.Mount, proxy.Port)
	}
	return body.String()
}

// appOwnsRoot reports whether an application is mounted at "/", which means the
// vhost must not also emit its own `location /`.
func appOwnsRoot(proxies []appProxy) bool {
	for _, proxy := range proxies {
		if proxy.Mount == "/" {
			return true
		}
	}
	return false
}

// AppProxyBlocks returns the rendered locations and whether an application holds
// the root mount. It is exported for the subdomain package, which renders its own
// server blocks rather than going through renderAndReload.
func AppProxyBlocks(db *sql.DB, domainID, subdomainID int64) (string, bool) {
	proxies := readAppProxies(db, domainID, subdomainID)
	return renderAppProxies(proxies), appOwnsRoot(proxies)
}
