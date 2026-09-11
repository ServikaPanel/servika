package provisioner

import "os"

// Webmail on the customer's OWN domain: https://customer.com/webmail/.
//
// Roundcube used to be reachable only through the panel's own 8443 vhost, so the
// address a hosting customer could be given was the panel hostname, or the bare
// server IP when the panel was opened by IP. What a hosting customer expects is
// their own domain, which is also what cPanel and Plesk serve.
//
// A path was chosen over a webmail.<domain> SUBDOMAIN on purpose: a subdomain
// needs both an extra A record and an extra name on the certificate for every
// domain, and if either is missing the browser shows a certificate warning. The
// domain's existing certificate (apex + www) already covers this path.
//
// TRADE-OFF: a site with a real /webmail directory is shadowed by the `^~`
// prefix match. cPanel reserves the same name.
const roundcubeRoot = "/opt/roundcube/public_html"

// webmailInstallRoot is the directory whose presence means Roundcube is
// installed. It is a variable so a test can decide that; nothing outside tests
// changes it, and the rendered block keeps naming roundcubeRoot.
var webmailInstallRoot = roundcubeRoot

// webmailNginx is the block added to a domain's own vhost.
//
// It mirrors the panel's block in assets/nginx/_panel.conf, which was built
// against a live Roundcube 1.7: the web root is public_html/, and skin and
// plugin assets are served through static.php with PATH_INFO rather than as
// files on disk. static.php therefore has to be matched BEFORE the
// extension-based static block, otherwise nginx treats it as a missing .css
// file and answers 404.
//
// The PHP-FPM pool is the roundcube pool, not the tenant's: this is one shared
// installation for every domain and cannot run under a customer identity.
//
// No location here defines add_header, so all of them inherit the domain's own
// server-level security headers. That keeps per-domain settings (HSTS above
// all, which a browser applies to the whole host) under the operator's control
// instead of hardcoding a policy into every vhost. The static block therefore
// relies on `expires` alone and gives up the `immutable` hint the panel block
// adds; Roundcube versions its asset URLs, so this costs one revalidation.
const webmailNginx = `
    # ---- Webmail (Roundcube), one shared installation for every domain ----
    location ^~ /webmail/ {
        alias ` + roundcubeRoot + `/;
        index index.php;

        # Roundcube's own sensitive directories. An alias does not apply the
        # bundled .htaccess files, so they are denied here.
        location ~ ^/webmail/(config|temp|logs|SQL|bin|tests)/ {
            deny all;
            return 404;
        }

        location ~ ^/webmail/static\.php(/.+)$ {
            fastcgi_pass unix:/run/php-fpm/roundcube.sock;
            fastcgi_param SCRIPT_FILENAME ` + roundcubeRoot + `/static.php;
            fastcgi_param PATH_INFO $1;
            fastcgi_param SCRIPT_NAME /webmail/static.php;
            include fastcgi_params;
            fastcgi_read_timeout 60s;
        }

        location ~ ^/webmail/(.+\.php)$ {
            alias ` + roundcubeRoot + `/$1;
            fastcgi_pass unix:/run/php-fpm/roundcube.sock;
            fastcgi_param SCRIPT_FILENAME ` + roundcubeRoot + `/$1;
            fastcgi_param SCRIPT_NAME /webmail/$1;
            include fastcgi_params;
            fastcgi_read_timeout 60s;
        }

        location ~ ^/webmail/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt|svg|woff2?|map))$ {
            alias ` + roundcubeRoot + `/$1;
            expires 7d;
        }
    }

    # /webmail without the trailing slash does not match the prefix above.
    location = /webmail { return 301 /webmail/; }
`

// webmailBlock returns the nginx block when Roundcube is installed, and an empty
// string otherwise, so a host without webmail does not get a dead path that
// answers 404 on every vhost.
func webmailBlock() string { return webmailBlockFor(webmailInstallRoot) }

func webmailBlockFor(root string) string {
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return ""
	}
	return webmailNginx
}

// webmailInstalled reports whether Roundcube is present on this host.
func webmailInstalled() bool {
	info, err := os.Stat(webmailInstallRoot)
	return err == nil && info.IsDir()
}
