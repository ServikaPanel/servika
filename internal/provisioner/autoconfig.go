package provisioner

// Mail client auto-configuration on the customer's OWN domain.
//
// Thunderbird probes /.well-known/autoconfig/mail/config-v1.1.xml and Outlook
// POSTs /autodiscover/autodiscover.xml, and both try the mail domain itself
// before any autoconfig./autodiscover. subdomain. Serving them here means the
// domain's existing certificate already covers the request, so no extra A record
// and no extra certificate name is needed per domain. The panel decides what to
// answer, including whether the domain hosts mail at all.
//
// Like the webmail block, nothing here defines add_header, so both locations
// inherit the domain's own server-level security headers instead of silently
// dropping them.
const autoconfigNginx = `
    # ---- Mail client auto-configuration (answered by the panel) ----
    location = /.well-known/autoconfig/mail/config-v1.1.xml {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 15s;
    }

    # Outlook capitalises the path as /AutoDiscover/AutoDiscover.xml, so the
    # match is case-insensitive. proxy_pass may not carry a URI inside a regex
    # location, hence the rewrite to the canonical spelling the panel routes on.
    location ~* ^/autodiscover/autodiscover\.xml$ {
        rewrite ^ /autodiscover/autodiscover.xml break;
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 15s;
    }
`

// autoconfigBlock returns the block for a vhost.
//
// It is rendered only on the TLS vhost, by the same reasoning as webmail: these
// endpoints tell a client where to send a mailbox password, and a client that
// read them over plain HTTP would have taken that instruction from anyone on the
// path. Outlook refuses an unencrypted answer outright.
func autoconfigBlock() string { return autoconfigNginx }

// discoveryVhostNginx answers the two names a mail client looks for before it
// falls back to the domain itself.
//
// It is a server block of its own rather than two more names on the main vhost's
// server_name, for two reasons. A canonical www redirect narrows that
// server_name to a single host (VhostOpts.ServerNames), so names appended there
// would disappear the moment the customer turns the redirect on. And the site
// itself must not answer on a hostname it was never given: `location /` returns
// 404 so these names serve the auto-configuration XML and nothing else.
//
// There is no port 80 block. Both clients fetch these URLs over HTTPS, and the
// ACME challenge for the names is already answered by the port 80 catch-all
// (assets/nginx/_default80.conf) from the shared webroot.
// mtaSTSNginx serves the MTA-STS policy from mta-sts.<domain>.
//
// RFC 8461 fixes both the hostname and the path, so neither is a choice. The
// panel answers rather than a file on disk because the policy has to name the
// current MX and carry the id the _mta-sts TXT record advertises, and a stale
// file would be worse than none: a sender caches what it fetched.
const mtaSTSNginx = `
    # ---- MTA-STS policy (answered by the panel) ----
    location = /.well-known/mta-sts.txt {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 15s;
    }
`

const discoveryVhostNginx = `
# Mail client auto-configuration hostnames for {{.DomainName}}.
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name {{.DiscoveryHosts}};

    ssl_certificate     {{.CertPath}};
    ssl_certificate_key {{.KeyPath}};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
{{.DiscoveryBlocks}}
    location / { return 404; }

    access_log /var/log/nginx/{{.DomainName}}.access.log;
    error_log  /var/log/nginx/{{.DomainName}}.error.log warn;
}
`
