package provisioner

import (
	"database/sql"
	"log"
	"os"
	"strings"
)

// webmailMarker identifies a vhost that already serves webmail, and
// autoconfigMarker one that already answers the mail client auto-configuration
// paths. Tests keep both in step with the blocks themselves.
const (
	webmailMarker    = "location ^~ /webmail/"
	autoconfigMarker = "location = /.well-known/autoconfig/mail/config-v1.1.xml"
	discoveryMarker  = "# Mail client auto-configuration hostnames for"
)

// normalVhostMarker identifies a vhost rendered from the ordinary template. The
// suspended, redirect-only and operator-written shapes do not carry the deny
// blocks, and none of them can hold these blocks either, so a vhost without this
// marker must not be re-rendered: it would never gain them and the repair would
// reload nginx for nothing on every boot.
const normalVhostMarker = "# ---- Deny CGI and interpreter scripts ----"

// nginxConfDir is where the domain vhosts live, and rerenderVhost is what the
// repair calls for a domain whose vhost lacks a block. Both are variables so a
// test can put vhost files in a writable directory and observe which domains are
// re-rendered; nothing outside tests changes them.
var (
	nginxConfDir  = "/etc/nginx/conf.d"
	rerenderVhost = RerenderVhost
)

// healTLSVhostBlocksOnStartup writes the blocks that are computed at render time
// into the vhosts of domains that already existed before those blocks did.
//
// Both blocks are produced on every render, but existing vhost files are not
// rewritten on their own: without this pass a customer would have to wait for the
// next certificate renewal or PHP version change before webmail answered on their
// own domain, or before a mail client could configure itself.
//
// Only vhosts that would actually gain something are re-rendered, so the pass
// costs one small file read per domain when there is nothing to do. The ordinary
// render path is used, which keeps its nginx validation and rollback.
func healTLSVhostBlocksOnStartup() {
	if packageDB == nil {
		return
	}
	// Webmail is only expected where Roundcube is installed; the auto-configuration
	// endpoints are answered by the panel itself and are always expected.
	required := []string{autoconfigMarker}
	if webmailInstalled() {
		required = append(required, webmailMarker)
	}

	rows, err := packageDB.Query(
		`SELECT id, system_user, domain_name, parent_domain_id,
		        COALESCE(cert_path,''), COALESCE(key_path,'')
		   FROM domains ORDER BY id`)
	if err != nil {
		log.Printf("vhost block repair: could not list domains: %v", err)
		return
	}
	type domain struct {
		id         int64
		systemUser string
		domainName string
		parentID   sql.NullInt64
		certPath   string
		keyPath    string
	}
	var domains []domain
	for rows.Next() {
		var item domain
		if err := rows.Scan(&item.id, &item.systemUser, &item.domainName, &item.parentID,
			&item.certPath, &item.keyPath); err != nil {
			log.Printf("vhost block repair: could not read domain row: %v", err)
			continue
		}
		domains = append(domains, item)
	}
	rowsErr := rows.Err()
	_ = rows.Close()
	if rowsErr != nil {
		log.Printf("vhost block repair: domain iteration failed: %v", rowsErr)
		return
	}

	updated, failed := 0, 0
	for _, item := range domains {
		configPath := nginxConfDir + "/dom_" + item.systemUser + ".conf"
		if item.parentID.Valid {
			configPath = addonVhostConfigPath(item.systemUser, item.domainName)
		}
		// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
		content, err := os.ReadFile(configPath)
		if err != nil {
			continue // no vhost yet; the first render will carry the blocks
		}
		body := string(content)
		// Both blocks are rendered onto the TLS vhost only, and only into the
		// ordinary shape. Anything else can never gain them.
		if !strings.Contains(body, "listen 443 ssl") || !strings.Contains(body, normalVhostMarker) {
			continue
		}
		// The auto-configuration hostnames are conditional on the certificate
		// naming them, so the marker is only expected where that holds. Adding it
		// to the shared list would re-render every domain whose certificate omits
		// the names on every boot, and never satisfy the check.
		expected := required
		if certValid(item.certPath, item.keyPath, 0, discoverySANHosts(item.domainName)...) {
			expected = append(append([]string{}, required...), discoveryMarker)
		}
		if !missingAnyBlock(body, expected) {
			continue
		}
		if err := rerenderVhost(packageDB, item.id); err != nil {
			log.Printf("vhost block repair: %s vhost update failed: %v", item.domainName, err)
			failed++
			continue
		}
		updated++
	}
	if updated > 0 {
		log.Printf("vhost block repair: %d domain vhosts brought up to date", updated)
	}
	if failed > 0 {
		log.Printf("vhost block repair: %d of %d domains failed, retry scheduled for next startup", failed, len(domains))
	}
}

// missingAnyBlock reports whether the vhost body lacks at least one of the
// markers it is expected to carry.
func missingAnyBlock(body string, required []string) bool {
	for _, marker := range required {
		if !strings.Contains(body, marker) {
			return true
		}
	}
	return false
}
