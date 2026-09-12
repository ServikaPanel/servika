package subdomain

import (
	"context"
	"database/sql"
	"strings"

	"servika/internal/logx"
	"servika/internal/provisioner"
)

// reasonPHPVersionLocked is returned when a subdomain is asked for a PHP version
// the server cannot actually serve it. It is a CODE rather than a sentence
// because the interface ships twelve languages and wording produced here could
// not be translated.
const reasonPHPVersionLocked = "php_version_locked_to_parent"

// phpVersionLocked reports whether a subdomain is stuck on its parent domain's
// PHP version.
//
// A tenant that has been moved to its own PHP-FPM service runs ONE master, built
// from one PHP binary, and provisioner.PHPSocketFor answers with that tenant's
// single socket no matter which version is asked for. A subdomain pool inside
// that master (provisioner.ApplySubdomainFPM) does not change this: a pool
// scopes the document root, not the interpreter.
//
// So a request for a different version cannot be carried out, and the panel must
// not pretend otherwise. Writing the requested value to the database while the
// vhost keeps pointing at the parent's socket is the worst of the options: the
// screen says 7.4, the server runs 8.1, and the tenant finds out when a script
// breaks. The lever that does work is the PARENT domain's version, which
// reinstalls the tenant unit and takes every subdomain with it.
//
// An empty request means "leave it alone" and is never locked.
func phpVersionLocked(tenantFPMActive bool, parentVersion, requested string) bool {
	requested = strings.TrimSpace(requested)
	if !tenantFPMActive || requested == "" {
		return false
	}
	return !provisioner.SamePHPVersion(parentVersion, requested)
}

// HealSubdomainPHPVersions corrects rows the panel recorded before it refused to
// record a version it could not serve.
//
// It runs at startup rather than in the updater, because it repairs state on an
// EXISTING installation and has to run on every boot for tenants that move to
// their own PHP-FPM service later. It only ever writes the version the server is
// already serving, so it cannot change what a site runs; it makes the record
// agree with it.
func HealSubdomainPHPVersions(db *sql.DB) {
	if db == nil {
		return
	}
	rows, err := db.QueryContext(context.Background(), `
		SELECT s.id, s.fqdn, s.php_version, d.system_user, COALESCE(d.php_version,'')
		  FROM subdomains s JOIN domains d ON d.id = s.domain_id`)
	if err != nil {
		logx.Errorf("heal subdomain PHP versions: %v", err)
		return
	}
	type drift struct {
		id     int64
		fqdn   string
		served string
	}
	var corrections []drift
	for rows.Next() {
		var id int64
		var fqdn, recorded, systemUser, parentVersion string
		if err := rows.Scan(&id, &fqdn, &recorded, &systemUser, &parentVersion); err != nil {
			// A dropped row is a subdomain whose recorded PHP version is never
			// corrected, so the panel keeps showing a version it does not serve.
			logx.Warnf("php lock heal: skipping an unreadable subdomain row: %v", err)
			continue
		}
		if parentVersion == "" {
			continue
		}
		if phpVersionLocked(tenantFPMActive(systemUser), parentVersion, recorded) {
			corrections = append(corrections, drift{id: id, fqdn: fqdn, served: parentVersion})
		}
	}
	_ = rows.Err()
	_ = rows.Close()

	for _, correction := range corrections {
		if _, err := db.Exec(`UPDATE subdomains SET php_version=? WHERE id=?`,
			correction.served, correction.id); err != nil {
			logx.Errorf("heal subdomain PHP version %s: %v", correction.fqdn, err)
			continue
		}
		logx.Warnf("subdomain %s was recorded on a PHP version its tenant does not serve; corrected to %s",
			correction.fqdn, correction.served)
	}
}
