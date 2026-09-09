// WAF (ModSecurity v3 + OWASP CRS) — per-domain / per-plan application layer.
//
// Design:
//   - Module loading is GLOBAL but HARMLESS: nothing changes until a vhost says
//     "modsecurity on" (per-domain opt-in). WAF can be enabled without affecting
//     existing sites.
//   - Effective setting = domain override (non-NULL/non-0) > plan default > off.
//   - Every vhost render (renderAndReload → buildModSec) from the effective setting:
//     (a) WAF active + module loaded → refreshes per-domain modsec conf + injects
//     "modsecurity on; modsecurity_rules_file <conf>;" into the server block,
//     (b) active but module NOT loaded → GRACEFUL skip (logs, doesn't break vhost),
//     (c) inactive → clears per-domain conf and injects nothing.
//     WAF self-heals on every render; an explicit WAFApply(db, id) trigger also exists.
package provisioner

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	wafModsecDir  = "/etc/nginx/modsec"
	wafDomainsDir = "/etc/nginx/modsec/domains"
	wafModulePath = "/usr/lib64/nginx/modules/ngx_http_modsecurity_module.so"
	wafNginxConf  = "/etc/nginx/nginx.conf"
)

// reWafSK guards the per-domain modsec conf file path against injection. sk (system_user)
// is produced by SlugFromDomain as "c_" + [a-z0-9_]. WAF is silently skipped for non-matching sk.
var reWafSK = regexp.MustCompile(`^c_[a-z0-9_]{1,60}$`)

// WAFModuleLoaded reports whether the ModSecurity module is LOADED in the main context.
// nginx -t must be able to recognize the "modsecurity" directive, which requires both
// (a) the module .so exists AND (b) it is load_module'd in the nginx.conf main context.
// Without both, writing "modsecurity on" into a vhost would break nginx -t — this gate prevents that.
func WAFModuleLoaded() bool {
	if _, err := os.Stat(wafModulePath); err != nil {
		return false
	}
	b, err := os.ReadFile(wafNginxConf)
	if err != nil {
		return false
	}
	return strings.Contains(string(b), "ngx_http_modsecurity_module.so")
}

// WAFEffective resolves the effective WAF setting for a domain (domain override + plan default).
// active=false means WAF is not applied. engine is "On" (block) or "DetectionOnly" (log only).
// paranoia is clamped to 1..4.
func WAFEffective(db *sql.DB, sk string) (active bool, engine string, paranoia int) {
	paranoia = 1
	if db == nil {
		return false, "", paranoia
	}
	var dEn, dPL sql.NullInt64
	var dMode sql.NullString
	var pEn, pPL int
	var pMode string
	err := db.QueryRow(
		`SELECT d.waf_enabled, d.waf_mode, d.waf_paranoia,
		        COALESCE(p.waf_enabled,0), COALESCE(p.waf_mode,'on'), COALESCE(p.waf_paranoia,1)
		 FROM domains d LEFT JOIN service_plans p ON p.id = d.plan_id
		 WHERE d.system_user = ? AND d.parent_domain_id IS NULL`, sk).
		Scan(&dEn, &dMode, &dPL, &pEn, &pMode, &pPL)
	if err != nil {
		return false, "", paranoia
	}
	enabled := pEn
	if dEn.Valid {
		enabled = int(dEn.Int64)
	}
	mode := strings.ToLower(strings.TrimSpace(pMode))
	if dMode.Valid && strings.TrimSpace(dMode.String) != "" {
		mode = strings.ToLower(strings.TrimSpace(dMode.String))
	}
	pl := pPL
	if dPL.Valid && dPL.Int64 > 0 {
		pl = int(dPL.Int64)
	}
	if pl < 1 {
		pl = 1
	}
	if pl > 4 {
		pl = 4
	}
	if enabled != 1 || mode == "off" || mode == "" {
		return false, "", pl
	}
	engine = "On"
	if mode == "detect" || mode == "detectiononly" {
		engine = "DetectionOnly"
	}
	return true, engine, pl
}

// wafDomainConfWrite generates /etc/nginx/modsec/domains/<sk>.conf (engine + paranoia).
// The file Includes the shared modsecurity.conf + CRS crs-setup.conf + all CRS rules;
// SecRuleEngine and the paranoia level are overridden per-domain. An empty <sk>.custom.conf
// is also created for future per-domain custom rules/exclusions (MVP: empty placeholder).
func wafDomainConfWrite(sk, engine string, paranoia int) error {
	if !reWafSK.MatchString(sk) {
		return fmt.Errorf("invalid system user: %q", sk)
	}
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(wafDomainsDir, 0755); err != nil {
		return err
	}
	custom := filepath.Join(wafDomainsDir, sk+".custom.conf")
	if _, err := os.Stat(custom); err != nil {
		// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
		_ = os.WriteFile(custom,
			[]byte("# Servika WAF — "+sk+" custom rules / exclusions (optional, MVP: empty).\n"+
				"# Example CRS exclusion: SecRuleRemoveById 942100\n"), 0644)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Servika WAF — %s — AUTO-GENERATED, do not edit by hand.\n", sk)
	b.WriteString("# Mode + paranoia are managed from the panel (domain override > plan default).\n")
	fmt.Fprintf(&b, "Include %s/modsecurity.conf\n", wafModsecDir)
	fmt.Fprintf(&b, "SecRuleEngine %s\n", engine)
	fmt.Fprintf(&b, "Include %s/crs/crs-setup.conf\n", wafModsecDir)
	// Set the paranoia level BEFORE CRS rules (including 901-INITIALIZATION) are loaded.
	// The id:900000 paranoia SecAction in crs-setup.conf.example is commented out BY DEFAULT;
	// using id:900000 here does not conflict and is the documented CRS mechanism.
	fmt.Fprintf(&b,
		"SecAction \"id:900000,phase:1,pass,nolog,t:none,"+
			"setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d\"\n",
		paranoia, paranoia)
	fmt.Fprintf(&b, "Include %s/crs/rules/*.conf\n", wafModsecDir)
	fmt.Fprintf(&b, "Include %s\n", custom)
	confPath := filepath.Join(wafDomainsDir, sk+".conf")
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	return os.WriteFile(confPath, []byte(b.String()), 0644)
}

// buildModSec returns the WAF directive block to write into the vhost server context (called
// inside renderAndReload on every render). Side effect: when WAF is active + module loaded,
// refreshes the per-domain conf; when inactive, clears it. NEVER breaks the vhost — returns ""
// on any problem.
func buildModSec(sk string) string {
	if !reWafSK.MatchString(sk) {
		return "" // path-injection guard
	}
	confPath := filepath.Join(wafDomainsDir, sk+".conf")
	active, engine, paranoia := WAFEffective(packageDB, sk)
	if !active {
		_ = os.Remove(confPath) // inactive — clean up per-domain conf
		return ""
	}
	if !WAFModuleLoaded() {
		log.Printf("waf: %s is WAF-enabled but ModSecurity module is NOT loaded — WAF SKIPPED (vhost intact). Run 'servika-waf-setup'.", sk)
		return ""
	}
	if err := wafDomainConfWrite(sk, engine, paranoia); err != nil {
		log.Printf("waf: %s per-domain conf write failed: %v — WAF SKIPPED (vhost intact)", sk, err)
		return ""
	}
	return "    # ---- WAF (ModSecurity v3 + OWASP CRS) — panel-managed ----\n" +
		"    modsecurity on;\n" +
		"    modsecurity_rules_file " + confPath + ";\n"
}

// WAFApply re-applies WAF settings (domain override + plan default) for a domain.
// The per-domain modsec conf is refreshed and the vhost is re-rendered (nginx -t gate + rollback).
// Called by create + plan-change + panel WAF settings save hooks.
func WAFApply(db *sql.DB, domainID int64) error {
	return RerenderVhost(db, domainID)
}

// HealWAFOnStartup validates module status at boot and refreshes per-domain modsec confs
// for every WAF-enabled (non-suspended) domain. When the module is not loaded it WARNS
// and leaves vhosts untouched (graceful). Vhosts are already re-rendered by HealVhostsOnStartup
// (buildModSec runs from there too); this function provides an explicit status log + conf
// refresh (belt-and-suspenders).
func HealWAFOnStartup() {
	if packageDB == nil {
		return
	}
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	_ = os.MkdirAll(wafDomainsDir, 0755)
	module := WAFModuleLoaded()
	rows, err := packageDB.Query(`SELECT DISTINCT system_user FROM domains WHERE COALESCE(suspended,0)=0 AND parent_domain_id IS NULL`)
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()
	var activeCount int
	for rows.Next() {
		var sk string
		if rows.Scan(&sk) != nil {
			continue
		}
		active, engine, paranoia := WAFEffective(packageDB, sk)
		if !active {
			continue
		}
		activeCount++
		if !module {
			continue // graceful: vhost render already skips WAF
		}
		if err := wafDomainConfWrite(sk, engine, paranoia); err != nil {
			log.Printf("waf heal: %s conf write: %v", sk, err)
		}
	}
	if err := rows.Err(); err != nil {
		// A short list leaves some tenants without their WAF configuration and
		// makes the count reported below understate what is enabled.
		log.Printf("waf heal: could not read the domain list: %v", err)
	}
	if activeCount > 0 && !module {
		log.Printf("waf heal: %d WAF-enabled domains but ModSecurity module is NOT LOADED — "+
			"'servika-waf-setup' must be run (WAF is currently PASSIVE, vhosts intact)", activeCount)
	} else {
		log.Printf("waf heal: module=%v, WAF-enabled domains=%d", module, activeCount)
	}
}
