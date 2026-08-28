// Package provisioner manages Linux users, nginx vhosts, multi-version PHP-FPM, and SSL/TLS for domains.
package provisioner

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"

	"servika/internal/config"
	"servika/internal/phpdefaults"
)

var (
	domainNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,251}\.[a-z]{2,24}$`)
	tenantUserPattern = regexp.MustCompile(`^c_[a-z0-9_]+$`)
	slugSan           = regexp.MustCompile(`[^a-z0-9]+`)
	packageDB         *sql.DB
)

const (
	cacheZoneName          = "servikacache"
	maxCertificateFileSize = 1 << 20
	cacheLogFormatName     = "servika_cache_status"
)

func cacheZoneDir() string { return config.NginxCacheDir() }

func cacheZoneConf() string { return config.NginxCacheConf() }

func cacheZoneTempConf() string { return config.NginxCacheTempConf() }

func certSystemBaseDir() string { return config.CertRoot() }

func cacheZoneBody() string {
	return `# Managed automatically by Servika. DO NOT EDIT.
# Vhosts use "fastcgi_cache servikacache"; this file provides the matching zone definition.
fastcgi_cache_path ` + cacheZoneDir() + ` levels=1:2 keys_zone=` + cacheZoneName + `:100m max_size=1g inactive=60m use_temp_path=off;
# Cache key defined once at http context so every vhost using the zone shares it.
# Separates scheme, method, host, and full request URI so distinct responses never collide.
fastcgi_cache_key "$scheme$request_method$host$request_uri";
`
}

func cacheLogFormatConf() string { return config.NginxCacheLogConf() }

func cacheLogFormatBody() string {
	return `# Managed automatically by Servika. DO NOT EDIT.
# Provides a minimal log format that records only the upstream cache status for FastCGI cache hit-rate metrics.
log_format ` + cacheLogFormatName + ` '$upstream_cache_status';
`
}

// PublicHTML returns the default tenant document root.
func PublicHTML(systemUser string) string {
	return filepath.Join("/home", systemUser, "public_html")
}

// SafeWebRootSubdirectory validates a document-root path relative to public_html.
func SafeWebRootSubdirectory(subdirectory string) (string, error) {
	rel := strings.Trim(strings.TrimSpace(subdirectory), "/")
	if rel == "" || rel == "." {
		return "", nil
	}
	if strings.Contains(rel, "..") || !regexp.MustCompile(`^[A-Za-z0-9._/-]+$`).MatchString(rel) {
		return "", fmt.Errorf("invalid web root")
	}
	return rel, nil
}

// AbsoluteWebRoot resolves a public_html-relative document root and rejects symlink escapes.
func AbsoluteWebRoot(systemUser, subdirectory string) (string, error) {
	if !tenantUserPattern.MatchString(systemUser) {
		return "", fmt.Errorf("invalid system user")
	}
	rel, err := SafeWebRootSubdirectory(subdirectory)
	if err != nil {
		return "", err
	}
	base := PublicHTML(systemUser)
	abs := base
	if rel != "" {
		abs = filepath.Clean(filepath.Join(base, rel))
	}
	if abs != base && !strings.HasPrefix(abs, base+string(os.PathSeparator)) {
		return "", fmt.Errorf("web root cannot leave public_html")
	}
	check := abs
	for check == base || strings.HasPrefix(check, base+string(os.PathSeparator)) {
		if real, err := filepath.EvalSymlinks(check); err == nil {
			if real != base && !strings.HasPrefix(real, base+string(os.PathSeparator)) {
				return "", fmt.Errorf("web root cannot leave public_html through a symlink")
			}
			break
		}
		if check == base {
			break
		}
		check = filepath.Dir(check)
	}
	return abs, nil
}

// WebRootSubdirectory returns the public_html-relative subdirectory for a stored web root.
func WebRootSubdirectory(systemUser, webRoot string) string {
	base := PublicHTML(systemUser)
	clean := filepath.Clean(strings.TrimSpace(webRoot))
	if clean == "." || clean == "" || clean == base {
		return ""
	}
	if rel, ok := strings.CutPrefix(clean, base+string(os.PathSeparator)); ok {
		return rel
	}
	return ""
}

// SafeWebRoot returns a safe absolute document root, falling back to public_html.
func SafeWebRoot(systemUser, webRoot string) string {
	sub := WebRootSubdirectory(systemUser, webRoot)
	abs, err := AbsoluteWebRoot(systemUser, sub)
	if err != nil {
		return PublicHTML(systemUser)
	}
	return abs
}

func AddonWebRoot(systemUser, domainName string) string {
	return filepath.Join("/home", systemUser, "domains", strings.ToLower(strings.TrimSpace(domainName)))
}

func addonVhostConfigPath(systemUser, domainName string) string {
	safeDomain := strings.ToLower(strings.TrimSpace(domainName))
	safeDomain = slugSan.ReplaceAllString(safeDomain, "_")
	safeDomain = strings.Trim(safeDomain, "_")
	return "/etc/nginx/conf.d/addon_" + systemUser + "_" + safeDomain + ".conf"
}

func safeAddonWebRoot(systemUser, domainName, webRoot string) string {
	base := filepath.Join("/home", systemUser, "domains")
	clean := filepath.Clean(strings.TrimSpace(webRoot))
	if clean != "" && clean != "." && strings.HasPrefix(clean, base+string(os.PathSeparator)) {
		return clean
	}
	return AddonWebRoot(systemUser, domainName)
}

func currentWebRoot(systemUser string) string {
	if packageDB == nil {
		return PublicHTML(systemUser)
	}
	var webRoot string
	if err := packageDB.QueryRow(`SELECT COALESCE(web_root,'') FROM domains WHERE system_user=? AND parent_domain_id IS NULL LIMIT 1`, systemUser).Scan(&webRoot); err != nil {
		return PublicHTML(systemUser)
	}
	return webRoot
}

// addonDomainInfo reports whether domainName is an addon/parked domain (its
// domains row carries a non-null parent_domain_id) and, when it is, returns the
// addon's own document root. Addon domains share the PARENT's system user, so the
// SSL writers' default dom_<system_user>.conf path would overwrite the parent
// domain's vhost and drop it from nginx entirely. Resolving the addon flag here
// lets every SSL path (issue, disable, startup heal) route an addon to its own
// addon_<system_user>_<domain>.conf instead.
//
// Fail-safe: when the DB is unavailable or the row is not an addon, it returns
// isAddon=false so behavior stays exactly as before — a false positive here would
// wrongly divert a real parent domain's vhost.
func addonDomainInfo(domainName string) (webRoot string, isAddon bool) {
	if packageDB == nil {
		return "", false
	}
	var parent sql.NullInt64
	var wr string
	if err := packageDB.QueryRow(
		`SELECT parent_domain_id, COALESCE(web_root,'') FROM domains WHERE domain_name=? LIMIT 1`,
		strings.ToLower(strings.TrimSpace(domainName))).Scan(&parent, &wr); err != nil || !parent.Valid {
		return "", false
	}
	return wr, true
}

var cacheZoneDefinitionPattern = regexp.MustCompile(`keys_zone\s*=\s*` + regexp.QuoteMeta(cacheZoneName) + `\s*:`)

// Init configures database-backed state and repairs managed server configuration.
func Init(db *sql.DB) {
	packageDB = db
	// Chicken-egg fix: guarantee per-user ACL (setfacl) and the RAR extractor (bsdtar) are
	// installed BEFORE HealHomePerms and the file manager RAR extraction rely on them. This
	// keeps per-user ACL isolation and RAR extraction ready on the very first update + restart.
	ensureArchiveTools()
	Ensure404Page()     // brand 404 page (root-owned; a tenant cannot modify it)
	EnsureBrandAssets() // Lottie animations + player (shared, served at /_srv/)
	healCacheZoneOnStartup()
	HealDefaultVhostsOnStartup() // port 80/443 catch-all vhosts, install-only until now
	// Before every other panel-vhost heal: a file nginx cannot bind makes each
	// of those heals fail its own nginx -t and revert work that was correct.
	HealPanelIPv6Listen()
	healPanelVhostHeadersOnStartup()
	healPanelLoginRateLimitOnStartup()
	HealPanelProxyTrustOnStartup() // :8080 proxy secret + pma-redeem deny + slowloris/limit_conn
	healPanelIndexNoCacheOnStartup()
	ensurePMAStartup()
	healVhostsOnStartup()
	healTLSVhostBlocksOnStartup() // webmail and mail auto-configuration on each customer's own domain
	HealNginxLogPerms()           // close /var/log/nginx to tenants (cross-tenant log reading)
	HealHomePerms()
	ensureFPMSELinuxFcontext()
	ensureHTTPDHomeBooleans()
	HealSSLCertPathsOnStartup()
	HealSSLVhost443OnStartup()
	// Before EnsureTenantFPMOnStartup: it starts the masters, and this decides
	// which file each of them opens.
	HealTenantFPMLogs()
	EnsureTenantFPMOnStartup()
	HealWAFOnStartup() // WAF: validate ModSecurity module status + refresh per-domain modsec confs for WAF-enabled domains
}

func healCacheZoneOnStartup() {
	changed, err := ensureCacheZone()
	if err != nil {
		log.Printf("servikacache repair: could not write zone configuration: %v", err)
		return
	}
	if !changed {
		return
	}
	if out, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
		log.Printf("servikacache repair: nginx configuration remains invalid, reload skipped: %s", strings.TrimSpace(string(out)))
		return
	}
	if out, err := exec.Command("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
		log.Printf("servikacache repair: nginx reload failed: %s", strings.TrimSpace(string(out)))
		return
	}
	log.Printf("servikacache repair: zone configuration restored and nginx reloaded")
}

func ensureCacheZone() (bool, error) {
	changed := false
	zoneDir := cacheZoneDir()
	zoneConf := cacheZoneConf()
	tempConf := cacheZoneTempConf()
	zoneBody := cacheZoneBody()
	if err := os.MkdirAll(zoneDir, 0700); err != nil {
		return false, fmt.Errorf("create cache directory: %w", err)
	}
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	if err := os.Chmod(filepath.Dir(zoneDir), 0o755); err != nil {
		return false, fmt.Errorf("set cache parent permissions: %w", err)
	}
	if uid, gid, err := uidGid("nginx"); err == nil {
		if err := os.Chown(zoneDir, uid, gid); err != nil {
			return false, fmt.Errorf("set cache directory ownership: %w", err)
		}
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_, _ = exec.Command("restorecon", "-R", zoneDir).CombinedOutput()

	if _, err := os.Stat(tempConf); err == nil {
		if err := os.Remove(tempConf); err != nil {
			return false, fmt.Errorf("remove temporary cache zone configuration: %w", err)
		}
		changed = true
	}

	if cacheZoneDefinedElsewhere() {
		if _, err := os.Stat(zoneConf); err == nil {
			if err := os.Remove(zoneConf); err != nil {
				return false, fmt.Errorf("remove duplicate managed cache zone configuration: %w", err)
			}
			changed = true
		}
		return changed, nil
	}

	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	if current, err := os.ReadFile(zoneConf); err == nil && string(current) == zoneBody {
		// Zone body unchanged; still ensure the log format file exists.
		return ensureCacheLogFormat(), nil
	}
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(zoneConf, []byte(zoneBody), 0644); err != nil {
		return false, fmt.Errorf("write cache zone configuration: %w", err)
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_, _ = exec.Command("restorecon", zoneConf).CombinedOutput()
	return ensureCacheLogFormat() || true, nil
}

// ensureCacheLogFormat writes the log_format definition file for cache status
// so that nginx vhosts can reference the servika_cache_status format. The file
// is prefixed 00- to load before any domain vhost in alphabetical glob order.
func ensureCacheLogFormat() bool {
	logFormatConf := cacheLogFormatConf()
	logFormatBody := cacheLogFormatBody()
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	if current, err := os.ReadFile(logFormatConf); err == nil && string(current) == logFormatBody {
		return false
	}
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(logFormatConf, []byte(logFormatBody), 0644); err != nil {
		log.Printf("servikacache repair: could not write cache log format: %v", err)
		return false
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_, _ = exec.Command("restorecon", logFormatConf).CombinedOutput()
	return true
}

// purgeFastCGICache removes all nginx FastCGI cache entries so that
// cache TTL and enable/disable changes take effect immediately on
// the next request instead of serving stale cached content.
func purgeFastCGICache(systemUser string) {
	dir := cacheZoneDir()
	if _, err := os.Stat(dir); err != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var purged int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Cache hierarchy: <dir>/<one-char>/<two-char>/<cache-file>
		oneCharDir := filepath.Join(dir, entry.Name())
		oneLevel, _ := os.ReadDir(oneCharDir)
		for _, one := range oneLevel {
			if !one.IsDir() {
				continue
			}
			twoCharDir := filepath.Join(oneCharDir, one.Name())
			twoLevel, _ := os.ReadDir(twoCharDir)
			for _, two := range twoLevel {
				if err := os.Remove(filepath.Join(twoCharDir, two.Name())); err == nil {
					purged++
				}
			}
		}
	}
	if purged > 0 {
		log.Printf("fastcgi cache: purged %d entries (%s)", purged, systemUser)
	}
}

func cacheZoneDefinedElsewhere() bool {
	files := []string{"/etc/nginx/nginx.conf"}
	if extra, err := filepath.Glob("/etc/nginx/conf.d/*.conf"); err == nil {
		files = append(files, extra...)
	}
	for _, filename := range files {
		if filename == cacheZoneConf() {
			continue
		}
		// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
		body, err := os.ReadFile(filename)
		if err == nil && cacheZoneDefinitionPattern.Match(body) {
			return true
		}
	}
	return false
}

type phpConfig struct {
	PoolDir string
	SockDir string
	Service string
	FPMBin  string
}

var phpMap = map[string]phpConfig{
	"7.4": {PoolDir: "/etc/opt/remi/php74/php-fpm.d", SockDir: "/var/opt/remi/php74/run/php-fpm", Service: "php74-php-fpm", FPMBin: "/opt/remi/php74/root/usr/sbin/php-fpm"},
	"8.0": {PoolDir: "/etc/opt/remi/php80/php-fpm.d", SockDir: "/var/opt/remi/php80/run/php-fpm", Service: "php80-php-fpm", FPMBin: "/opt/remi/php80/root/usr/sbin/php-fpm"},
	"8.1": {PoolDir: "/etc/opt/remi/php81/php-fpm.d", SockDir: "/var/opt/remi/php81/run/php-fpm", Service: "php81-php-fpm", FPMBin: "/opt/remi/php81/root/usr/sbin/php-fpm"},
	"8.2": {PoolDir: "/etc/opt/remi/php82/php-fpm.d", SockDir: "/var/opt/remi/php82/run/php-fpm", Service: "php82-php-fpm", FPMBin: "/opt/remi/php82/root/usr/sbin/php-fpm"},
	"8.3": {PoolDir: "/etc/php-fpm.d", SockDir: "/run/php-fpm", Service: "php-fpm", FPMBin: "/usr/sbin/php-fpm"},
	"8.4": {PoolDir: "/etc/opt/remi/php84/php-fpm.d", SockDir: "/var/opt/remi/php84/run/php-fpm", Service: "php84-php-fpm", FPMBin: "/opt/remi/php84/root/usr/sbin/php-fpm"},
	"8.5": {PoolDir: "/etc/opt/remi/php85/php-fpm.d", SockDir: "/var/opt/remi/php85/run/php-fpm", Service: "php85-php-fpm", FPMBin: "/opt/remi/php85/root/usr/sbin/php-fpm"},
	"8.6": {PoolDir: "/etc/opt/remi/php86/php-fpm.d", SockDir: "/var/opt/remi/php86/run/php-fpm", Service: "php86-php-fpm", FPMBin: "/opt/remi/php86/root/usr/sbin/php-fpm"},
}

func ValidateDomain(d string) error {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" {
		return fmt.Errorf("domain name is required")
	}
	if len(d) > 253 {
		return fmt.Errorf("domain name is too long")
	}
	if !domainNamePattern.MatchString(d) {
		return fmt.Errorf("invalid domain name format (example: example.com)")
	}
	return nil
}

func certSystemDir(domainName string) string {
	return filepath.Join(certSystemBaseDir(), domainName)
}

func prepareCertificateDir(domainName string) (string, error) {
	if err := ValidateDomain(domainName); err != nil {
		return "", err
	}
	sslDir := certSystemDir(strings.ToLower(strings.TrimSpace(domainName)))
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(sslDir, 0755); err != nil {
		return "", fmt.Errorf("create certificate directory: %w", err)
	}
	if err := os.Chown(sslDir, 0, 0); err != nil {
		return "", fmt.Errorf("set certificate directory ownership: %w", err)
	}
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	if err := os.Chmod(sslDir, 0755); err != nil {
		return "", fmt.Errorf("set certificate directory permissions: %w", err)
	}
	_, _ = tenantCommand("restorecon", "-R", sslDir).CombinedOutput()
	return sslDir, nil
}

func applyCertificatePermissions(sslDir, certPath, keyPath string) error {
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{
		{path: certPath, mode: 0644},
		{path: keyPath, mode: 0600},
	} {
		if err := os.Chown(item.path, 0, 0); err != nil {
			return fmt.Errorf("set certificate ownership: %w", err)
		}
		if err := os.Chmod(item.path, item.mode); err != nil {
			return fmt.Errorf("set certificate permissions: %w", err)
		}
	}
	_, _ = tenantCommand("restorecon", "-R", sslDir).CombinedOutput()
	return nil
}

func readTenantCertificate(path string, expectedUID int) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open tenant certificate: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("open tenant certificate: invalid file descriptor")
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect tenant certificate: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("tenant certificate is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != expectedUID {
		return nil, fmt.Errorf("tenant certificate owner does not match the tenant")
	}
	if info.Size() <= 0 || info.Size() > maxCertificateFileSize {
		return nil, fmt.Errorf("tenant certificate size is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCertificateFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read tenant certificate: %w", err)
	}
	if len(data) > maxCertificateFileSize {
		return nil, fmt.Errorf("tenant certificate exceeds the size limit")
	}
	return data, nil
}

func writeSystemCertificate(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".servika-certificate-*")
	if err != nil {
		return fmt.Errorf("create temporary certificate: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()

	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set temporary certificate permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary certificate: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary certificate: %w", err)
	}
	if err := temporary.Chown(0, 0); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set temporary certificate ownership: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary certificate: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("install certificate: %w", err)
	}
	return nil
}

func copyTenantCertificate(source, destination string, expectedUID int, mode os.FileMode) error {
	data, err := readTenantCertificate(source, expectedUID)
	if err != nil {
		return err
	}
	return writeSystemCertificate(destination, data, mode)
}

func removeHomeCertificate(systemUser, domainName string) {
	if !tenantUserPattern.MatchString(systemUser) || ValidateDomain(domainName) != nil {
		return
	}
	domainName = strings.ToLower(strings.TrimSpace(domainName))
	sslDir := filepath.Join("/home", systemUser, "ssl")
	_ = os.Remove(filepath.Join(sslDir, domainName+".crt"))
	_ = os.Remove(filepath.Join(sslDir, domainName+".key"))
}

// HealSSLCertPathsOnStartup migrates active certificates from tenant homes into root-owned system storage.
func HealSSLCertPathsOnStartup() {
	if packageDB == nil {
		return
	}
	rows, err := packageDB.Query(`SELECT id, domain_name, system_user, COALESCE(php_version,'8.3'), cert_path, key_path
		FROM domains
		WHERE ssl_enabled=1 AND (cert_path LIKE '/home/%' OR key_path LIKE '/home/%')`)
	if err != nil {
		log.Printf("SSL certificate path healing: query failed: %v", err)
		return
	}
	defer func() { _ = rows.Close() }()

	migrated := 0
	for rows.Next() {
		var id int64
		var domainName, systemUser, phpVersion, oldCertPath, oldKeyPath string
		if err := rows.Scan(&id, &domainName, &systemUser, &phpVersion, &oldCertPath, &oldKeyPath); err != nil {
			log.Printf("SSL certificate path healing: row scan failed: %v", err)
			continue
		}
		if ValidateDomain(domainName) != nil || !tenantUserPattern.MatchString(systemUser) {
			log.Printf("SSL certificate path healing: refused invalid domain or tenant for domain ID %d", id)
			continue
		}
		domainName = strings.ToLower(strings.TrimSpace(domainName))
		expectedCertPath := filepath.Join("/home", systemUser, "ssl", domainName+".crt")
		expectedKeyPath := filepath.Join("/home", systemUser, "ssl", domainName+".key")
		if filepath.Clean(oldCertPath) != expectedCertPath || filepath.Clean(oldKeyPath) != expectedKeyPath {
			log.Printf("SSL certificate path healing: refused unexpected tenant paths for %s", domainName)
			continue
		}
		uid, _, err := uidGid(systemUser)
		if err != nil {
			log.Printf("SSL certificate path healing: resolve owner for %s: %v", domainName, err)
			continue
		}
		sslDir, err := prepareCertificateDir(domainName)
		if err != nil {
			log.Printf("SSL certificate path healing: prepare directory for %s: %v", domainName, err)
			continue
		}
		newCertPath := filepath.Join(sslDir, domainName+".crt")
		newKeyPath := filepath.Join(sslDir, domainName+".key")
		if err := copyTenantCertificate(oldCertPath, newCertPath, uid, 0644); err != nil {
			log.Printf("SSL certificate path healing: migrate certificate for %s: %v", domainName, err)
			continue
		}
		if err := copyTenantCertificate(oldKeyPath, newKeyPath, uid, 0600); err != nil {
			log.Printf("SSL certificate path healing: migrate private key for %s: %v", domainName, err)
			continue
		}
		_, _ = tenantCommand("restorecon", "-R", sslDir).CombinedOutput()

		socket, err := PHPSocketFor(systemUser, phpVersion)
		if err != nil {
			log.Printf("SSL certificate path healing: resolve PHP socket for %s: %v", domainName, err)
			continue
		}
		if err := applyVhostForDomain(packageDB, id, socket, phpVersion, &newCertPath, &newKeyPath); err != nil {
			log.Printf("SSL certificate path healing: render vhost for %s: %v", domainName, err)
			continue
		}
		if _, err := packageDB.Exec(`UPDATE domains SET cert_path=?, key_path=? WHERE id=?`, newCertPath, newKeyPath, id); err != nil {
			log.Printf("SSL certificate path healing: update database for %s: %v", domainName, err)
			continue
		}
		removeHomeCertificate(systemUser, domainName)
		migrated++
	}
	if err := rows.Err(); err != nil {
		log.Printf("SSL certificate path healing: row iteration failed: %v", err)
	}
	if migrated > 0 {
		log.Printf("SSL certificate path healing: migrated %d certificate sets", migrated)
	}
}

// slugBodyMax is the longest slug body SlugFromDomain produces, and the ceiling
// every suffixed candidate is held to as well.
//
// Keeping the ceiling where it already is means no downstream path meets a
// length it has never seen: the systemd slice name, the MariaDB account name,
// the PHP-FPM socket path and the nginx config name are all derived from this
// value and none of them declares its own limit.
const slugBodyMax = 26

func SlugFromDomain(d string) string {
	s := strings.ToLower(strings.TrimSpace(d))
	s = slugSan.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if len(s) > slugBodyMax {
		s = s[:slugBodyMax]
	}
	return "c_" + s
}

// errSystemUserExhausted is returned when a hundred candidates were all taken,
// which means something is wrong with the caller rather than with the names.
var errSystemUserExhausted = errors.New("provisioner: no free system user name")

// allocateSystemUser returns the system user name for a domain that no other
// tenant already answers to.
//
// SlugFromDomain is NOT injective, and truncation is not the main reason: it
// maps every non-alphanumeric character to `_`, so `blog.example.com` and
// `blog-example.com` produce one name without either being long enough to be
// cut. Everything downstream assumes a system user names exactly ONE top-level
// domain: the vhost is `dom_<system user>.conf`, so the second domain's creation
// would overwrite the first one's file, and the tenant home, FTP account, cron
// spool and `c_<system user>_` database namespace would all be shared by two
// domains that can belong to two different customers.
//
// The first candidate is what SlugFromDomain has always produced, so no
// existing domain is ever renamed; only a name already in use gains a suffix.
//
// A failing `taken` refuses rather than falling through to the candidate. A name
// that MIGHT be shared is exactly what this exists to prevent, and refusing to
// create a domain is recoverable where handing two tenants one identity is not.
func allocateSystemUser(domainName string, taken func(string) (bool, error)) (string, error) {
	base := SlugFromDomain(domainName)
	for attempt := 1; attempt <= 99; attempt++ {
		candidate := base
		if attempt > 1 {
			suffix := "_" + strconv.Itoa(attempt)
			// ValidateDomain runs before this and requires the name to start with
			// an alphanumeric character, so the body is never empty.
			body := strings.TrimPrefix(base, "c_")
			if len(body)+len(suffix) > slugBodyMax {
				body = strings.TrimRight(body[:slugBodyMax-len(suffix)], "_")
			}
			candidate = "c_" + body + suffix
		}
		used, err := taken(candidate)
		if err != nil {
			return "", err
		}
		if !used {
			return candidate, nil
		}
	}
	return "", errSystemUserExhausted
}

// systemUserTaken reports whether a candidate name is already answered to, by
// the host or by the panel.
//
// Both sources are asked because either alone is incomplete: a restored panel
// database can name a tenant whose Linux user has not been recreated yet, and a
// host can carry a user for a domain the panel no longer has. The domain query
// is NOT narrowed to top-level rows, because an addon domain or a subdomain row
// carries its parent's system user and that name is taken all the same.
func systemUserTaken(candidate string) (bool, error) {
	if userExists(candidate) {
		return true, nil
	}
	var one int
	err := packageDB.QueryRow(
		`SELECT 1 FROM domains WHERE system_user=? LIMIT 1`, candidate).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

func normalizePHP(v string) string {
	v = strings.TrimSpace(v)
	if _, ok := phpMap[v]; !ok {
		return "8.3"
	}
	return v
}

// SamePHPVersion reports whether two version strings name the same runtime once
// normalised, which includes both of them being unrecognised and therefore
// resolving to the default.
//
// It is exported so a caller outside this package decides "same version" the way
// the pool eligibility check does. Two comparisons of the same thing drift, and
// a caller that disagreed with subdomainFPMEligible would refuse a change the
// provisioner would have carried out, or allow one it would not.
func SamePHPVersion(a, b string) bool {
	return normalizePHP(a) == normalizePHP(b)
}

// vhostTmpl covers vhosts both with and without SSL.
var vhostTmpl = template.Must(template.New("v").Funcs(vhostFuncs).Parse(`{{- if .SSL -}}
# {{.DomainName}} — port 80 remains open for the HTTP-01 challenge; all other traffic redirects to 443
server {
    listen 80;
{{listen6 "80"}}    server_name {{.ServerNames}};

    location /.well-known/acme-challenge/ {
        root /var/www/_acme;
        auth_basic off;
        try_files $uri =404;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
{{listen6 "443 ssl"}}    http2 on;
    server_name {{.ServerNames}};

    ssl_certificate     {{.CertPath}};
    ssl_certificate_key {{.KeyPath}};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    root {{.WebRoot}};
    index index.php index.html index.htm;
    disable_symlinks if_not_owner;

    # ---- Security headers (managed by the panel) ----
{{.SecHeaders}}
{{.ModSec}}{{.MaintenanceBlock}}{{.GeoBlock}}{{.RateLimit}}{{.IPRules}}{{.DenyBlocks}}{{.HotlinkLocation}}{{.WebmailBlock}}{{.AutoconfigBlock}}

    access_log /var/log/nginx/{{.DomainName}}.access.log;
    error_log  /var/log/nginx/{{.DomainName}}.error.log warn;

{{.ErrorPageBlock}}
{{.AppBlocks}}
{{if eq .Backend "apache"}}    # ---- Backend: Apache (127.0.0.1:10080 proxy) ----
{{if not .AppOwnsRoot}}    location / {
        proxy_pass http://127.0.0.1:10080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $host;
        proxy_read_timeout 60s;
    }
{{end}}{{else if eq .Backend "static"}}    # ---- Backend: Static files (no PHP), PHP source-exposure guard ----
    location ~* \.(php|phtml|php3|php4|php5|phps)(/|$) { return 404; }
{{if not .AppOwnsRoot}}    location / { try_files $uri $uri/ =404; }
{{end}}{{else}}    # ---- Backend: nginx + PHP-FPM (default) ----
{{if not .AppOwnsRoot}}    location / { try_files $uri $uri/ /index.php?$query_string; }
{{end}}

{{if .FastCgiCache}}    set $skip_cache 0;
    if ($request_method = POST) { set $skip_cache 1; }
    if ($query_string != "") { set $skip_cache 1; }
    if ($request_uri ~* "/wp-admin/|/wp-login.php|/cart/|/checkout/|/my-account/|preview=true|sitemap.*\.xml") { set $skip_cache 1; }
    if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in") { set $skip_cache 1; }
{{end}}    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:{{.PHPSocket}};
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_param HTTPS on;
        fastcgi_read_timeout {{.FastCgiReadTimeoutSeconds}}s;
        # Repeat headers because this location may define add_header below.
{{.SecHeaders}}{{if .FastCgiCache}}        fastcgi_cache servikacache;
        fastcgi_cache_valid 200 301 302 {{.FastCgiCacheMinutes}}m;
        fastcgi_cache_valid 404 1m;
        fastcgi_cache_bypass $skip_cache;
        fastcgi_no_cache $skip_cache;
        fastcgi_cache_use_stale error timeout invalid_header updating http_500 http_503;
        fastcgi_cache_background_update on;
        fastcgi_cache_lock on;
        add_header X-Cache-Status $upstream_cache_status always;
        access_log /var/log/nginx/{{.DomainName}}.cache.log servika_cache_status buffer=32k flush=5m;
{{end}}    }
{{end}}
{{if .BrowserCache}}    # ---- Browser cache (static files and legitimate archive downloads) ----
    # ZIP and GZIP downloads are allowed; sensitive .sql.gz files are denied by the earlier location.
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff2?|svg|webp|avif|mp4|webm|pdf|zip|gz)$ {
        expires {{.BrowserCacheDays}}d;
        access_log off;
        add_header Cache-Control "public" always;
        # Repeat headers because this location defines add_header.
{{.SecHeaders}}    }
{{end}}

    location ~ /\.(?!well-known) { deny all; }

{{if .ExtraDirectives}}    # ---- Additional directives (user-provided) ----
    {{.ExtraDirectives}}
{{end}}    # Servika managed (SSL: {{.SSLSource}}) — {{.DomainName}}
}
{{- else -}}
server {
    listen 80;
{{listen6 "80"}}    server_name {{.ServerNames}};

    root {{.WebRoot}};
    index index.php index.html index.htm;
    disable_symlinks if_not_owner;

    access_log /var/log/nginx/{{.DomainName}}.access.log;
    error_log  /var/log/nginx/{{.DomainName}}.error.log warn;

    # ---- Security headers (managed by the panel) ----
{{.SecHeaders}}
    location /.well-known/acme-challenge/ {
        root /var/www/_acme;
        auth_basic off;
        try_files $uri =404;
    }

{{.MaintenanceBlock}}{{.GeoBlock}}{{.RateLimit}}{{.IPRules}}{{.DenyBlocks}}{{.HotlinkLocation}}

{{.ErrorPageBlock}}
{{.AppBlocks}}
{{if eq .Backend "apache"}}    # ---- Backend: Apache (127.0.0.1:10080 proxy) ----
{{if not .AppOwnsRoot}}    location / {
        proxy_pass http://127.0.0.1:10080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto http;
        proxy_set_header X-Forwarded-Host $host;
        proxy_read_timeout 60s;
    }
{{end}}{{else if eq .Backend "static"}}    # ---- Backend: Static files (no PHP), PHP source-exposure guard ----
    location ~* \.(php|phtml|php3|php4|php5|phps)(/|$) { return 404; }
{{if not .AppOwnsRoot}}    location / { try_files $uri $uri/ =404; }
{{end}}{{else}}    # ---- Backend: nginx + PHP-FPM (default) ----
{{if not .AppOwnsRoot}}    location / { try_files $uri $uri/ /index.php?$query_string; }
{{end}}

{{if .FastCgiCache}}    set $skip_cache 0;
    if ($request_method = POST) { set $skip_cache 1; }
    if ($query_string != "") { set $skip_cache 1; }
    if ($request_uri ~* "/wp-admin/|/wp-login.php|/cart/|/checkout/|/my-account/|preview=true|sitemap.*\.xml") { set $skip_cache 1; }
    if ($http_cookie ~* "comment_author|wordpress_[a-f0-9]+|wp-postpass|wordpress_no_cache|wordpress_logged_in") { set $skip_cache 1; }
{{end}}    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:{{.PHPSocket}};
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_read_timeout {{.FastCgiReadTimeoutSeconds}}s;
        # Repeat headers because this location may define add_header below.
{{.SecHeaders}}{{if .FastCgiCache}}        fastcgi_cache servikacache;
        fastcgi_cache_valid 200 301 302 {{.FastCgiCacheMinutes}}m;
        fastcgi_cache_valid 404 1m;
        fastcgi_cache_bypass $skip_cache;
        fastcgi_no_cache $skip_cache;
        fastcgi_cache_use_stale error timeout invalid_header updating http_500 http_503;
        fastcgi_cache_background_update on;
        fastcgi_cache_lock on;
        add_header X-Cache-Status $upstream_cache_status always;
        access_log /var/log/nginx/{{.DomainName}}.cache.log servika_cache_status buffer=32k flush=5m;
{{end}}    }
{{end}}
{{if .BrowserCache}}    # ---- Browser cache (static files and legitimate archive downloads) ----
    # ZIP and GZIP downloads are allowed; sensitive .sql.gz files are denied by the earlier location.
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff2?|svg|webp|avif|mp4|webm|pdf|zip|gz)$ {
        expires {{.BrowserCacheDays}}d;
        access_log off;
        add_header Cache-Control "public" always;
        # Repeat headers because this location defines add_header.
{{.SecHeaders}}    }
{{end}}

    location ~ /\.(?!well-known) { deny all; }

{{if .ExtraDirectives}}    # ---- Additional directives (user-provided) ----
    {{.ExtraDirectives}}
{{end}}    # Servika managed — {{.DomainName}} (HTTP only, PHP {{.PHPVersion}})
}
{{- end -}}
`))

// wwwRedirectTmpl renders the extra server block that answers the NON-canonical
// hostname once a canonical redirect is configured; it is appended to the same
// vhost file as the main template. The main block drops that hostname from its
// server_name (see ServerNames), so without this block the host would fall through
// to nginx's default vhost instead of reaching the site at all.
//
// The ACME challenge location stays open here: HTTP-01 validation for the
// redirected host must still be answerable, or the certificate could not be
// renewed with both hostnames on it.
var discoveryVhostTmpl = template.Must(template.New("discovery").Funcs(vhostFuncs).Parse(discoveryVhostNginx))

var wwwRedirectTmpl = template.Must(template.New("wwwredirect").Funcs(vhostFuncs).Parse(`
# {{.RedirectFromHost}} — redirected to the canonical hostname {{.RedirectToHost}}
server {
    listen 80;
{{listen6 "80"}}{{if .SSL}}    listen 443 ssl;
{{listen6 "443 ssl"}}    http2 on;
    ssl_certificate     {{.CertPath}};
    ssl_certificate_key {{.KeyPath}};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
{{end}}    server_name {{.RedirectFromHost}};

    location /.well-known/acme-challenge/ {
        root /var/www/_acme;
        auth_basic off;
        try_files $uri =404;
    }

    location / {
        return 301 {{if .SSL}}https{{else}}http{{end}}://{{.RedirectToHost}}$request_uri;
    }
}
`))

const denyBlocksNginx = `    # ---- Deny CGI and interpreter scripts ----
    location ~* \.(cgi|pl|py|sh|rb|lua|fcgi)$ { deny all; }
    # ---- Deny backup, dump, and sensitive files ----
    # Legitimate archives and compressed sitemaps remain downloadable.
    location ~* \.(sql|sql\.gz|bak|old|orig|save|swp|swo|dump|inc|log|php\.bak|php~|php\.save)$ { deny all; }
`

func buildSecurityHeaders(opts VhostOpts) string {
	var headers strings.Builder
	if opts.HdrXContentType {
		headers.WriteString("    add_header X-Content-Type-Options \"nosniff\" always;\n")
	}
	if opts.HdrXXSS {
		headers.WriteString("    add_header X-XSS-Protection \"1; mode=block\" always;\n")
	}
	if opts.HdrReferrer {
		headers.WriteString("    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n")
	}
	if opts.HdrPermissions {
		headers.WriteString("    add_header Permissions-Policy \"geolocation=(), microphone=(), camera=(), interest-cohort=()\" always;\n")
	}
	fmt.Fprintf(&headers, "    add_header Content-Security-Policy-Report-Only \"default-src 'self' https: http: data: blob: 'unsafe-inline' 'unsafe-eval'; frame-ancestors %s;\" always;\n", panelFrameAncestors())
	// Clickjacking protection is enforced via CSP frame-ancestors (not X-Frame-Options,
	// which cannot authorize the panel's own origin to preview a tenant site).
	headers.WriteString(framePolicyHeader("    ", opts.SSL() && opts.HdrCSPUpgrade))
	if opts.SSL() && opts.HdrHSTS {
		includeSubdomains := ""
		if opts.HSTSSubdomains {
			includeSubdomains = "; includeSubDomains"
		}
		preload := ""
		if opts.HSTSPreload {
			preload = "; preload"
		}
		fmt.Fprintf(&headers, "    add_header Strict-Transport-Security \"max-age=%d%s%s\" always;\n", opts.HSTSMaxAge, includeSubdomains, preload)
	}
	return headers.String()
}

var suspendedVhostTmpl = template.Must(template.New("suspended").Funcs(vhostFuncs).Parse(`# {{.DomainName}} suspended by Servika
server {
    listen 80;
{{listen6 "80"}}    server_name {{.ServerNames}};

    location /.well-known/acme-challenge/ {
        root /var/www/_acme;
        auth_basic off;
        try_files $uri =404;
    }

    access_log /var/log/nginx/{{.DomainName}}.access.log;
    error_log /var/log/nginx/{{.DomainName}}.error.log warn;

    location / { return 503; }
    error_page 503 /_suspended.html;
    location = /_suspended.html {
        internal;
        default_type text/html;
        return 503 '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Account Suspended</title><style>body{font-family:system-ui,sans-serif;background:#f8fafc;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}.card{max-width:520px;background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:48px;text-align:center}h1{font-size:22px;color:#0f172a;margin:0 0 8px}p{color:#64748b;line-height:1.6}</style></head><body><div class="card"><h1>Account Suspended</h1><p>This website has been temporarily suspended. Please contact your service provider.</p></div></body></html>';
    }
}
{{if .SSL}}
server {
    listen 443 ssl;
{{listen6 "443 ssl"}}    http2 on;
    server_name {{.ServerNames}};

    ssl_certificate {{.CertPath}};
    ssl_certificate_key {{.KeyPath}};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    access_log /var/log/nginx/{{.DomainName}}.access.log;
    error_log /var/log/nginx/{{.DomainName}}.error.log warn;

    location / { return 503; }
    error_page 503 /_suspended.html;
    location = /_suspended.html {
        internal;
        default_type text/html;
        return 503 '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Account Suspended</title><style>body{font-family:system-ui,sans-serif;background:#f8fafc;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}.card{max-width:520px;background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:48px;text-align:center}h1{font-size:22px;color:#0f172a;margin:0 0 8px}p{color:#64748b;line-height:1.6}</style></head><body><div class="card"><h1>Account Suspended</h1><p>This website has been temporarily suspended. Please contact your service provider.</p></div></body></html>';
    }
}
{{end}}`))

var redirectVhostTmpl = template.Must(template.New("redirect").Funcs(vhostFuncs).Parse(`# {{.DomainName}} redirect managed by Servika
server {
    listen 80;
{{listen6 "80"}}    server_name {{.ServerNames}};

    location /.well-known/acme-challenge/ {
        root /var/www/_acme;
        auth_basic off;
        try_files $uri =404;
    }

    access_log /var/log/nginx/{{.DomainName}}.access.log;
    error_log /var/log/nginx/{{.DomainName}}.error.log warn;

    location / {
        return {{.RedirectCode}} {{.RedirectTarget}}$request_uri;
    }
}
{{if .SSL}}
server {
    listen 443 ssl;
{{listen6 "443 ssl"}}    http2 on;
    server_name {{.ServerNames}};

    ssl_certificate {{.CertPath}};
    ssl_certificate_key {{.KeyPath}};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    access_log /var/log/nginx/{{.DomainName}}.access.log;
    error_log /var/log/nginx/{{.DomainName}}.error.log warn;

    location / {
        return {{.RedirectCode}} {{.RedirectTarget}}$request_uri;
    }
}
{{end}}`))

var phpPoolTmpl = template.Must(template.New("p").Parse(`[{{.User}}]
user = {{.User}}
group = {{.User}}
listen = {{.Socket}}
listen.owner = nginx
listen.group = nginx
listen.mode = 0660
pm = ondemand
pm.max_children = 8
pm.process_idle_timeout = 30s
pm.max_requests = 500
; Security settings use php_admin_value so tenant code cannot override them.
php_admin_value[open_basedir] = /home/{{.User}}/:/tmp/
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,proc_close,proc_get_status,proc_terminate,proc_nice,pcntl_exec,dl,symlink,link,posix_kill,posix_mkfifo,posix_setpgid,posix_setsid,posix_setuid,posix_setgid
php_admin_value[upload_tmp_dir] = /home/{{.User}}/tmp
php_admin_value[sys_temp_dir] = /home/{{.User}}/tmp
php_admin_value[session.save_path] = /home/{{.User}}/tmp
catch_workers_output = yes
`))

// VhostOpts contains the optional SSL and server settings used to render a vhost.
type VhostOpts struct {
	DomainName string
	WebRoot    string
	PHPSocket  string
	PHPVersion string
	CertPath   string
	KeyPath    string
	SSLSource  string // "self-signed" | "letsencrypt" | ""
	Suspended  bool
	ConfigPath string

	// nginx security header toggles, enabled by default.
	HdrXContentType bool
	HdrXXSS         bool
	HdrReferrer     bool
	HdrPermissions  bool
	HdrCSPUpgrade   bool
	HdrHSTS         bool
	HSTSMaxAge      int
	HSTSSubdomains  bool
	HSTSPreload     bool

	// Performance caching.
	FastCgiCache        bool
	FastCgiCacheMinutes int
	BrowserCache        bool
	BrowserCacheDays    int

	// User-provided extra directives.
	ExtraDirectives string

	// Full raw custom vhost, enabled only for administrator-managed domains.
	CustomVhostContent string

	// Whole-domain redirect, enabled when no suspension or custom vhost is active.
	RedirectTarget string
	RedirectCode   int

	// WWWRedirect makes one of the two hostnames canonical: "to_www" answers only
	// www and 301s the apex to it, "to_apex" does the reverse, and "" or "off"
	// leaves both hostnames serving the site as they do today. It applies ONLY on
	// the normal render path: a suspended, custom-vhost or whole-domain-redirect
	// vhost already covers apex and www together, and dropping one of them from
	// server_name there would send that host to nginx's default vhost.
	WWWRedirect string

	// Web server backend: "php-fpm" by default, "apache", or "static".
	Backend string

	// Render-time security blocks that are not persisted in the database.
	SecHeaders string
	DenyBlocks string
	ModSec     string // WAF (ModSecurity) server-context directive block; empty when WAF is off or module absent
	IPRules    string // IP allow/deny directives; empty when access control is off
	// MaintenanceBlock takes the whole site to a 503 page while leaving the
	// excepted addresses and the ACME challenge path through. It is empty
	// unless the domain has maintenance mode on, and it is never computed for
	// a suspended domain, which renders a different template entirely.
	MaintenanceBlock string
	// GeoBlock refuses a request by the country its address belongs to, and
	// RateLimit caps how fast one address may make dynamic requests. Both are
	// empty when the domain has not turned them on, and GeoBlock is also empty
	// when no country database has been downloaded, because a country rule with
	// no ranges behind it refuses nobody in deny mode and everybody in allow.
	GeoBlock        string
	RateLimit       string
	HotlinkLocation string // valid_referers image location; empty when hotlink protection is off
	// WebmailBlock is the `location ^~ /webmail/` block that serves Roundcube
	// from the domain's own name. It is computed on every render rather than
	// stored, and stays empty when Roundcube is absent or the vhost has no TLS.
	WebmailBlock string
	// AutoconfigBlock proxies the Thunderbird and Outlook auto-configuration
	// paths to the panel. Empty on a vhost without TLS, where those endpoints
	// would be handing out a password destination over plain HTTP.
	AutoconfigBlock string
	// AppBlocks are the `location ^~` proxies for this domain's applications,
	// computed on every render from the apps table rather than stored.
	AppBlocks string
	// AppOwnsRoot is set when an application is mounted at "/". The vhost then
	// omits its own `location /`, because two blocks for the same prefix are a
	// duplicate nginx refuses.
	AppOwnsRoot bool

	// MaxExecutionTime is the domain's php_settings value, in seconds. It is
	// read on every render so nginx does not give up before PHP does; see
	// FastCgiReadTimeout. Zero means "not read", and the render then keeps the
	// timeout this vhost has always carried.
	MaxExecutionTime int
}

const (
	// fastCgiReadTimeoutFloor is what every tenant vhost carried before the
	// timeout was derived, so a domain can never come out of a render with a
	// SHORTER timeout than it had.
	fastCgiReadTimeoutFloor = 60
	// fastCgiReadTimeoutMargin keeps nginx waiting a little past the point PHP
	// kills the script itself, so the visitor gets PHP's own error rather than
	// a 504 that says nothing about why.
	fastCgiReadTimeoutMargin = 60
	// fastCgiReadTimeoutCeiling bounds how long one worker may be held for a
	// single request.
	fastCgiReadTimeoutCeiling = 3600
)

// FastCgiReadTimeout answers the `fastcgi_read_timeout` a vhost should carry for
// a domain whose PHP max_execution_time is the given number of seconds.
//
// The two are not independent. nginx stops waiting for the FastCGI response on
// its own clock, so a max_execution_time above that clock is invisible: measured
// with nginx 1.26.3 and a pool carrying max_execution_time 3000, a sleep(65)
// request answered HTTP 504 after 60.06 seconds while sleep(2) answered 200. The
// panel would report 3000 seconds while every script died at 60.
func FastCgiReadTimeout(maxExecutionTime int) int {
	timeout := maxExecutionTime + fastCgiReadTimeoutMargin
	if maxExecutionTime <= 0 {
		// Not read, or PHP's own "unlimited". Neither is a reason to hold a
		// worker forever, and the floor is what this vhost carried before.
		timeout = fastCgiReadTimeoutFloor
	}
	if timeout < fastCgiReadTimeoutFloor {
		timeout = fastCgiReadTimeoutFloor
	}
	if timeout > fastCgiReadTimeoutCeiling {
		timeout = fastCgiReadTimeoutCeiling
	}
	return timeout
}

// FastCgiReadTimeoutSeconds is what the vhost templates render. It goes through
// the same clamp, so a VhostOpts built without MaxExecutionTime (every heal and
// test that fills the struct by hand) keeps the timeout it has always had.
func (o VhostOpts) FastCgiReadTimeoutSeconds() int {
	return FastCgiReadTimeout(o.MaxExecutionTime)
}

func (o VhostOpts) SSL() bool {
	return o.CertPath != "" && o.KeyPath != ""
}

// ServerNames returns the nginx server_name list for the domain's main vhost. With
// a canonical redirect configured it names only the canonical host; the other one is
// answered by wwwRedirectTmpl in the same file.
func (o VhostOpts) ServerNames() string {
	if to := o.RedirectToHost(); to != "" {
		return to
	}
	return strings.Join(wwwHostNames(o.DomainName), " ")
}

// canonicalRedirect reports whether a canonical hostname redirect applies. It never
// applies to a domain that is itself a www host, because there is no second name to
// redirect from.
func (o VhostOpts) canonicalRedirect() bool {
	if strings.HasPrefix(strings.ToLower(o.DomainName), "www.") {
		return false
	}
	return o.WWWRedirect == "to_www" || o.WWWRedirect == "to_apex"
}

// RedirectToHost returns the canonical hostname, or "" when no canonical redirect
// applies. Exported for the vhost templates.
func (o VhostOpts) RedirectToHost() string {
	if !o.canonicalRedirect() {
		return ""
	}
	if o.WWWRedirect == "to_www" {
		return "www." + o.DomainName
	}
	return o.DomainName
}

// withCertifiableCanonicalRedirect drops a canonical redirect the installed
// certificate cannot carry.
//
// The redirect is checked against the certificate when the SETTING is stored,
// but it is stored once and re-applied by every later render (a PHP version
// change, an SSL renewal, a WAF toggle), so the certificate it was checked
// against is not the one that ends up serving it. Two ways they diverge: SSL
// installation is asynchronous, so cert_path is still empty while the setting is
// being stored and the check cannot run at all; and a renewal can come back
// without a name the previous certificate had.
//
// Once a certificate exists the template turns the 301 into an https one, so
// emitting it against a certificate that does not name the target replaces a
// working site with a browser certificate error. Dropping it leaves both
// hostnames serving the site directly, which is a lost preference rather than an
// outage. The setting stays stored, so the next render after the certificate
// covers the target picks it back up on its own.
//
// covers is a parameter so the decision can be tested without a certificate on
// disk; production always passes CertificateCoversHost.
func withCertifiableCanonicalRedirect(opts VhostOpts, covers func(certPath, keyPath, host string) bool) VhostOpts {
	if canonicalRedirectDropReason(opts, covers) == "" {
		return opts
	}
	// #nosec G706 -- both values are validated hostnames (ValidateDomain) or template-derived, so no raw tenant string with CR/LF reaches the log.
	log.Printf("canonical redirect for %q dropped from this render: the installed certificate does not cover %q", opts.DomainName, opts.RedirectToHost())
	opts.WWWRedirect = ""
	return opts
}

// CanonicalRedirectCertMissing is the reason code for a stored canonical
// redirect the installed certificate cannot carry.
const CanonicalRedirectCertMissing = "redirect_cert_missing_target"

// canonicalRedirectDropReason answers why this render drops the redirect, or ""
// when it emits it.
func canonicalRedirectDropReason(opts VhostOpts, covers func(certPath, keyPath, host string) bool) string {
	target := opts.RedirectToHost()
	// Nothing to emit, or the target stays http and no certificate is involved.
	if target == "" || !opts.SSL() {
		return ""
	}
	if covers(opts.CertPath, opts.KeyPath, target) {
		return ""
	}
	return CanonicalRedirectCertMissing
}

// CanonicalRedirectDropReasonFor answers the same question for a screen that
// holds the domain's columns rather than a VhostOpts, so the panel cannot report
// a redirect as in force while every render is dropping it. The setting is
// stored once and vetted against a certificate that did not exist yet, so
// reading the stored value alone is exactly how that misreport happened.
func CanonicalRedirectDropReasonFor(mode, domainName, certPath, keyPath string) string {
	return canonicalRedirectDropReason(VhostOpts{
		DomainName:  domainName,
		WWWRedirect: mode,
		CertPath:    certPath,
		KeyPath:     keyPath,
	}, CertificateCoversHost)
}

// RedirectFromHost returns the hostname that answers with a 301, or "" when no
// canonical redirect applies. Exported for the vhost templates.
func (o VhostOpts) RedirectFromHost() string {
	if !o.canonicalRedirect() {
		return ""
	}
	if o.WWWRedirect == "to_www" {
		return o.DomainName
	}
	return "www." + o.DomainName
}

// MTASTSHost is the hostname an MTA-STS policy is fetched from (RFC 8461).
func MTASTSHost(domain string) string { return "mta-sts." + domain }

// DiscoveryHosts returns the server_name list for the auto-configuration vhost.
//
// Only names the installed certificate actually covers are listed. The vhost
// carries two independent capabilities now, and a name served from a
// certificate that omits it is worse than one that goes unanswered: the client
// gets a mismatch on the very connection it made to learn something.
func (o VhostOpts) DiscoveryHosts() string {
	var hosts []string
	if o.discoveryEligible() {
		hosts = append(hosts, discoverySANHosts(o.DomainName)...)
	}
	if o.mtaSTSEligible() {
		hosts = append(hosts, MTASTSHost(o.DomainName))
	}
	return strings.Join(hosts, " ")
}

// DiscoveryBlocks returns the location blocks the auto-configuration vhost
// serves, each gated on its own name being covered.
func (o VhostOpts) DiscoveryBlocks() string {
	var blocks strings.Builder
	if o.discoveryEligible() {
		blocks.WriteString(autoconfigNginx)
	}
	if o.mtaSTSEligible() {
		blocks.WriteString(mtaSTSNginx)
	}
	return blocks.String()
}

// mtaSTSEligible reports whether mta-sts.<domain> may be served.
//
// It is deliberately SEPARATE from discoveryEligible rather than another name
// in discoverySANHosts. That set is the one discoveryEligible requires in full,
// so adding a name to it would make every certificate issued before this
// feature fail the check and silently stop the auto-configuration vhost from
// rendering at all, breaking working mail client setup on every domain.
func (o VhostOpts) mtaSTSEligible() bool {
	if o.Suspended || !o.SSL() {
		return false
	}
	return certValid(o.CertPath, o.KeyPath, 0, MTASTSHost(o.DomainName))
}

// discoveryEligible reports whether the auto-configuration vhost may be
// rendered.
//
// The installed certificate has to name both hosts. Serving them from a
// certificate that omits them is worse than not answering at all: the client
// gets a name mismatch on the very connection it is making to learn where to
// send a mailbox password, whereas an unanswered name simply moves it on to the
// next lookup in its own order.
func (o VhostOpts) discoveryEligible() bool {
	if o.Suspended || !o.SSL() {
		return false
	}
	return certValid(o.CertPath, o.KeyPath, 0, discoverySANHosts(o.DomainName)...)
}

// ErrorPageBlock returns the nginx block that wires the brand 404 page and the
// shared /_srv/ asset location into the vhost. Exposed as a method so the vhost
// template can inject it with {{.ErrorPageBlock}}.
func (o VhostOpts) ErrorPageBlock() string { return errorPageBlock }

// wwwHostNames returns the canonical certificate and vhost hostnames for a domain.
// It always includes www.<domain>; use it for vhost server_name and self-signed
// SANs where extra coverage is harmless. For ACME issuance and real-CA reuse,
// prefer certSANHosts, which drops www when DNS does not support it.
func wwwHostNames(domain string) []string {
	if strings.HasPrefix(strings.ToLower(domain), "www.") {
		return []string{domain}
	}
	return []string{domain, "www." + domain}
}

// wwwSANEligible reports whether www.<domain> may be included in ACME validation.
// Rule: www must RESOLVE in DNS and point to the SAME address(es) as the apex.
// Otherwise HTTP-01 validation for www would land on a different server and fail
// the WHOLE order. When DNS still cannot be read after retrying, www is left out
// — an apex-only certificate always beats the self-signed fail-safe, which on
// HSTS-preload TLDs (e.g. .app) makes the site entirely unreachable.
//
// Each name is looked up through lookupHostRetrying: dropping www because of one
// slow resolver answer costs a certificate that omits it, and the canonical www
// redirect is then refused for a host the certificate does not name. A mismatch
// is not retried; that is an answer.
func wwwSANEligible(domain string) bool {
	apex := lookupHostRetrying(domain)
	if len(apex) == 0 {
		return false
	}
	return sanEligible(apex, "www."+domain)
}

// sanEligible reports whether host may join the SAN of the apex's certificate.
//
// The apex addresses are passed in rather than looked up, because the caller
// judges several optional names against the same apex and resolving it once per
// name multiplies a retrying lookup across every domain the startup heal walks.
func sanEligible(apexAddresses []string, host string) bool {
	if len(apexAddresses) == 0 {
		return false
	}
	addresses := lookupHostRetrying(host)
	if len(addresses) == 0 {
		return false
	}
	apexSet := make(map[string]bool, len(apexAddresses))
	for _, ip := range apexAddresses {
		apexSet[ip] = true
	}
	for _, ip := range addresses {
		if !apexSet[ip] {
			return false // the name points at a different server
		}
	}
	return true
}

// discoverySANHosts are the optional names a mail client looks for before it
// falls back to the domain itself.
//
// Thunderbird probes autoconfig.<domain> FIRST and only then the domain's own
// /.well-known path; Outlook probes the domain first and autodiscover.<domain>
// second. Covering both names means the client succeeds on its first attempt,
// and it is the only route that works at all when the apex resolves to someone
// else's server while mail is hosted here.
func discoverySANHosts(domain string) []string {
	return []string{"autoconfig." + domain, "autodiscover." + domain}
}

// WWWResolvesToApex reports whether www.<domain> resolves to the same address(es)
// as the apex. Enabling a redirect TO www without this is a site outage: every
// visitor is sent to a hostname that does not exist or belongs to another server.
func WWWResolvesToApex(domain string) bool { return wwwSANEligible(domain) }

// CertificateCoversHost reports whether the installed certificate is currently
// valid and names host. A redirect to a hostname the certificate omits replaces a
// working site with a certificate warning, so the caller checks before enabling it.
func CertificateCoversHost(certPath, keyPath, host string) bool {
	return certValid(certPath, keyPath, 0, host)
}

// MTASTSResolvesToApex reports whether mta-sts.<domain> resolves to the same
// address(es) as the apex.
//
// This is the gate that keeps the name out of certSANHosts until the customer
// has actually written the record, so a domain that never enables MTA-STS orders
// exactly the same SAN set it ordered before the feature existed.
func MTASTSResolvesToApex(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return sanEligible(lookupHostRetrying(domain), MTASTSHost(domain))
}

// MTASTSCertificateReady reports whether the certificate the vhost would serve
// currently names mta-sts.<domain>.
//
// It asks bestCertificate rather than a fixed path because that is the same
// selection renderAndReload makes, so the answer is about the certificate a
// sender will actually be shown and not about a file that happens to exist.
func MTASTSCertificateReady(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	certPath, keyPath, _ := bestCertificate(domain, 0)
	if certPath == "" {
		return false
	}
	return certValid(certPath, keyPath, 0, MTASTSHost(domain))
}

// certSANHosts returns the hostnames a real certificate must cover for a domain:
// the apex always, plus www and the mail-discovery names when DNS supports them.
// This is the DNS aware counterpart to wwwHostNames, used by ACME issuance and
// real-CA reuse.
//
// Every optional name goes through the SAME gate here, and that is what keeps
// issuance stable. The set this returns is both what is ORDERED and what a
// stored certificate is REQUIRED to cover before it may be reused
// (ssl_heal.go bestCertificate), so a name added unconditionally would make
// every existing certificate fail the reuse check, and one that never resolves
// for a customer would keep failing it after each order — a re-issuance on every
// attempt, against Let's Encrypt's weekly per-registered-domain limit.
func certSANHosts(domain string) []string {
	if strings.HasPrefix(strings.ToLower(domain), "www.") {
		return []string{domain}
	}
	apex := lookupHostRetrying(domain)
	if len(apex) == 0 {
		return []string{domain}
	}
	hosts := []string{domain}
	if sanEligible(apex, "www."+domain) {
		hosts = append(hosts, "www."+domain)
	}
	// Order is fixed so the SAN set does not differ between two runs that agree
	// on which names are eligible.
	for _, host := range discoverySANHosts(domain) {
		if sanEligible(apex, host) {
			hosts = append(hosts, host)
		}
	}
	// The MTA-STS hostname goes through the SAME gate, which is what keeps this
	// inert for every domain that has not asked for it: mta-sts.<domain> has no
	// A record until MTA-STS is enabled, so sanEligible answers false and the
	// SAN set is byte for byte what it was. A name added unconditionally here
	// would fail the reuse check in ssl_heal.bestCertificate for every stored
	// certificate at once and order a re-issuance on every attempt, against Let's
	// Encrypt's weekly per-registered-domain limit.
	if sanEligible(apex, MTASTSHost(domain)) {
		hosts = append(hosts, MTASTSHost(domain))
	}
	return hosts
}

type Result struct {
	SystemUser string
	WebRoot    string
	FTPHost    string
	PHPVersion string
	PHPSocket  string
}

func phpPoolPath(systemUser, phpVersion string) (string, string, string) {
	version := normalizePHP(phpVersion)
	config := phpMap[version]
	return filepath.Join(config.PoolDir, systemUser+".conf"),
		filepath.Join(config.SockDir, systemUser+".sock"),
		config.Service
}

func writePoolValidated(systemUser, phpVersion string) (socket, service string, err error) {
	// Never write a pool for a user that no longer exists. A domain deletion
	// removes the Linux user (userdel), and a concurrent or later heal that
	// resurrects the pool would make `php-fpm -t` fail PERMANENTLY for that PHP
	// version (the pool references a missing user), which blocks creation of
	// EVERY new domain on that version. Fail closed instead.
	if !userExists(systemUser) {
		return "", "", fmt.Errorf("php pool skipped: system user %q does not exist", systemUser)
	}
	version := normalizePHP(phpVersion)
	config := phpMap[version]
	poolPath, socket, service := phpPoolPath(systemUser, version)

	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(filepath.Dir(poolPath), 0755); err != nil {
		return "", "", fmt.Errorf("create PHP pool directory: %w", err)
	}
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(filepath.Dir(socket), 0755); err != nil {
		return "", "", fmt.Errorf("create PHP socket directory: %w", err)
	}

	var pool bytes.Buffer
	if err := phpPoolTmpl.Execute(&pool, map[string]string{"User": systemUser, "Socket": socket}); err != nil {
		return "", "", fmt.Errorf("render PHP pool: %w", err)
	}

	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	previousPool, readErr := os.ReadFile(poolPath)
	hadPreviousPool := readErr == nil
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(poolPath, pool.Bytes(), 0644); err != nil {
		return "", "", fmt.Errorf("write PHP pool: %w", err)
	}
	if config.FPMBin != "" {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		if output, err := exec.Command(config.FPMBin, "-t").CombinedOutput(); err != nil {
			if hadPreviousPool {
				// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
				_ = os.WriteFile(poolPath, previousPool, 0644)
			} else {
				_ = os.Remove(poolPath)
			}
			return "", "", fmt.Errorf("php-fpm -t (%s) failed, pool restored: %s: %w", version, strings.TrimSpace(string(output)), err)
		}
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	if output, err := exec.Command("systemctl", "reload-or-restart", service).CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("php-fpm (%s) reload: %s: %w", service, strings.TrimSpace(string(output)), err)
	}
	return socket, service, nil
}

// renderAndReload writes the vhost, validates nginx, and reloads it for both SSL modes.
// For the "apache" backend, it also writes the per-domain Apache vhost and reloads httpd.
// When switching away from Apache, it removes the obsolete Apache vhost.
func renderAndReload(opts VhostOpts, systemUser string) error {
	// Use PHP-FPM as the default backend.
	if opts.Backend == "" {
		opts.Backend = "php-fpm"
	}
	// Preserve the isolated socket across every vhost rewrite, including SSL changes.
	if TenantFPMActive(systemUser) {
		opts.PHPSocket = tenantSocket(systemUser)
	}
	if !opts.Suspended && packageDB != nil {
		var suspended int
		_ = packageDB.QueryRow(
			`SELECT COALESCE(suspended,0) FROM domains WHERE system_user=? AND parent_domain_id IS NULL LIMIT 1`, systemUser).
			Scan(&suspended)
		opts.Suspended = suspended == 1
	}

	opts.SecHeaders = buildSecurityHeaders(opts)
	opts.DenyBlocks = denyBlocksNginx
	// WAF (ModSecurity) directive: computed from effective settings on every render.
	// When suspended the suspended template (no ModSec field) is rendered — computation is skipped.
	// buildModSec returns "" when WAF is off or the module is absent (doesn't break the vhost);
	// when active it also refreshes the per-domain modsec conf — single source, self-healing.
	if !opts.Suspended {
		opts.ModSec = buildModSec(systemUser)
		opts.IPRules = buildIPRules(opts.DomainName)
		opts.MaintenanceBlock = buildMaintenanceBlock(opts.DomainName)
		opts.GeoBlock, opts.RateLimit = domainProtection(opts.DomainName)
		opts.HotlinkLocation = buildHotlink(opts.DomainName)
		// Webmail only on the TLS vhost. On a domain without a certificate the
		// block would carry mailbox passwords in the clear; the mail page keeps
		// pointing such a domain at the panel's own HTTPS webmail instead.
		if opts.SSL() {
			opts.WebmailBlock = webmailBlock()
			opts.AutoconfigBlock = autoconfigBlock()
		}
		// Applications are computed on every render for the same reason the WAF
		// and IP rules are: the vhost is rewritten by ~30 unrelated call sites,
		// none of which know an application exists.
		if packageDB != nil {
			var domainID int64
			if err := packageDB.QueryRow(
				`SELECT id FROM domains WHERE domain_name=? LIMIT 1`, opts.DomainName).Scan(&domainID); err == nil {
				opts.AppBlocks, opts.AppOwnsRoot = AppProxyBlocks(packageDB, domainID, 0)
			}
		}
	}

	if !opts.Suspended && opts.CustomVhostContent == "" && packageDB != nil {
		var target string
		var code int
		if err := packageDB.QueryRow(
			`SELECT target_url, status_code FROM domain_redirects WHERE domain_id=(SELECT id FROM domains WHERE domain_name=? LIMIT 1)`, opts.DomainName).
			Scan(&target, &code); err == nil && strings.TrimSpace(target) != "" {
			opts.RedirectTarget = target
			opts.RedirectCode = code
		}
	}

	// Canonical hostname redirect, read here so every caller keeps it: the setting is
	// stored once and ~30 call sites (PHP version change, SSL renewal, WAF toggle)
	// re-render the vhost without knowing about it. It applies only when none of the
	// other three shapes is in play, because each of those already answers on apex
	// and www together.
	if !opts.Suspended && opts.CustomVhostContent == "" && opts.RedirectTarget == "" &&
		opts.WWWRedirect == "" && packageDB != nil {
		var mode string
		if err := packageDB.QueryRow(
			`SELECT COALESCE(www_redirect,'off') FROM domains WHERE system_user=? AND parent_domain_id IS NULL LIMIT 1`,
			systemUser).Scan(&mode); err == nil {
			opts.WWWRedirect = mode
		}
	}

	tmpl := vhostTmpl
	if opts.Suspended {
		tmpl = suspendedVhostTmpl
	} else if opts.RedirectTarget != "" {
		tmpl = redirectVhostTmpl
	}
	// The other three shapes keep both hostnames on one server_name, so the canonical
	// redirect must not remove one of them there.
	if opts.Suspended || opts.RedirectTarget != "" || opts.CustomVhostContent != "" {
		opts.WWWRedirect = ""
	}
	opts = withCertifiableCanonicalRedirect(opts, CertificateCoversHost)
	var buf bytes.Buffer
	if opts.CustomVhostContent != "" && !opts.Suspended {
		buf.WriteString(strings.TrimSpace(opts.CustomVhostContent))
		buf.WriteByte('\n')
	} else {
		if err := tmpl.Execute(&buf, opts); err != nil {
			return fmt.Errorf("template render: %w", err)
		}
		if opts.RedirectFromHost() != "" {
			if err := wwwRedirectTmpl.Execute(&buf, opts); err != nil {
				return fmt.Errorf("canonical redirect render: %w", err)
			}
		}
		if opts.discoveryEligible() || opts.mtaSTSEligible() {
			if err := discoveryVhostTmpl.Execute(&buf, opts); err != nil {
				return fmt.Errorf("auto-configuration vhost render: %w", err)
			}
		}
	}
	cfgPath := opts.ConfigPath
	if cfgPath == "" {
		cfgPath = "/etc/nginx/conf.d/dom_" + systemUser + ".conf"
	}
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	previousConfig, readErr := os.ReadFile(cfgPath)
	hadPreviousConfig := readErr == nil
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(cfgPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write vhost: %w", err)
	}
	if _, err := ensureCacheZone(); err != nil {
		return err
	}
	// The map must exist before a vhost references $connection_upgrade, or nginx
	// rejects the whole configuration and the rollback below fires on a defect
	// that is not in the vhost.
	if opts.AppBlocks != "" {
		if err := ensureUpgradeMap(); err != nil {
			return err
		}
	}
	// The country and rate-limit declarations live in http context, so they have
	// to exist before a vhost names the variables and zones they declare. They
	// are rolled back with the vhost below: nginx keeps serving its loaded
	// configuration after a failed test, so a shared file left broken here would
	// take the whole server down at the next unrelated reload instead.
	sharedRestorers, sharedErr := ensureProtectionConf()
	if sharedErr != nil {
		for _, saved := range sharedRestorers {
			saved.restore()
		}
		return sharedErr
	}
	if out, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
		if hadPreviousConfig {
			// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
			_ = os.WriteFile(cfgPath, previousConfig, 0644)
		} else {
			_ = os.Remove(cfgPath)
		}
		for _, saved := range sharedRestorers {
			saved.restore()
		}
		return fmt.Errorf("nginx -t failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if out, err := exec.Command("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
		return fmt.Errorf("nginx reload: %s: %w", strings.TrimSpace(string(out)), err)
	}
	// Purge stale FastCGI cache entries for this domain so that cache TTL and
	// enable/disable changes take effect immediately instead of serving old content.
	purgeFastCGICache(systemUser)

	// Manage the Apache backend idempotently by writing or removing its vhost.
	if opts.Backend == "apache" && !opts.Suspended {
		if err := writeApacheVhost(opts, systemUser); err != nil {
			return err
		}
	} else {
		if err := deleteApacheVhostIfExists(systemUser); err != nil {
			return err
		}
	}
	return nil
}

func Provision(domainName, phpVersion string) (*Result, error) {
	if err := ValidateDomain(domainName); err != nil {
		return nil, err
	}
	phpVersion = normalizePHP(phpVersion)
	domainName = strings.ToLower(strings.TrimSpace(domainName))
	if packageDB == nil {
		// Without the panel database the allocator cannot tell an unused name from
		// one another domain already answers to, and falling back to the bare slug
		// is precisely the behaviour this replaced.
		return nil, fmt.Errorf("provisioning: the panel database is not wired up")
	}
	systemUser, err := allocateSystemUser(domainName, systemUserTaken)
	if err != nil {
		return nil, fmt.Errorf("allocate system user: %w", err)
	}
	home := "/home/" + systemUser

	if !userExists(systemUser) {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		out, err := exec.Command("useradd", "-m", "-d", home, "-s", "/usr/sbin/nologin", systemUser).CombinedOutput()
		if err != nil && !strings.Contains(string(out), "already exists") {
			return nil, fmt.Errorf("useradd: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}

	dirs := []string{"public_html", "logs", "tmp", "ssl", ".cron"}
	for _, d := range dirs {
		_ = os.MkdirAll(filepath.Join(home, d), 0750)
	}

	uid, gid, err := uidGid(systemUser)
	if err == nil {
		_ = filepath.Walk(home, func(p string, _ os.FileInfo, _ error) error {
			// #nosec G122 -- operator provisioning of a tenant home tree, not tenant input; best-effort ownership fix.
			_ = os.Chown(p, uid, gid)
			return nil
		})
	}

	_ = filepath.Walk(filepath.Join(home, "public_html"), func(p string, info os.FileInfo, _ error) error {
		if info == nil {
			return nil
		}
		if info.IsDir() {
			// #nosec G122 G302 -- operator provisioning of a tenant home tree, not tenant input; best-effort mode fix.
			_ = os.Chmod(p, 0750)
		} else {
			// #nosec G122 G302 -- operator provisioning of a tenant home tree, not tenant input; best-effort mode fix.
			_ = os.Chmod(p, 0644)
		}
		return nil
	})
	if err == nil {
		hardenHomePerms(home, systemUser, uid, gid)
	}

	indexPath := filepath.Join(home, "public_html", "index.html")
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	_ = os.WriteFile(indexPath, []byte(welcomeHTML(domainName)), 0644)
	if err == nil {
		_ = os.Chown(indexPath, uid, gid)
	}

	// #nosec G204 G702 -- fixed binary (restorecon) with constant flag and internal home path (no shell); no tenant input.
	_, _ = exec.Command("restorecon", "-R", home).CombinedOutput()

	// Write, validate, and activate the tenant PHP-FPM pool.
	socket, _, err := writePoolValidated(systemUser, phpVersion)
	if err != nil {
		return nil, err
	}

	// Create the initial vhost without SSL.
	if err := renderAndReload(VhostOpts{
		DomainName: domainName,
		WebRoot:    PublicHTML(systemUser),
		PHPSocket:  socket,
		PHPVersion: phpVersion,
	}, systemUser); err != nil {
		return nil, err
	}

	return &Result{
		SystemUser: systemUser,
		WebRoot:    PublicHTML(systemUser),
		FTPHost:    domainName, // The handler stores h.IPv4, the server IP, in the ftp_host database column.
		PHPVersion: phpVersion,
		PHPSocket:  socket,
	}, nil
}

// DeprovisionAddonDomain removes the host state an addon domain owns OUTSIDE the
// tenant home: its vhost and its certificate directory, both root-owned.
//
// The document root is deliberately not its business. That path lives inside the
// tenant's home, where a string prefix decides nothing, because every component
// belongs to the tenant and one swapped for a symlink sends a root-run removal
// outside the jail while the path still reads like one inside it. Removing it
// safely needs internal/files, which imports THIS package, so it belongs to the
// caller, next to the mkdir that created it (addondomains.removeDocRoot). Do not
// restore an os.RemoveAll here.
func DeprovisionAddonDomain(domainName, systemUser string) error {
	if domainName != "" && ValidateDomain(domainName) == nil {
		_ = os.Remove(addonVhostConfigPath(systemUser, domainName))
		_ = os.RemoveAll(certSystemDir(strings.ToLower(strings.TrimSpace(domainName))))
	}
	_, _ = exec.Command("systemctl", "reload", "nginx").CombinedOutput()
	purgeFastCGICache(systemUser)
	return nil
}

// OtherTopLevelDomainsUsing lists the domains that still answer to a system
// user once the named one is gone.
//
// The exception is by domain NAME because that column is UNIQUE, so it names
// exactly the row being torn down whether or not it has been deleted yet, and no
// caller has to pass an id it may not have. Addon and subdomain rows are
// excluded: they carry their parent's system user and are removed with it, so
// counting them would make every parent look shared.
//
// A read failure is returned, never swallowed. The caller treats it as "still in
// use", because the alternative is deleting a live tenant's home directory on
// the strength of a query that did not run.
func OtherTopLevelDomainsUsing(systemUser, exceptDomainName string) ([]int64, error) {
	if systemUser == "" {
		return nil, nil
	}
	if packageDB == nil {
		return nil, fmt.Errorf("provisioner: the panel database is not wired up")
	}
	rows, err := packageDB.Query(
		`SELECT id FROM domains
		  WHERE system_user=? AND parent_domain_id IS NULL AND domain_name<>?`,
		systemUser, strings.ToLower(strings.TrimSpace(exceptDomainName)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ReportSystemUserCollisions logs every system user that more than one
// top-level domain answers to.
//
// It CHANGES NOTHING. Two such domains have one home directory with both
// tenants' files interleaved, and nothing in the panel can tell which file
// belongs to which, so separating them is an operator's decision. What this
// gives them is the knowledge that the pair exists, which until now nothing
// reported.
//
// New domains cannot land here any more (allocateSystemUser), so on a panel
// installed after that this is silent for good.
func ReportSystemUserCollisions() {
	if packageDB == nil {
		return
	}
	rows, err := packageDB.Query(
		`SELECT system_user, GROUP_CONCAT(domain_name ORDER BY id SEPARATOR ', ')
		   FROM domains
		  WHERE parent_domain_id IS NULL AND system_user<>''
		  GROUP BY system_user
		 HAVING COUNT(*) > 1`)
	if err != nil {
		log.Printf("system user collision check failed: %v", err)
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var systemUser, domainNames string
		if err := rows.Scan(&systemUser, &domainNames); err != nil {
			log.Printf("system user collision check failed: %v", err)
			return
		}
		log.Printf("system user %q is shared by more than one domain (%s): they share a home directory, "+
			"an FTP account and a database namespace, and deleting one no longer removes the account",
			systemUser, domainNames)
	}
	if err := rows.Err(); err != nil {
		log.Printf("system user collision check failed: %v", err)
	}
}

func Deprovision(domainName, systemUser string) error {
	// Everything below except the certificate directory is keyed on the system
	// user, and an upgraded panel can still carry two domains that share one:
	// until allocateSystemUser existed, the slug rule mapped `.` and `-` to the
	// same separator. Removing any of it while a sibling is live takes that
	// sibling's home directory, its FTP account and its backups with it.
	//
	// A failed lookup counts as shared. An orphaned user is recoverable; a
	// deleted tenant home is not.
	siblings, err := OtherTopLevelDomainsUsing(systemUser, domainName)
	if err != nil {
		log.Printf("deprovision %q: cannot tell whether the system user is shared, keeping it: %v", domainName, err)
	}
	if err != nil || len(siblings) > 0 {
		if domainName != "" && ValidateDomain(domainName) == nil {
			_ = os.RemoveAll(certSystemDir(strings.ToLower(strings.TrimSpace(domainName))))
		}
		_, _ = exec.Command("systemctl", "reload", "nginx").CombinedOutput()
		purgeFastCGICache(systemUser)
		if err == nil {
			log.Printf("deprovision %q: system user %q still answers for %d other domain(s), host teardown skipped",
				domainName, systemUser, len(siblings))
		}
		return nil
	}

	cfgPath := "/etc/nginx/conf.d/dom_" + systemUser + ".conf"
	_ = os.Remove(cfgPath)
	subdomainVhosts, _ := filepath.Glob("/etc/nginx/conf.d/sub_" + systemUser + "_*.conf")
	for _, vhostPath := range subdomainVhosts {
		_ = os.Remove(vhostPath)
	}
	TeardownTenantFPM(systemUser)
	if domainName != "" && ValidateDomain(domainName) == nil {
		_ = os.RemoveAll(certSystemDir(strings.ToLower(strings.TrimSpace(domainName))))
	}
	// Clean up per-domain WAF modsec confs (prevent orphans).
	if reWafSK.MatchString(systemUser) {
		_ = os.Remove(filepath.Join(wafDomainsDir, systemUser+".conf"))
		_ = os.Remove(filepath.Join(wafDomainsDir, systemUser+".custom.conf"))
	}
	_, _ = exec.Command("systemctl", "reload", "nginx").CombinedOutput()
	purgeFastCGICache(systemUser)

	if !strings.HasPrefix(systemUser, "c_") {
		return fmt.Errorf("security: refusing to delete a user without the c_ prefix")
	}
	// userdel -r does not always remove the tenant crontab on AlmaLinux; drop it
	// (and any suspended copy) explicitly so import rollback and normal domain
	// deletion cannot leave orphaned jobs running.
	_ = os.Remove(filepath.Join("/var/spool/cron", systemUser))
	_ = os.Remove(filepath.Join("/var/lib/servika/cron-suspended", systemUser))
	if userExists(systemUser) {
		// #nosec G204 G702 -- fixed binary (userdel) with separate args (no shell); systemUser is validated before exec.
		_, _ = exec.Command("userdel", "-r", systemUser).CombinedOutput()
		// Orphan cleanup: userdel -r removes the home dir, but these live outside
		// it, so they survived and accumulated after every domain deletion or
		// import rollback.
		_ = os.RemoveAll(filepath.Join(config.BackupRoot(), systemUser)) // manual + scheduled backups
		removeTenantLogs(systemUser)                                     // tenant PHP-FPM log, its rotated copies, and the pre-move path
	}
	// Sweep the shared PHP-FPM pool AFTER userdel, not before. Once the user is
	// gone, writePoolValidated's user-existence guard refuses to resurrect the
	// pool, so a concurrent heal cannot re-create it in the gap between sweep and
	// userdel. The pool lives outside the home dir, so userdel -r never removes it.
	for _, config := range phpMap {
		p := filepath.Join(config.PoolDir, systemUser+".conf")
		if _, err := os.Stat(p); err == nil {
			_ = os.Remove(p)
			// #nosec G204 G702 -- fixed binary (systemctl) with constant/internal args (no shell); no tenant shell input.
			_, _ = exec.Command("systemctl", "reload-or-restart", config.Service).CombinedOutput()
		}
	}
	return nil
}

func SetPHPVersion(domainName, systemUser, newVersion, certPath, keyPath, sslSource, backend, webRoot string) (string, error) {
	newVersion = normalizePHP(newVersion)
	for _, config := range phpMap {
		p := filepath.Join(config.PoolDir, systemUser+".conf")
		if _, err := os.Stat(p); err == nil {
			_ = os.Remove(p)
			// #nosec G204 G702 -- fixed binary (systemctl) with constant/internal args (no shell); no tenant shell input.
			_, _ = exec.Command("systemctl", "reload-or-restart", config.Service).CombinedOutput()
		}
	}

	socket, _, err := writePoolValidated(systemUser, newVersion)
	if err != nil {
		return "", err
	}

	if err := renderAndReload(VhostOpts{
		DomainName: domainName,
		WebRoot:    SafeWebRoot(systemUser, webRoot),
		PHPSocket:  socket,
		PHPVersion: newVersion,
		CertPath:   certPath,
		KeyPath:    keyPath,
		SSLSource:  sslSource,
		Backend:    backend,
	}, systemUser); err != nil {
		return "", err
	}
	return socket, nil
}

// EnableSelfSigned generates a self-signed certificate with OpenSSL and re-renders the vhost with SSL.
func EnableSelfSigned(domainName, systemUser, phpVersion, backend string) (certPath, keyPath string, err error) {
	if err := ValidateDomain(domainName); err != nil {
		return "", "", err
	}
	domainName = strings.ToLower(strings.TrimSpace(domainName))
	phpVersion = normalizePHP(phpVersion)
	certPath, keyPath, err = generateSelfSigned(domainName)
	if err != nil {
		return "", "", err
	}
	if err := writeSSLVhost(domainName, systemUser, phpVersion, backend, certPath, keyPath, "self-signed"); err != nil {
		return "", "", err
	}
	removeHomeCertificate(systemUser, domainName)
	return certPath, keyPath, nil
}

// EnableLetsEncrypt obtains a certificate with acme.sh and re-renders the vhost with SSL.
//
// Rate-limit resilience (teardown fix — see ssl_heal.go):
//  1. REUSE-BEFORE-ISSUE: when a valid certificate (notAfter > now+30d, covers
//     the required hostnames, matching key) exists in the acme store or /etc/pki,
//     deploy it and SKIP issuance.
//     This never triggers a re-issue with the same SAN set (LE 429 rate-limit).
//  2. FAIL-SAFE: when issuance fails (including 429), sslFailSafe keeps 443 alive with the
//     existing/self-signed certificate. The vhost is never dropped to HTTP-only.
//
// IssueOutcome carries everything the caller needs to explain an issuance, as
// codes rather than prose: the panel is English and the interface ships twelve
// languages, so a sentence produced here could never be translated.
type IssueOutcome struct {
	// Real reports whether a real CA issued the certificate. False means the
	// self-signed fail-safe kept 443 alive instead.
	Real bool
	// Reason is the stable failure code when Real is false, empty otherwise.
	Reason string
	// Skipped maps a hostname left out of the SAN to the code explaining why.
	// A name is dropped so one unreachable host cannot fail the whole order, so
	// the caller has to be able to say which coverage the customer did not get.
	Skipped map[string]string
}

// skippedSANNames turns the probe's dropped-host map into the codes the screen
// renders, leaving the apex out.
//
// The apex is never partial coverage. When it fails there is no certificate to
// report a gap in, only a failure, and the caller reports it as the failure
// reason instead. Listing it here as well would show the owner a certificate
// that is missing one name when what they actually have is no certificate.
func skippedSANNames(droppedHosts map[string]challengeReason, apex string) map[string]string {
	skipped := map[string]string{}
	for host, reason := range droppedHosts {
		if host == apex {
			continue
		}
		skipped[host] = string(reason)
	}
	return skipped
}

func EnableLetsEncrypt(domainName, systemUser, phpVersion, backend string) (certPath, keyPath string, outcome IssueOutcome, err error) {
	if err := ValidateDomain(domainName); err != nil {
		return "", "", IssueOutcome{}, err
	}
	domainName = strings.ToLower(strings.TrimSpace(domainName))
	phpVersion = normalizePHP(phpVersion)

	sslDir, err := prepareCertificateDir(domainName)
	if err != nil {
		return "", "", IssueOutcome{}, err
	}
	certPath = filepath.Join(sslDir, domainName+".crt")
	keyPath = filepath.Join(sslDir, domainName+".key")

	// (1) Reuse-before-issue: skip a fresh issuance only when a valid real CA certificate exists.
	if src, srcKey := reusableLetsEncryptCertificate(domainName, 30); src != "" {
		if cp, kp, e := installToPKI(domainName, src, srcKey); e == nil {
			if e := writeSSLVhost(domainName, systemUser, phpVersion, backend, cp, kp, "letsencrypt"); e != nil {
				return "", "", IssueOutcome{}, e
			}
			removeHomeCertificate(systemUser, domainName)
			log.Printf("ssl reuse: %s valid letsencrypt certificate found; fresh LE issuance skipped (rate-limit protection)", domainName)
			return cp, kp, IssueOutcome{Real: true}, nil
		}
	}

	// An apex that does not resolve cannot pass http-01, so calling acme.sh would
	// only spend one of the five failed validations Let's Encrypt allows per
	// hostname per hour and leave the user with a generic failure. Refuse here
	// instead, keep 443 alive, and say what to fix. certSANHosts drops www when
	// DNS does not support it, so www alone never reaches this point.
	if !domainResolves(domainName) {
		return sslFailSafe(domainName, systemUser, phpVersion, backend, sslReason{
			Code:   sslReasonDNSUnresolved,
			Detail: domainName + " does not resolve, so Let's Encrypt cannot reach it for validation",
		})
	}

	// (2) Real issuance/renewal (only reached when <30 days remain or no cert exists).
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	_ = os.MkdirAll("/var/www/_acme", 0755)
	_, _ = tenantCommand("restorecon", "-R", "/var/www/_acme").CombinedOutput()

	// --force removed: acme.sh does not re-issue when it already has a valid cert
	// (rate-limit protection). It still renews inside the renewal window.
	//
	// www is added to the SAN only when DNS supports it (certSANHosts). If it is
	// eligible yet issuance still fails (e.g. www regressed between the DNS probe
	// and validation), retry apex-only before falling back to self-signed, because
	// a www-only failure must not drop the apex to the fail-safe path.
	buildIssueArgs := func(hosts []string) []string {
		a := []string{"--issue", "--webroot", "/var/www/_acme"}
		for _, host := range hosts {
			a = append(a, "-d", host)
		}
		return append(a, "--keylength", "2048")
	}
	// Measure each name before asking the CA for it. Resolving here does not mean
	// a name can answer http-01: a CDN in front, a filtered port 80, or another
	// vhost claiming the name all resolve perfectly well and still fail
	// validation, and one failing name fails the WHOLE order.
	sanHosts, droppedHosts := validatedSANHosts(certSANHosts(domainName))
	// The customer has to be able to see which coverage they did not get. A name
	// is dropped so one unreachable host cannot fail the whole order, and until
	// now that only reached the panel log.
	skipped := skippedSANNames(droppedHosts, domainName)
	if reason, apexFailed := droppedHosts[domainName]; apexFailed {
		// Ordering anyway would spend one of the five validation failures Let's
		// Encrypt allows per hostname per hour and leave the same result.
		// The probe already produced a code; passing it through keeps the screen
		// telling the owner which of the challenge failures they are looking at.
		return sslFailSafe(domainName, systemUser, phpVersion, backend, sslReason{
			Code:    string(reason),
			Detail:  domainName + " does not answer the ACME challenge path from the public internet",
			Skipped: skipped,
		})
	}
	out, e := RunACMEIssue(buildIssueArgs(sanHosts)...)
	// RENEW_SKIP means the store already holds a valid certificate for these hosts, so
	// there is nothing to retry and nothing to fail over: fall through to install-cert and
	// deploy what acme.sh already has. The reuse-before-issue check above only skips
	// issuance above 30 days, so this window is reachable.
	if e != nil && !IsACMERenewSkip(e) && len(sanHosts) > 1 {
		log.Printf("acme issue with www failed for %s, retrying apex-only: %s", domainName, strings.TrimSpace(string(out)))
		out, e = RunACMEIssue(buildIssueArgs([]string{domainName})...)
	}
	if e != nil && !IsACMERenewSkip(e) {
		// FAIL-SAFE (no teardown): keep 443 alive with the existing/self-signed cert.
		return sslFailSafe(domainName, systemUser, phpVersion, backend, classifySSLFailure(string(out)).with(skipped))
	}

	// Install the certificate into the target paths with acme.sh install-cert.
	insArgs := []string{
		"--install-cert",
		"-d", domainName,
		"--cert-file", certPath,
		"--key-file", keyPath,
		"--fullchain-file", certPath,
		"--reloadcmd", "systemctl reload nginx",
	}
	if out, e := acmeCommand(insArgs...).CombinedOutput(); e != nil {
		return sslFailSafe(domainName, systemUser, phpVersion, backend, sslReason{
			Code:    sslReasonInstallFailed,
			Detail:  summarizeSSLReason(string(out)),
			Skipped: skipped,
		})
	}
	if err := applyCertificatePermissions(sslDir, certPath, keyPath); err != nil {
		return "", "", IssueOutcome{}, err
	}
	if e := writeSSLVhost(domainName, systemUser, phpVersion, backend, certPath, keyPath, "letsencrypt"); e != nil {
		return "", "", IssueOutcome{}, e
	}
	removeHomeCertificate(systemUser, domainName)
	return certPath, keyPath, IssueOutcome{Real: true, Skipped: skipped}, nil
}

// domainResolves reports whether a hostname has any address record. Refusing
// issuance here keeps the site on its fail-safe certificate, so the answer is
// worth retrying: a resolver that is briefly unavailable would otherwise read as
// NXDOMAIN and cost the domain a real certificate until someone tries again.
func domainResolves(host string) bool {
	return len(lookupHostRetrying(host)) > 0
}

// DisableSSL re-renders the vhost without SSL while retaining certificate files for reuse.
func DisableSSL(domainName, systemUser, phpVersion, backend string) error {
	phpVersion = normalizePHP(phpVersion)
	_, socket, _ := phpPoolPath(systemUser, phpVersion)
	opts := VhostOpts{
		DomainName: domainName,
		WebRoot:    SafeWebRoot(systemUser, currentWebRoot(systemUser)),
		PHPSocket:  socket,
		PHPVersion: phpVersion,
		Backend:    backend,
	}
	// Same addon separation as writeSSLVhost: disabling SSL on an addon domain must
	// rewrite the addon's own conf, not the parent's dom_<sk>.conf.
	if wr, isAddon := addonDomainInfo(domainName); isAddon {
		opts.ConfigPath = addonVhostConfigPath(systemUser, domainName)
		opts.WebRoot = safeAddonWebRoot(systemUser, domainName, wr)
	}
	return renderAndReload(opts, systemUser)
}

func userExists(username string) bool {
	_, err := user.Lookup(username)
	return err == nil
}

func uidGid(username string) (int, int, error) {
	account, err := user.Lookup(username)
	if err != nil {
		return 0, 0, err
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	return uid, gid, nil
}

// ensureArchiveToolsOnce runs the archive-tool heal at most once per process (no repeated dnf).
var ensureArchiveToolsOnce sync.Once

// ensureArchiveTools guarantees that per-user ACL (setfacl, acl package) and the RAR extractor
// (bsdtar, libarchive) are installed on the host, at panel startup, BEFORE HealHomePerms and the
// file manager RAR extraction rely on them.
//
// Why this is needed (chicken-egg): servika-update updates itself first; the step that installs
// `dnf install acl bsdtar` exists only in the new update script, so it does not run on the first
// update. Without the tools, hardenHomePerms falls back to the fail-safe group=nginx model
// (per-user ACL only arrives on the second update) and .rar archives cannot be opened. This heal
// installs the tools from the panel's own startup, so per-user ACL isolation and RAR extraction
// are ready even on the first update + restart.
//
// Idempotent and once per process (sync.Once). When a tool is already on PATH, dnf is NOT called.
// When dnf is unavailable (different distribution or minimal environment), the heal is skipped
// silently so the existing fail-safe branches (group=nginx, RAR unar/unrar fallback) stay in
// effect. Each install is logged.
func ensureArchiveTools() {
	ensureArchiveToolsOnce.Do(func() {
		if _, err := exec.LookPath("dnf"); err != nil {
			return
		}
		if _, err := exec.LookPath("setfacl"); err != nil {
			if out, err := exec.Command("dnf", "install", "-y", "acl").CombinedOutput(); err != nil {
				log.Printf("archive-tool heal: 'acl' install failed (fail-safe group=nginx in effect): %s", strings.TrimSpace(string(out)))
			} else {
				log.Printf("archive-tool heal: 'acl' (setfacl) installed; per-user ACL isolation active on first update")
			}
		}
		if _, err := exec.LookPath("bsdtar"); err != nil {
			if out, err := exec.Command("dnf", "install", "-y", "bsdtar").CombinedOutput(); err != nil {
				log.Printf("archive-tool heal: 'bsdtar' install failed (RAR may fall back to unar/unrar): %s", strings.TrimSpace(string(out)))
			} else {
				log.Printf("archive-tool heal: 'bsdtar' (libarchive) installed; RAR extraction ready on first update")
			}
		}
	})
}

const homeACLSentinel = "/var/lib/servika/.home_acl_v1_done"

func aclAvailable() bool {
	_, err := exec.LookPath("setfacl")
	return err == nil
}

// nginxCanRead reports whether the nginx account can actually reach the document
// root.
//
// setfacl can exit 0 while the filesystem silently ignores the ACL (mounted
// without acl support, or a filesystem type that does not honour it). The mode
// bits then stay 0710/0750 with no access for other, nginx cannot read anything,
// and the site answers 403 with nothing in any log to explain it. A real read
// attempt as nginx is the only trustworthy signal.
func nginxCanRead(publicHTML string) bool {
	target := filepath.Join(publicHTML, "index.html")
	if _, err := os.Stat(target); err != nil {
		target = publicHTML // a freshly provisioned root may still be empty
	}
	return tenantCommand("runuser", "-u", "nginx", "--", "test", "-r", target).Run() == nil
}

// applyLegacyHomePerms serves the document root through group ownership instead
// of per-user ACLs, for hosts where the ACL model cannot work.
//
// The permission bits are IDENTICAL to the ACL model (home 0710, public_html
// 0750, no access for other) — this fallback must never loosen isolation to
// 0711/0755, which would expose every tenant's document root to every other
// tenant. The group is carried recursively so existing sub-directories (created
// 0750 and owned by the tenant) stay reachable, and setgid makes new content
// inherit the nginx group, which is what the default ACL does in the other model.
func applyLegacyHomePerms(home string, uid, nginxGID int) {
	publicHTML := filepath.Join(home, "public_html")
	_ = os.Chown(home, uid, nginxGID)
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	_ = os.Chmod(home, 0710)
	// -h -P: act on a symlink itself and never descend through one, so a planted
	// symlink cannot redirect the ownership change outside the tenant tree.
	if output, err := tenantCommand("chown", "-R", "-h", "-P",
		fmt.Sprintf("%d:%d", uid, nginxGID), publicHTML).CombinedOutput(); err != nil {
		log.Printf("tenant home permissions: group fallback chown failed for %s: %s",
			publicHTML, strings.TrimSpace(string(output)))
	}
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	_ = os.Chmod(publicHTML, 0750|os.ModeSetgid)
}

func hardenHomePerms(home, systemUser string, uid, gid int) bool {
	publicHTML := filepath.Join(home, "public_html")
	if !managedPublicHTML(publicHTML, systemUser) {
		log.Printf("tenant home permissions: rejected unmanaged path %s", publicHTML)
		return false
	}
	if aclAvailable() {
		_ = os.Chown(home, uid, gid)
		// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
		_ = os.Chmod(home, 0710)
		_ = os.Chown(publicHTML, uid, gid)
		// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
		_ = os.Chmod(publicHTML, 0750)
		if output, err := tenantCommand("setfacl", "-m", "u:nginx:--x", home).CombinedOutput(); err != nil {
			log.Printf("tenant home permissions: home ACL failed for %s: %s", systemUser, strings.TrimSpace(string(output)))
			return false
		}
		if output, err := tenantCommand("setfacl", "-m", "u:nginx:rX", publicHTML).CombinedOutput(); err != nil {
			log.Printf("tenant home permissions: document root ACL failed for %s: %s", systemUser, strings.TrimSpace(string(output)))
			return false
		}
		if output, err := tenantCommand("setfacl", "-d", "-m", "u:nginx:rX", publicHTML).CombinedOutput(); err != nil {
			log.Printf("tenant home permissions: default ACL failed for %s: %s", systemUser, strings.TrimSpace(string(output)))
			return false
		}
		// Every setfacl call reported success, which is not proof the filesystem
		// honoured them. Verify before trusting the ACL model.
		if nginxCanRead(publicHTML) {
			return true
		}
		log.Printf("tenant home permissions: ACLs are ineffective on this filesystem for %s, using the nginx group instead (0710/0750 preserved)", systemUser)
	}

	if _, nginxGID, err := uidGid("nginx"); err == nil {
		applyLegacyHomePerms(home, uid, nginxGID)
		return false
	}
	log.Printf("tenant home permissions: ACL tools and nginx account unavailable for %s", systemUser)
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	_ = os.Chmod(home, 0711)
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	_ = os.Chmod(publicHTML, 0755)
	return false
}

func managedPublicHTML(path, systemUser string) bool {
	if !tenantUserPattern.MatchString(systemUser) {
		return false
	}
	expected := filepath.Join("/home", systemUser, "public_html")
	if filepath.Clean(path) != expected {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func hardenHomePermsRecursive(publicHTML, systemUser string) bool {
	if !managedPublicHTML(publicHTML, systemUser) || !aclAvailable() {
		return false
	}
	output, err := tenantCommand("setfacl", "-R", "-P", "-m", "u:nginx:rX", publicHTML).CombinedOutput()
	if err != nil {
		log.Printf("tenant home permissions: recursive ACL failed for %s: %s", systemUser, strings.TrimSpace(string(output)))
		return false
	}
	return true
}

// ReapplyPublicHTMLACL reapplies the nginx read ACL (u:nginx:rX + default ACL)
// recursively across a tenant's public_html. The file-manager permission-reset
// re-runs this after a chmod sweep, since a chmod (or a restore without --acls)
// can strip the ACL that lets nginx/PHP-FPM read the site.
func ReapplyPublicHTMLACL(publicHTML, systemUser string) bool {
	return hardenHomePermsRecursive(publicHTML, systemUser)
}

// HealHomePerms applies tenant-isolating ownership and permissions to existing managed homes.
func HealHomePerms() {
	if packageDB == nil {
		return
	}
	rows, err := packageDB.Query(`SELECT DISTINCT system_user FROM domains`)
	if err != nil {
		log.Printf("heal tenant home permissions: %v", err)
		return
	}
	defer func() { _ = rows.Close() }()

	_, sentinelErr := os.Stat(homeACLSentinel)
	migrateExisting := os.IsNotExist(sentinelErr)
	updated := 0
	migrationSucceeded := aclAvailable()
	for rows.Next() {
		var systemUser string
		if err := rows.Scan(&systemUser); err != nil || !tenantUserPattern.MatchString(systemUser) {
			continue
		}
		home := filepath.Join("/home", systemUser)
		info, err := os.Lstat(home)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		uid, gid, err := uidGid(systemUser)
		if err != nil {
			continue
		}
		if !hardenHomePerms(home, systemUser, uid, gid) {
			migrationSucceeded = false
		}
		if migrateExisting && !hardenHomePermsRecursive(filepath.Join(home, "public_html"), systemUser) {
			migrationSucceeded = false
		}
		updated++
	}
	if err := rows.Err(); err != nil {
		log.Printf("heal tenant home permissions rows: %v", err)
		migrationSucceeded = false
	}
	if updated > 0 {
		log.Printf("healed permissions for %d tenant homes", updated)
	}
	if migrateExisting && migrationSucceeded {
		// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
		if err := os.MkdirAll(filepath.Dir(homeACLSentinel), 0755); err != nil {
			log.Printf("heal tenant home permissions: could not create sentinel directory: %v", err)
			return
		}
		// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
		if err := os.WriteFile(homeACLSentinel, []byte("done\n"), 0644); err != nil {
			log.Printf("heal tenant home permissions: could not write sentinel: %v", err)
		}
	}
}

func tenantCommand(name string, args ...string) *exec.Cmd {
	return tenantCommandContext(context.Background(), name, args...)
}

func tenantCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed/config binary with separate args (no shell); callers pass validated tenant input.
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
	}
	return command
}

func acmeCommand(args ...string) *exec.Cmd {
	return acmeCommandContext(context.Background(), args...)
}

func acmeCommandContext(ctx context.Context, args ...string) *exec.Cmd {
	command := tenantCommandContext(ctx, config.ACMEBin(), args...)
	command.Env = append(command.Env, "HOME="+config.ACMEHome())
	return command
}

// SuspendUserRuntime disables or restores cron execution and terminates managed tenant processes.
func SuspendUserRuntime(systemUser string, suspended bool) {
	if !tenantUserPattern.MatchString(systemUser) {
		return
	}
	const suspendedCronDir = "/var/lib/servika/cron-suspended"
	cronSpool := filepath.Join("/var/spool/cron", systemUser)
	storedCron := filepath.Join(suspendedCronDir, systemUser)

	if suspended {
		if _, err := os.Stat(cronSpool); err == nil {
			if err := os.MkdirAll(suspendedCronDir, 0700); err != nil {
				log.Printf("suspend tenant runtime: create cron store for %s: %v", systemUser, err)
			} else if err := os.Rename(cronSpool, storedCron); err != nil {
				log.Printf("suspend tenant runtime: disable crontab for %s: %v", systemUser, err)
			}
		}
		_, _ = tenantCommand("pkill", "-KILL", "-u", systemUser).CombinedOutput()
		return
	}

	if _, err := os.Stat(storedCron); err == nil {
		if err := os.MkdirAll("/var/spool/cron", 0700); err != nil {
			log.Printf("resume tenant runtime: create cron spool for %s: %v", systemUser, err)
			return
		}
		if err := os.Rename(storedCron, cronSpool); err != nil {
			log.Printf("resume tenant runtime: restore crontab for %s: %v", systemUser, err)
			return
		}
		_ = os.Chmod(cronSpool, 0600)
		_, _ = tenantCommand("restorecon", cronSpool).CombinedOutput()
	}
}

// ApplyVhostForDomain re-renders an nginx vhost for a domain ID.
// It runs after PHP version or socket changes and loads SSL settings from the database.
func ApplyVhostForDomain(db *sql.DB, domainID int64, socket, phpVersion string) error {
	return applyVhostForDomain(db, domainID, socket, phpVersion, nil, nil)
}

func applyVhostForDomain(db *sql.DB, domainID int64, socket, phpVersion string, certPathOverride, keyPathOverride *string) error {
	var domainName, systemUser, certPath, keyPath, sslSource, backend, webRoot, customVhostContent string
	var suspended, customVhostEnabled int
	var parentDomainID sql.NullInt64
	if err := db.QueryRow(
		`SELECT domain_name, system_user, COALESCE(cert_path,''), COALESCE(key_path,''), COALESCE(ssl_source,''),
		        COALESCE(web_backend,'php-fpm'), COALESCE(web_root,''), COALESCE(suspended,0),
		        COALESCE(custom_vhost_enabled,0), COALESCE(custom_vhost_content,''), parent_domain_id
		 FROM domains WHERE id=?`, domainID).
		Scan(&domainName, &systemUser, &certPath, &keyPath, &sslSource, &backend, &webRoot, &suspended,
			&customVhostEnabled, &customVhostContent, &parentDomainID); err != nil {
		return fmt.Errorf("read domain details: %w", err)
	}
	if certPathOverride != nil && keyPathOverride != nil {
		certPath = *certPathOverride
		keyPath = *keyPathOverride
	}
	if TenantFPMActive(systemUser) {
		socket = tenantSocket(systemUser)
	}

	webRoot = SafeWebRoot(systemUser, webRoot)
	configPath := "/etc/nginx/conf.d/dom_" + systemUser + ".conf"
	if parentDomainID.Valid {
		configPath = addonVhostConfigPath(systemUser, domainName)
		webRoot = safeAddonWebRoot(systemUser, domainName, webRoot)
	}

	// Default nginx settings to enabled when no row exists.
	opts := VhostOpts{
		ConfigPath:      configPath,
		DomainName:      domainName,
		WebRoot:         webRoot,
		PHPSocket:       socket,
		PHPVersion:      phpVersion,
		CertPath:        certPath,
		KeyPath:         keyPath,
		SSLSource:       sslSource,
		Backend:         backend,
		Suspended:       suspended == 1,
		HdrXContentType: true, HdrXXSS: true, HdrReferrer: true,
		HdrPermissions: true, HdrCSPUpgrade: true, HdrHSTS: true,
		HSTSMaxAge: 31536000, HSTSSubdomains: true, HSTSPreload: false,
	}
	if customVhostEnabled == 1 {
		opts.CustomVhostContent = customVhostContent
	}
	// Disable FastCGI cache and enable a 30-day browser cache by default.
	opts.FastCgiCache = false
	opts.FastCgiCacheMinutes = 60
	opts.BrowserCache = true
	opts.BrowserCacheDays = 30

	var b1, b2, b3, b4, b5, b6, b7, b8, bFC, bBC int
	var maxAge, fastCgiCacheMinutes, browserCacheDays int
	var extraDirectives string
	err := db.QueryRow(
		`SELECT hdr_x_content_type, hdr_x_xss, hdr_referrer, hdr_permissions,
		        hdr_csp_upgrade, hdr_hsts, hsts_max_age, hsts_subdomains, hsts_preload, extra_directives,
		        fastcgi_cache, fastcgi_cache_minutes, browser_cache, browser_cache_days
		 FROM nginx_settings WHERE domain_id=? AND subdomain_id=0`, domainID).
		Scan(&b1, &b2, &b3, &b4, &b5, &b6, &maxAge, &b7, &b8, &extraDirectives,
			&bFC, &fastCgiCacheMinutes, &bBC, &browserCacheDays)
	if err == nil {
		opts.HdrXContentType = b1 == 1
		opts.HdrXXSS = b2 == 1
		opts.HdrReferrer = b3 == 1
		opts.HdrPermissions = b4 == 1
		opts.HdrCSPUpgrade = b5 == 1
		opts.HdrHSTS = b6 == 1
		opts.HSTSMaxAge = maxAge
		opts.HSTSSubdomains = b7 == 1
		opts.HSTSPreload = b8 == 1
		opts.ExtraDirectives = extraDirectives
		opts.FastCgiCache = bFC == 1
		opts.FastCgiCacheMinutes = fastCgiCacheMinutes
		opts.BrowserCache = bBC == 1
		opts.BrowserCacheDays = browserCacheDays
	}
	// The FastCGI read timeout follows the domain's own max_execution_time, or
	// nginx gives up before PHP does and the panel reports a limit no visitor
	// ever reaches. A domain with no php_settings row gets the same default the
	// panel shows it.
	opts.MaxExecutionTime = phpdefaults.MaxExecutionTime
	var maxExecutionTime int
	if err := db.QueryRow(
		`SELECT max_execution_time FROM php_settings WHERE domain_id=? AND subdomain_id=0`,
		domainID).Scan(&maxExecutionTime); err == nil && maxExecutionTime > 0 {
		opts.MaxExecutionTime = maxExecutionTime
	}
	// Add protected-directory .htpasswd blocks regardless of whether nginx_settings has a row.
	if pb := buildProtectedBlocks(db, domainID, 0, socket); pb != "" {
		if opts.ExtraDirectives != "" {
			opts.ExtraDirectives += "\n"
		}
		opts.ExtraDirectives += pb
	}
	return renderAndReload(opts, systemUser)
}

// RerenderVhost resolves a domain's PHP socket and re-renders its vhost.
func RerenderVhost(db *sql.DB, domainID int64) error {
	var systemUser, phpVersion string
	if err := db.QueryRow(
		`SELECT system_user, php_version FROM domains WHERE id=?`, domainID).
		Scan(&systemUser, &phpVersion); err != nil {
		return err
	}
	socket, err := PHPSocketFor(systemUser, phpVersion)
	if err != nil {
		socket = "/run/php-fpm/" + systemUser + ".sock"
	}
	return ApplyVhostForDomain(db, domainID, socket, phpVersion)
}

// PHPSocketFor returns the active tenant or shared socket path.
func PHPSocketFor(systemUser, phpVersion string) (string, error) {
	if TenantFPMActive(systemUser) {
		return tenantSocket(systemUser), nil
	}
	return sharedSocketPath(systemUser, phpVersion)
}

func sharedSocketPath(systemUser, phpVersion string) (string, error) {
	phpVersion = normalizePHP(phpVersion)
	// AppStream 8.3
	if phpVersion == "8.3" {
		return "/run/php-fpm/" + systemUser + ".sock", nil
	}
	// Remi pattern: 5.6 -> 56, 7.4 -> 74, 8.2 -> 82
	versionCode := strings.Replace(phpVersion, ".", "", 1)
	if len(versionCode) >= 2 {
		socketDir := "/var/opt/remi/php" + versionCode + "/run/php-fpm"
		// Verify that the service is installed.
		if _, err := os.Stat("/opt/remi/php" + versionCode + "/root/usr/sbin/php-fpm"); err == nil {
			return socketDir + "/" + systemUser + ".sock", nil
		}
	}
	return "", fmt.Errorf("unsupported or uninstalled version: %s", phpVersion)
}

// ProtectedBlocks generates the nginx auth_basic blocks for one document root.
// subdomainID 0 selects the domain's own root; a non-zero value selects that
// subdomain's root. Callers outside this package use this to render a vhost with
// exactly the protection rows that belong to the scope they are rendering.
func ProtectedBlocks(db *sql.DB, domainID, subdomainID int64, socket string) string {
	return buildProtectedBlocks(db, domainID, subdomainID, socket)
}

// buildProtectedBlocks generates nginx auth_basic location blocks from protected_directories.
// Each protected path receives an outer prefix location and a nested .php location that prevents PHP source disclosure.
// The subdomain_id filter is what keeps the scopes separate: a subdomain's rows must
// never leak into the parent domain's vhost, so the domain scope matches 0 exactly
// rather than selecting every row for the domain.
func buildProtectedBlocks(db *sql.DB, domainID, subdomainID int64, socket string) string {
	rows, err := db.Query(`SELECT DISTINCT path, htpasswd_file FROM protected_directories WHERE domain_id=? AND subdomain_id=? ORDER BY path`, domainID, subdomainID)
	if err != nil {
		return ""
	}
	defer func() { _ = rows.Close() }()
	var b strings.Builder
	for rows.Next() {
		var path, file string
		if err := rows.Scan(&path, &file); err != nil {
			continue
		}
		if path == "/" {
			// The root path cannot use a separate "location /" because it duplicates the required
			// existing prefix and nginx rejects it. Define auth_basic at the server level instead,
			// allowing all locations, including PHP, to inherit it. The acme-challenge location
			// remains exempt through "auth_basic off", so Let's Encrypt issuance and renewal work.
			fmt.Fprintf(&b, `    auth_basic "Authentication Required";
    auth_basic_user_file %s;
`, file)
			continue
		}
		fmt.Fprintf(&b, `    location ^~ %s {
        auth_basic "Authentication Required";
        auth_basic_user_file %s;
        location ~ \.php$ {
            auth_basic "Authentication Required";
            auth_basic_user_file %s;
            try_files $uri =404;
            fastcgi_split_path_info ^(.+\.php)(/.+)$;
            fastcgi_pass unix:%s;
            fastcgi_index index.php;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param HTTPS on;
        }
    }
`, path, file, file, socket)
	}
	_ = rows.Err()
	return b.String()
}

const (
	// vhostHardenSentinel gates the sweep below, which is the ONLY thing that
	// re-renders an existing tenant's FPM pool and vhost after an update. A
	// change to either template therefore reaches a fresh install only, unless
	// this version is raised in the same commit.
	//
	// v3 delivers two changes that are invisible without it: the raised PHP
	// limits (the pool is re-rendered by writePoolValidated below) and the
	// FastCGI read timeout derived from max_execution_time.
	//
	// v4 delivers the mandatory disable_functions floor to shared-master tenants:
	// RenderPool now merges it, so writePoolValidated below re-renders the pool with
	// the LPE primitives blocked. Own-master tenants already receive it through
	// EnsureTenantFPMOnStartup's repairTenantPoolDrift, which is not sentinel-gated.
	//
	// v5 delivers the per-tenant opcache.enable flag to shared-master tenants:
	// RenderPool now writes php_admin_flag[opcache.enable] from the stored setting,
	// so an operator turning OPcache off in the panel reaches the pool. Own-master
	// tenants again receive it through repairTenantPoolDrift.
	vhostHardenSentinel = "/var/lib/servika/.vhost_hardening_v5_done"
	panelVhostPath      = "/etc/nginx/conf.d/_panel.conf"
	panelSecSentinel    = "# SERVIKA-PANEL-SEC v2"
)

func healVhostsOnStartup() {
	if packageDB == nil {
		return
	}
	if _, err := os.Stat(vhostHardenSentinel); err == nil {
		return
	}

	rows, err := packageDB.Query(`SELECT id, system_user, php_version FROM domains`)
	if err != nil {
		log.Printf("vhost hardening: could not list domains: %v", err)
		return
	}
	type domain struct {
		id         int64
		systemUser string
		phpVersion string
	}
	var domains []domain
	rowReadFailed := false
	for rows.Next() {
		var item domain
		if err := rows.Scan(&item.id, &item.systemUser, &item.phpVersion); err != nil {
			log.Printf("vhost hardening: could not read domain row: %v", err)
			rowReadFailed = true
			continue
		}
		domains = append(domains, item)
	}
	rowsErr := rows.Err()
	_ = rows.Close()
	if rowsErr != nil {
		log.Printf("vhost hardening: domain iteration failed: %v", rowsErr)
		return
	}
	if rowReadFailed {
		log.Printf("vhost hardening: at least one domain row could not be read, retry scheduled for next startup")
		return
	}

	failed := 0
	for _, item := range domains {
		domainFailed := false
		var socket string
		if TenantFPMActive(item.systemUser) {
			socket = tenantSocket(item.systemUser)
		} else {
			resolved, _, err := writePoolValidated(item.systemUser, item.phpVersion)
			if err != nil {
				log.Printf("vhost hardening: %s PHP pool update failed: %v", item.systemUser, err)
				domainFailed = true
				if fallback, resolveErr := sharedSocketPath(item.systemUser, item.phpVersion); resolveErr == nil {
					resolved = fallback
				}
			}
			socket = resolved
			if socket == "" {
				socket = "/run/php-fpm/" + item.systemUser + ".sock"
			}
		}
		if err := ApplyVhostForDomain(packageDB, item.id, socket, item.phpVersion); err != nil {
			log.Printf("vhost hardening: %s vhost update failed: %v", item.systemUser, err)
			domainFailed = true
		}
		if domainFailed {
			failed++
		}
	}
	if failed != 0 {
		log.Printf("vhost hardening: %d of %d domains failed, retry scheduled for next startup", failed, len(domains))
		return
	}

	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(filepath.Dir(vhostHardenSentinel), 0755); err != nil {
		log.Printf("vhost hardening: could not create sentinel directory: %v", err)
		return
	}
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(vhostHardenSentinel, []byte("done\n"), 0644); err != nil {
		log.Printf("vhost hardening: could not write sentinel: %v", err)
	}
}

func healPanelVhostHeadersOnStartup() {
	original, err := os.ReadFile(panelVhostPath)
	if err != nil {
		return
	}
	content := string(original)
	if strings.Contains(content, panelSecSentinel) {
		updatedServerName := strings.Replace(content, "server_name _;", "server_name _servika_panel_;", 1)
		if updatedServerName != content {
			// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
			if err := os.WriteFile(panelVhostPath, []byte(updatedServerName), 0644); err != nil {
				log.Printf("panel security repair: could not update panel server name: %v", err)
				return
			}
			if output, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
				// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
				_ = os.WriteFile(panelVhostPath, original, 0644)
				log.Printf("panel security repair: server name nginx -t failed, vhost restored: %s", strings.TrimSpace(string(output)))
				return
			}
			if output, err := exec.Command("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
				// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
				_ = os.WriteFile(panelVhostPath, original, 0644)
				log.Printf("panel security repair: server name nginx reload failed, vhost restored: %s", strings.TrimSpace(string(output)))
				return
			}
			log.Printf("panel security repair: panel server name updated + nginx reloaded")
			return
		}
		// Older v2 installs hardened the panel before the domain-preview iframe
		// needed frame-src. Retrofit it even when the sentinel is present. The
		// match is scoped to the strict SPA CSP (unique `script-src 'self';`) so
		// the relaxed phpMyAdmin/Roundcube CSPs are left untouched; ReplaceAll
		// covers both the server-level and `location /` copies at once.
		const oldStrictCSP = "script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: blob:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'self'"
		const newStrictCSP = "script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: blob:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self'; frame-src https: http:; frame-ancestors 'self'"
		patched := strings.ReplaceAll(content, oldStrictCSP, newStrictCSP)
		// object-src falls back to default-src, which is 'self', so a same-origin
		// upload served back to the browser could still be embedded as a plugin
		// object. Nothing the panel or phpMyAdmin serves needs one.
		//
		// The anchor covers the strict and the relaxed copies alike, and the
		// replacement consumes it, so re-running finds nothing left to do.
		const beforeObjectSrc = "frame-ancestors 'self'; base-uri 'self'"
		const afterObjectSrc = "frame-ancestors 'self'; object-src 'none'; base-uri 'self'"
		patched = strings.ReplaceAll(patched, beforeObjectSrc, afterObjectSrc)
		if patched == content {
			return // already current
		}
		// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
		if err := os.WriteFile(panelVhostPath, []byte(patched), 0644); err != nil {
			log.Printf("panel security repair: could not update CSP: %v", err)
			return
		}
		if output, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
			// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
			_ = os.WriteFile(panelVhostPath, original, 0644)
			log.Printf("panel security repair: CSP nginx -t failed, vhost restored: %s", strings.TrimSpace(string(output)))
			return
		}
		if output, err := exec.Command("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
			// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
			_ = os.WriteFile(panelVhostPath, original, 0644)
			log.Printf("panel security repair: CSP nginx reload failed, vhost restored: %s", strings.TrimSpace(string(output)))
			return
		}
		log.Printf("panel security repair: CSP updated for the domain preview + nginx reloaded")
		return
	}
	anchor := "server_name _servika_panel_;"
	anchorIndex := strings.Index(content, anchor)
	if anchorIndex < 0 {
		anchor = "server_name _;"
		anchorIndex = strings.Index(content, anchor)
	}
	if anchorIndex < 0 {
		log.Printf("panel security repair: panel server name anchor not found")
		return
	}

	headers := "\n    " + panelSecSentinel + "\n" +
		"    add_header X-Content-Type-Options \"nosniff\" always;\n" +
		"    add_header X-Frame-Options \"SAMEORIGIN\" always;\n" +
		"    add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n" +
		"    add_header Permissions-Policy \"geolocation=(), microphone=(), camera=(), interest-cohort=()\" always;\n" +
		"    add_header Content-Security-Policy \"" + panelStrictCSP + "\" always;\n" +
		"    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
	insertAt := anchorIndex + len(anchor)
	updated := content[:insertAt] + headers + content[insertAt:]

	cacheHeader := "        add_header Cache-Control \"public\";"
	repeatedHeaders := cacheHeader + "\n" +
		"        add_header X-Content-Type-Options \"nosniff\" always;\n" +
		"        add_header X-Frame-Options \"SAMEORIGIN\" always;\n" +
		"        add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n" +
		"        add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
	updated = strings.ReplaceAll(updated, cacheHeader, repeatedHeaders)

	// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(panelVhostPath, []byte(updated), 0644); err != nil {
		log.Printf("panel security repair: could not write vhost: %v", err)
		return
	}
	if output, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
		// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
		_ = os.WriteFile(panelVhostPath, original, 0644)
		log.Printf("panel security repair: nginx -t failed, vhost restored: %s", strings.TrimSpace(string(output)))
		return
	}
	if output, err := exec.Command("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
		log.Printf("panel security repair: nginx reload failed: %s", strings.TrimSpace(string(output)))
	}
}

// SecurityHeaderBlock renders the add_header block a vhost emits for the given
// settings. It is exported so a subdomain vhost, which is assembled outside this
// package, gets byte-for-byte the same header set as the domain's own vhost instead
// of a second hand-maintained copy that would drift.
func SecurityHeaderBlock(opts VhostOpts) string {
	return buildSecurityHeaders(opts)
}

// EnsureCacheZone makes sure the shared FastCGI cache zone exists before a vhost
// references it. nginx refuses to load a config naming an undefined keys_zone, so a
// caller enabling the cache must call this first.
func EnsureCacheZone() error {
	_, err := ensureCacheZone()
	return err
}

// CacheZoneName is the keys_zone every Servika vhost uses for FastCGI caching.
const CacheZoneName = cacheZoneName
