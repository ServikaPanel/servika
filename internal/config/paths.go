package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	DefaultEnvFile      = "/etc/servika/env"
	DefaultComposerBin  = "/usr/local/bin/composer"
	DefaultWPCLIBin     = "/usr/local/bin/wp"
	DefaultClamScanBin  = "/usr/bin/clamscan"
	DefaultFreshclamBin = "/usr/bin/freshclam"
	DefaultPECLBin      = "/usr/bin/pecl"
	// DefaultReadPSTBin converts an Outlook .pst export into Maildir folders. It
	// comes from libpst, which EL10 may not package, so callers report its absence
	// as a supported-format answer rather than failing an upload with it.
	DefaultReadPSTBin        = "/usr/bin/readpst"
	DefaultRemiPECLRoot      = "/opt/remi"
	DefaultACMEHome          = "/root/.acme.sh"
	DefaultACMEBin           = "/root/.acme.sh/acme.sh"
	DefaultBackupRoot        = "/var/backups/servika"
	DefaultLaravelLogDir     = "/var/log/servika-laravel"
	DefaultPluginRoot        = "/opt/servika/plugins"
	DefaultLogDir            = "/opt/servika/logs"
	DefaultUpdateLog         = "/opt/servika/logs/update.log"
	DefaultKernelCareLog     = "/opt/servika/logs/kernelcare-update.log"
	DefaultKernelCareWrapper = "/opt/servika/kernelcare-update.sh"
	DefaultCVELog            = "/opt/servika/logs/cve-update.log"
	DefaultPHPOpLog          = "/opt/servika/logs/php-op.log"
	DefaultPHPOpState        = "/opt/servika/php-op.json"
	DefaultPHPOpWrapper      = "/opt/servika/php-op.sh" // #nosec G101 -- filesystem path, not a credential
	// Node and Python runtime installation, mirroring the PHP operation above.
	DefaultRuntimeOpLog     = "/opt/servika/logs/runtime-op.log"
	DefaultRuntimeOpState   = "/opt/servika/runtime-op.json"
	DefaultRuntimeOpWrapper = "/opt/servika/runtime-op.sh" // #nosec G101 -- filesystem path, not a credential
	// DefaultNodeRoot is where the `n` version manager keeps its installations.
	DefaultNodeRoot = "/usr/local/n/versions/node"
	// DefaultAppLogDir holds one log per application. It is root-owned on
	// purpose: systemd's StandardOutput=append: follows a symlink, so a tenant
	// who could write the directory could redirect a root-opened descriptor.
	DefaultAppLogDir = "/var/log/servika-apps"
	// DefaultTenantFPMLogDir holds one PHP-FPM error log per tenant. It is
	// deliberately NOT under /var/log/php-fpm: the distribution's own logrotate
	// rule globs `/var/log/php-fpm/*log` and signals only the SYSTEM master's
	// pid file, so it rotated every tenant log away and left each tenant master
	// writing to a deleted inode (measured on AlmaLinux 10). A second rule for
	// the same paths is not an option either, because logrotate refuses a
	// duplicate entry and skips the file altogether.
	DefaultTenantFPMLogDir = "/var/log/servika-fpm"
	// DefaultAppEnvDir holds one EnvironmentFile per application, each 0600
	// root-owned: systemd parses the file in the manager process as root, so
	// the service's own user never opens it and needs no access.
	DefaultAppEnvDir = "/etc/servika/apps"
	// DefaultGeoIPDir holds the downloaded country database and the nginx
	// include generated from it. It sits on persistent state rather than under
	// /opt/servika because servika-update replaces bin/, frontend-dist and src/
	// only, and a database re-downloaded on every update would spend the
	// operator's MaxMind allowance for nothing.
	DefaultGeoIPDir = "/var/lib/servika/geoip"
	// DefaultQuarantineDir holds files the malware scanner took out of a tenant
	// tree. It sits OUTSIDE every home on purpose: the tenant owns their home, so
	// a quarantine directory there can be emptied or carried back by the same
	// account that planted the file, it is charged to their disk quota, and it
	// joins their backups. Root-owned 0700, one directory per system user.
	DefaultQuarantineDir = "/var/lib/servika/quarantine"
	// DefaultWPChecksumDir holds the WordPress core checksum tables the panel
	// fetched from wordpress.org, one file per version and locale. It sits on
	// persistent state rather than under /opt/servika for the same reason the
	// GeoIP database does: servika-update replaces bin/, frontend-dist and src/
	// only, and a table re-downloaded on every update would leave the integrity
	// check offline for exactly as long as wordpress.org is unreachable.
	DefaultWPChecksumDir = "/var/lib/servika/wp-checksums"
	// DefaultAVRulesFile holds the last signed malware rule package that
	// verified. It sits on persistent state for the same reason the GeoIP
	// database does: servika-update replaces bin/, frontend-dist and src/ only,
	// and a package re-fetched on every update would leave the scanner on the
	// built-in set for as long as the publication host is unreachable. The scan
	// worker and the real-time watcher are separate processes and read this file
	// rather than the network, so the panel is the only thing that fetches.
	DefaultAVRulesFile = "/var/lib/servika/av/rules.svkav"
	// DefaultAVCacheFile records, per file the sweep inspected and found clean,
	// the size, mtime and ctime it had at that moment. The next sweep skips a
	// file whose three values still match, which is what makes a nightly sweep
	// of a whole server cheap. It sits on persistent state beside the rule
	// package, because a cache thrown away on every update would make the first
	// sweep after each release a full one.
	DefaultAVCacheFile = "/var/lib/servika/av/rapidscan.json"

	// DefaultMySQLSocket is where MariaDB listens locally.
	//
	// It is the ONLY way to reach a tenant database account: the panel creates
	// every one of them as 'user'@'localhost' (credentials.MySQLCreateScopedUser),
	// and MariaDB treats a TCP connection to 127.0.0.1 as a different host, so
	// it answers access denied. The panel's own connection is the exception,
	// because the installer creates 'panel'@'127.0.0.1' deliberately.
	DefaultMySQLSocket = "/var/lib/mysql/mysql.sock"
	// DefaultTuningBackupDir holds the copy of a configuration file taken before
	// the tuning screen edits it. The copy is what a revert restores, so it must
	// outlive the panel process and must NOT sit beside the file it copies:
	// /etc/nginx/conf.d and /etc/my.cnf.d are both read wholesale by their
	// daemon, and a backup left there is loaded as configuration.
	DefaultTuningBackupDir = "/var/lib/servika/tuning-backups"
	// DefaultHostAppRoot holds one directory per server-level application, each
	// owned by that application's own svk_ account. It is NOT under /home:
	// everything there belongs to a tenant, and a directory in that tree would be
	// swept by the disk-usage scan, the quota enforcement and the backup schedule,
	// none of which this application has.
	DefaultHostAppRoot = "/opt/servika-apps"
	// DefaultHostAppLogDir holds one log per server-level application, root-owned
	// for the same reason as DefaultAppLogDir: systemd's StandardOutput=append:
	// follows a symlink, so a directory the service's own account could write
	// would let it redirect a root-opened descriptor.
	DefaultHostAppLogDir = "/var/log/servika-hostapps"
	// DefaultHostAppEnvDir holds one EnvironmentFile per server-level
	// application, each 0600 root-owned. `systemctl show` hands every
	// Environment= value to any local account, and these carry admin tokens.
	DefaultHostAppEnvDir = "/etc/servika/host-apps"
	// DefaultHostAppBackupDir holds the archive taken of an application's data
	// directory before it is removed. Removal is the one operation here that
	// cannot be undone, and the data belongs to the operator rather than to the
	// panel, so it is kept outside the tree that removal deletes.
	DefaultHostAppBackupDir = "/var/lib/servika/host-app-backups"
	// DefaultMariaDBSlowLog is the panel's OWN slow query log, deliberately not
	// MariaDB's default mariadb-slow.log name: an operator who already turned the
	// slow log on keeps their file and their logrotate rule, and the panel never
	// reads or truncates it. The file records every tenant's SQL, so the heal that
	// enables it also closes the directory to everyone but root and mysql.
	DefaultMariaDBSlowLog = "/var/log/mariadb/servika-slow.log"
	DefaultMailLog        = "/var/log/maillog"
	DefaultInstallationID = "/etc/servika/installation-id"
	DefaultVersionCache   = "/opt/servika/version-cache.json"
	DefaultPMAToken       = "/etc/servika/pma-internal.token" // #nosec G101 -- filesystem path, not a credential
	DefaultPMASignonDir   = "/opt/servika/pma-signon"
	DefaultPHPMyAdminRoot = "/opt/phpmyadmin"
	// The writable half of the phpMyAdmin installation: its session files and
	// its temporary directory, which is why it lives outside the read-only
	// installation root above.
	DefaultPHPMyAdminVarLib   = "/var/lib/phpmyadmin"
	DefaultRoundcubeConfig    = "/opt/roundcube/config/config.inc.php"
	DefaultRoundcubePlugins   = "/opt/roundcube/plugins"
	DefaultPHPMyAdminConfig   = "/opt/phpmyadmin/config.inc.php"
	DefaultCertRoot           = "/etc/pki/servika"
	DefaultNginxCacheDir      = "/var/cache/nginx/servikacache"
	DefaultNginxCacheConf     = "/etc/nginx/conf.d/servikacache.conf"
	DefaultNginxCacheTempConf = "/etc/nginx/conf.d/00-servikacache-temporary.conf"
	DefaultNginxCacheLogConf  = "/etc/nginx/conf.d/00-servika-cache-log.conf"
	// The 00- prefix loads this before any domain vhost, so the variable an
	// application proxy references is defined by the time it is used.
	DefaultNginxUpgradeMapConf = "/etc/nginx/conf.d/00-servika-upgrade-map.conf"
	DefaultGitHubAPI           = "https://api.github.com"
	// DefaultDNSVerifyResolver is the recursive resolver the DNS verification
	// screen queries. It is deliberately NOT the system resolver: the panel host
	// runs an authoritative BIND for the domains it hosts, so /etc/resolv.conf
	// pointing at it would answer from the local zone and hide the mismatch the
	// screen exists to find.
	DefaultDNSVerifyResolver = "1.1.1.1:53"
	// The IonCube loader is published per architecture, and the two archives
	// carry IDENTICAL member names (measured: both hold
	// ioncube/ioncube_loader_lin_8.3.so), so nothing downstream can notice that
	// the wrong one was fetched. The panel ships arm64 builds, and on such a
	// server the x86-64 URL installed an object PHP could not load: measured,
	// the interpreter prints "Failed loading ..." on stderr and CONTINUES, exit
	// 0, so the install reported success and every later PHP invocation wrote a
	// load failure into the tenant's own FPM error log.
	DefaultIonCubeURLAMD64    = "https://downloads.ioncube.com/loader_downloads/ioncube_loaders_lin_x86-64.tar.gz"
	DefaultIonCubeURLARM64    = "https://downloads.ioncube.com/loader_downloads/ioncube_loaders_lin_aarch64.tar.gz"
	DefaultUpdateBootstrapURL = "https://raw.githubusercontent.com/ServikaPanel/servika/main/assets/ops/servika-update"
	// DefaultAVRulesURL is where the signed malware rule package is published.
	// The host does not have to be trusted: the package carries an Ed25519
	// signature made with a key that never reaches the publication host, and a
	// package that does not verify is refused rather than loaded. That is why
	// serving it from the same branch path as version.json is safe.
	DefaultAVRulesURL      = "https://raw.githubusercontent.com/ServikaPanel/servika/main/assets/av/rules.svkav"
	DefaultVersionEndpoint = "https://raw.githubusercontent.com/ServikaPanel/servika/main/version.json"
)

// EnvString returns a trimmed environment value or its fallback.
func EnvString(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

// EnvAbsPath returns an absolute path from the environment or its fallback.
func EnvAbsPath(key, fallback string) (string, error) {
	value := EnvString(key, fallback)
	if strings.ContainsRune(value, '\x00') || !filepath.IsAbs(value) {
		return "", fmt.Errorf("%s must be an absolute path", key)
	}
	return filepath.Clean(value), nil
}

// EnvURL returns an HTTP or HTTPS URL from the environment or its fallback.
func EnvURL(key, fallback string) (string, error) {
	value := EnvString(key, fallback)
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", fmt.Errorf("%s must be an http or https URL", key)
	}
	return value, nil
}

// ShellQuote quotes a value for POSIX shell command strings.
func ShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func mustAbsPath(key, fallback string) string {
	value, err := EnvAbsPath(key, fallback)
	if err != nil {
		panic(err)
	}
	return value
}

func mustURL(key, fallback string) string {
	value, err := EnvURL(key, fallback)
	if err != nil {
		panic(err)
	}
	return value
}

// EnvFile is the panel's own environment file, the one the installer writes and
// the systemd unit loads. Two packages need it for reasons that have nothing to
// do with each other, internal/panelport to rewrite the listen address and
// internal/antivirus to hand the same configuration to a detached scan, so it
// is named once here rather than defaulted separately in each.
func EnvFile() string { return mustAbsPath("SERVIKA_ENV_FILE", DefaultEnvFile) }

func ComposerBin() string   { return mustAbsPath("SERVIKA_COMPOSER_BIN", DefaultComposerBin) }
func WPCLIBin() string      { return mustAbsPath("SERVIKA_WPCLI_BIN", DefaultWPCLIBin) }
func ClamScanBin() string   { return mustAbsPath("SERVIKA_CLAMSCAN_BIN", DefaultClamScanBin) }
func FreshclamBin() string  { return mustAbsPath("SERVIKA_FRESHCLAM_BIN", DefaultFreshclamBin) }
func PECLBin() string       { return mustAbsPath("SERVIKA_PECL_BIN", DefaultPECLBin) }
func ReadPSTBin() string    { return mustAbsPath("SERVIKA_READPST_BIN", DefaultReadPSTBin) }
func RemiPECLRoot() string  { return mustAbsPath("SERVIKA_REMI_PECL_ROOT", DefaultRemiPECLRoot) }
func ACMEHome() string      { return mustAbsPath("SERVIKA_ACME_HOME", DefaultACMEHome) }
func ACMEBin() string       { return mustAbsPath("SERVIKA_ACME_BIN", DefaultACMEBin) }
func BackupRoot() string    { return mustAbsPath("SERVIKA_BACKUP_ROOT", DefaultBackupRoot) }
func LaravelLogDir() string { return mustAbsPath("SERVIKA_LARAVEL_LOG_DIR", DefaultLaravelLogDir) }
func PluginRoot() string    { return mustAbsPath("SERVIKA_PLUGIN_ROOT", DefaultPluginRoot) }
func LogDir() string        { return mustAbsPath("SERVIKA_LOG_DIR", DefaultLogDir) }
func UpdateLog() string     { return mustAbsPath("SERVIKA_UPDATE_LOG", DefaultUpdateLog) }
func KernelCareLog() string { return mustAbsPath("SERVIKA_KERNELCARE_LOG", DefaultKernelCareLog) }
func KernelCareWrapper() string {
	return mustAbsPath("SERVIKA_KERNELCARE_WRAPPER", DefaultKernelCareWrapper)
}
func CVELog() string { return mustAbsPath("SERVIKA_CVE_LOG", DefaultCVELog) }

// Installing or removing a PHP version runs detached, so its output, the
// descriptor the screen resumes from and the script systemd executes all outlive
// the request that started them.
func PHPOpLog() string     { return mustAbsPath("SERVIKA_PHPOP_LOG", DefaultPHPOpLog) }
func PHPOpState() string   { return mustAbsPath("SERVIKA_PHPOP_STATE", DefaultPHPOpState) }
func PHPOpWrapper() string { return mustAbsPath("SERVIKA_PHPOP_WRAPPER", DefaultPHPOpWrapper) }

func RuntimeOpLog() string   { return mustAbsPath("SERVIKA_RUNTIMEOP_LOG", DefaultRuntimeOpLog) }
func RuntimeOpState() string { return mustAbsPath("SERVIKA_RUNTIMEOP_STATE", DefaultRuntimeOpState) }
func RuntimeOpWrapper() string {
	return mustAbsPath("SERVIKA_RUNTIMEOP_WRAPPER", DefaultRuntimeOpWrapper)
}
func NodeRoot() string  { return mustAbsPath("SERVIKA_NODE_ROOT", DefaultNodeRoot) }
func AppLogDir() string { return mustAbsPath("SERVIKA_APP_LOG_DIR", DefaultAppLogDir) }
func TenantFPMLogDir() string {
	return mustAbsPath("SERVIKA_FPM_LOG_DIR", DefaultTenantFPMLogDir)
}
func AppEnvDir() string { return mustAbsPath("SERVIKA_APP_ENV_DIR", DefaultAppEnvDir) }
func GeoIPDir() string  { return mustAbsPath("SERVIKA_GEOIP_DIR", DefaultGeoIPDir) }

// QuarantineDir is where a file taken out of a tenant tree is kept, outside
// every home so the account it came from cannot reach it.
func QuarantineDir() string {
	return mustAbsPath("SERVIKA_QUARANTINE_DIR", DefaultQuarantineDir)
}

// WPChecksumDir is where the WordPress core checksum tables are cached, so the
// integrity check still has an answer when api.wordpress.org cannot be reached.
func WPChecksumDir() string {
	return mustAbsPath("SERVIKA_WP_CHECKSUM_DIR", DefaultWPChecksumDir)
}

// TuningBackupDir is where the tuning screen keeps the copy of a configuration
// file it is about to edit. Deliberately outside every directory a daemon reads
// as configuration.
func TuningBackupDir() string {
	return mustAbsPath("SERVIKA_TUNING_BACKUP_DIR", DefaultTuningBackupDir)
}

// HostAppRoot is where a server-level application's files live, one directory
// per application, outside every tenant home.
func HostAppRoot() string { return mustAbsPath("SERVIKA_HOST_APP_ROOT", DefaultHostAppRoot) }

// HostAppLogDir is where a server-level application's output is appended.
func HostAppLogDir() string {
	return mustAbsPath("SERVIKA_HOST_APP_LOG_DIR", DefaultHostAppLogDir)
}

// HostAppEnvDir is where a server-level application's EnvironmentFile lives.
func HostAppEnvDir() string {
	return mustAbsPath("SERVIKA_HOST_APP_ENV_DIR", DefaultHostAppEnvDir)
}

// HostAppBackupDir is where the archive of a removed application's data
// directory is kept.
func HostAppBackupDir() string {
	return mustAbsPath("SERVIKA_HOST_APP_BACKUP_DIR", DefaultHostAppBackupDir)
}

// MariaDBSlowLog is where the panel asks MariaDB to write slow queries, and the
// only file internal/slowquery reads.
func MariaDBSlowLog() string {
	return mustAbsPath("SERVIKA_MARIADB_SLOW_LOG", DefaultMariaDBSlowLog)
}

// MailLog is where Postfix and Dovecot write. AlmaLinux keeps it at
// /var/log/maillog; a host that sends mail logging elsewhere overrides it.
func MailLog() string { return mustAbsPath("SERVIKA_MAIL_LOG", DefaultMailLog) }
func InstallationIDPath() string {
	return mustAbsPath("SERVIKA_INSTALLATION_ID", DefaultInstallationID)
}
func VersionCachePath() string { return mustAbsPath("SERVIKA_VERSION_CACHE", DefaultVersionCache) }
func PMATokenPath() string     { return mustAbsPath("SERVIKA_PMA_TOKEN", DefaultPMAToken) }
func PMASignonDir() string     { return mustAbsPath("SERVIKA_PMA_SIGNON_DIR", DefaultPMASignonDir) }
func PHPMyAdminRoot() string {
	return mustAbsPath("SERVIKA_PHPMYADMIN_ROOT", DefaultPHPMyAdminRoot)
}
func PHPMyAdminVarLib() string {
	return mustAbsPath("SERVIKA_PHPMYADMIN_VAR_LIB", DefaultPHPMyAdminVarLib)
}
func PHPMyAdminConfig() string {
	return mustAbsPath("SERVIKA_PHPMYADMIN_CONFIG", DefaultPHPMyAdminConfig)
}
func RoundcubeConfig() string {
	return mustAbsPath("SERVIKA_ROUNDCUBE_CONFIG", DefaultRoundcubeConfig)
}

func RoundcubePlugins() string {
	return mustAbsPath("SERVIKA_ROUNDCUBE_PLUGINS", DefaultRoundcubePlugins)
}
func CertRoot() string       { return mustAbsPath("SERVIKA_CERT_ROOT", DefaultCertRoot) }
func NginxCacheDir() string  { return mustAbsPath("SERVIKA_NGINX_CACHE_DIR", DefaultNginxCacheDir) }
func NginxCacheConf() string { return mustAbsPath("SERVIKA_NGINX_CACHE_CONF", DefaultNginxCacheConf) }
func NginxCacheTempConf() string {
	return mustAbsPath("SERVIKA_NGINX_CACHE_TEMP_CONF", DefaultNginxCacheTempConf)
}
func NginxCacheLogConf() string {
	return mustAbsPath("SERVIKA_NGINX_CACHE_LOG_CONF", DefaultNginxCacheLogConf)
}
func NginxUpgradeMapConf() string {
	return mustAbsPath("SERVIKA_NGINX_UPGRADE_MAP_CONF", DefaultNginxUpgradeMapConf)
}

// DNSVerifyResolver returns the host:port of the recursive resolver used by the
// DNS verification screen. An override without a port gets the default one, and
// anything unparseable falls back to the default rather than producing a dialer
// that fails every lookup.
func DNSVerifyResolver() string {
	value := strings.TrimSpace(os.Getenv("SERVIKA_DNS_VERIFY_RESOLVER"))
	if value == "" {
		return DefaultDNSVerifyResolver
	}
	if _, _, err := net.SplitHostPort(value); err != nil {
		value = net.JoinHostPort(value, "53")
	}
	if host, _, err := net.SplitHostPort(value); err != nil || net.ParseIP(host) == nil {
		return DefaultDNSVerifyResolver
	}
	return value
}

func GitHubAPI() string { return mustURL("SERVIKA_GITHUB_API", DefaultGitHubAPI) }

// DefaultIonCubeURLForArch answers the published archive for the architecture
// this binary was built for, which on a Servika server is the host's: the
// installer picks the release bundle by uname -m.
//
// An unknown architecture keeps the amd64 address rather than answering empty,
// because an empty URL would fail EnvURL and stop the panel from starting over a
// feature nobody on that platform can use. The ELF check in internal/phpext
// refuses the download there, which is the right place for that refusal.
func DefaultIonCubeURLForArch() string { return ionCubeURLForArch(runtime.GOARCH) }

// ionCubeURLForArch takes the architecture as an argument so both answers can be
// measured on one machine. A test that could only ever exercise the platform it
// runs on would leave the other half of the mapping unproven, which is the half
// that was wrong.
func ionCubeURLForArch(goarch string) string {
	if goarch == "arm64" {
		return DefaultIonCubeURLARM64
	}
	return DefaultIonCubeURLAMD64
}

func IonCubeURL() string { return mustURL("SERVIKA_IONCUBE_URL", DefaultIonCubeURLForArch()) }
func UpdateBootstrapURL() string {
	return mustURL("SERVIKA_UPDATE_BOOTSTRAP_URL", DefaultUpdateBootstrapURL)
}
func VersionEndpoint() string { return mustURL("SERVIKA_VERSION_ENDPOINT", DefaultVersionEndpoint) }
func AVRulesURL() string      { return mustURL("SERVIKA_AV_RULES_URL", DefaultAVRulesURL) }
func AVRulesFile() string     { return mustAbsPath("SERVIKA_AV_RULES_FILE", DefaultAVRulesFile) }

// AVCacheFile is where the sweep records what it inspected and found clean.
func AVCacheFile() string { return mustAbsPath("SERVIKA_AV_CACHE_FILE", DefaultAVCacheFile) }

// MySQLSocket is the local MariaDB socket, the only path a tenant database
// account can be reached over.
func MySQLSocket() string { return mustAbsPath("SERVIKA_MYSQL_SOCKET", DefaultMySQLSocket) }

// OpsTool returns the absolute path for an operations helper under SERVIKA_OPSBIN.
func OpsTool(name string) string {
	return filepath.Join(mustAbsPath("SERVIKA_OPSBIN", "/usr/local/bin"), name)
}

// ValidateRuntimePaths validates env-backed paths and URLs once during startup.
func ValidateRuntimePaths() error {
	checks := []struct {
		key      string
		fallback string
		isURL    bool
	}{
		{"SERVIKA_COMPOSER_BIN", DefaultComposerBin, false},
		{"SERVIKA_WPCLI_BIN", DefaultWPCLIBin, false},
		{"SERVIKA_CLAMSCAN_BIN", DefaultClamScanBin, false},
		{"SERVIKA_FRESHCLAM_BIN", DefaultFreshclamBin, false},
		{"SERVIKA_PECL_BIN", DefaultPECLBin, false},
		{"SERVIKA_READPST_BIN", DefaultReadPSTBin, false},
		{"SERVIKA_REMI_PECL_ROOT", DefaultRemiPECLRoot, false},
		{"SERVIKA_ACME_HOME", DefaultACMEHome, false},
		{"SERVIKA_ACME_BIN", DefaultACMEBin, false},
		{"SERVIKA_BACKUP_ROOT", DefaultBackupRoot, false},
		{"SERVIKA_QUARANTINE_DIR", DefaultQuarantineDir, false},
		{"SERVIKA_TUNING_BACKUP_DIR", DefaultTuningBackupDir, false},
		{"SERVIKA_HOST_APP_ROOT", DefaultHostAppRoot, false},
		{"SERVIKA_HOST_APP_LOG_DIR", DefaultHostAppLogDir, false},
		{"SERVIKA_HOST_APP_ENV_DIR", DefaultHostAppEnvDir, false},
		{"SERVIKA_HOST_APP_BACKUP_DIR", DefaultHostAppBackupDir, false},
		{"SERVIKA_LARAVEL_LOG_DIR", DefaultLaravelLogDir, false},
		{"SERVIKA_PLUGIN_ROOT", DefaultPluginRoot, false},
		{"SERVIKA_LOG_DIR", DefaultLogDir, false},
		{"SERVIKA_UPDATE_LOG", DefaultUpdateLog, false},
		{"SERVIKA_KERNELCARE_LOG", DefaultKernelCareLog, false},
		{"SERVIKA_KERNELCARE_WRAPPER", DefaultKernelCareWrapper, false},
		{"SERVIKA_CVE_LOG", DefaultCVELog, false},
		{"SERVIKA_PHPOP_LOG", DefaultPHPOpLog, false},
		{"SERVIKA_PHPOP_STATE", DefaultPHPOpState, false},
		{"SERVIKA_PHPOP_WRAPPER", DefaultPHPOpWrapper, false},
		{"SERVIKA_RUNTIMEOP_LOG", DefaultRuntimeOpLog, false},
		{"SERVIKA_RUNTIMEOP_STATE", DefaultRuntimeOpState, false},
		{"SERVIKA_RUNTIMEOP_WRAPPER", DefaultRuntimeOpWrapper, false},
		{"SERVIKA_NODE_ROOT", DefaultNodeRoot, false},
		{"SERVIKA_APP_LOG_DIR", DefaultAppLogDir, false},
		{"SERVIKA_FPM_LOG_DIR", DefaultTenantFPMLogDir, false},
		{"SERVIKA_APP_ENV_DIR", DefaultAppEnvDir, false},
		{"SERVIKA_MARIADB_SLOW_LOG", DefaultMariaDBSlowLog, false},
		{"SERVIKA_MAIL_LOG", DefaultMailLog, false},
		{"SERVIKA_INSTALLATION_ID", DefaultInstallationID, false},
		{"SERVIKA_VERSION_CACHE", DefaultVersionCache, false},
		{"SERVIKA_ROUNDCUBE_PLUGINS", DefaultRoundcubePlugins, false},
		{"SERVIKA_PMA_TOKEN", DefaultPMAToken, false},
		{"SERVIKA_PMA_SIGNON_DIR", DefaultPMASignonDir, false},
		{"SERVIKA_PHPMYADMIN_ROOT", DefaultPHPMyAdminRoot, false},
		{"SERVIKA_PHPMYADMIN_VAR_LIB", DefaultPHPMyAdminVarLib, false},
		{"SERVIKA_PHPMYADMIN_CONFIG", DefaultPHPMyAdminConfig, false},
		{"SERVIKA_CERT_ROOT", DefaultCertRoot, false},
		{"SERVIKA_NGINX_CACHE_DIR", DefaultNginxCacheDir, false},
		{"SERVIKA_NGINX_CACHE_CONF", DefaultNginxCacheConf, false},
		{"SERVIKA_NGINX_CACHE_TEMP_CONF", DefaultNginxCacheTempConf, false},
		{"SERVIKA_NGINX_CACHE_LOG_CONF", DefaultNginxCacheLogConf, false},
		{"SERVIKA_NGINX_UPGRADE_MAP_CONF", DefaultNginxUpgradeMapConf, false},
		{"SERVIKA_OPSBIN", "/usr/local/bin", false},
		{"SERVIKA_GITHUB_API", DefaultGitHubAPI, true},
		{"SERVIKA_IONCUBE_URL", DefaultIonCubeURLForArch(), true},
		{"SERVIKA_UPDATE_BOOTSTRAP_URL", DefaultUpdateBootstrapURL, true},
		{"SERVIKA_VERSION_ENDPOINT", DefaultVersionEndpoint, true},
		{"SERVIKA_AV_RULES_URL", DefaultAVRulesURL, true},
		{"SERVIKA_AV_RULES_FILE", DefaultAVRulesFile, false},
		{"SERVIKA_AV_CACHE_FILE", DefaultAVCacheFile, false},
		{"SERVIKA_MYSQL_SOCKET", DefaultMySQLSocket, false},
	}
	for _, check := range checks {
		var err error
		if check.isURL {
			_, err = EnvURL(check.key, check.fallback)
		} else {
			_, err = EnvAbsPath(check.key, check.fallback)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
