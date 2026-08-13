package provisioner

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	tenantUnitDir = "/etc/systemd/system"
	tenantCfgRoot = "/etc/php-fpm-tenant"
)

func tenantUnitName(systemUser string) string {
	return "php-fpm-" + systemUser + ".service"
}

func tenantUnitPath(systemUser string) string {
	return filepath.Join(tenantUnitDir, tenantUnitName(systemUser))
}

func tenantRunDir(systemUser string) string {
	return "/run/php-fpm-" + systemUser
}

func tenantSocket(systemUser string) string {
	return filepath.Join(tenantRunDir(systemUser), systemUser+".sock")
}

func tenantCfgDir(systemUser string) string {
	return filepath.Join(tenantCfgRoot, systemUser)
}

// tenantPoolDir holds one file per pool served by the tenant's own master: the
// domain's pool plus one per subdomain that runs the parent's PHP version.
func tenantPoolDir(systemUser string) string {
	return filepath.Join(tenantCfgDir(systemUser), "pool.d")
}

func tenantMainPoolPath(systemUser string) string {
	return filepath.Join(tenantPoolDir(systemUser), "main.conf")
}

func tenantSubPoolPath(systemUser string, subdomainID int64) string {
	return filepath.Join(tenantPoolDir(systemUser), fmt.Sprintf("sub-%d.conf", subdomainID))
}

// tenantLegacyPoolPath is the single-pool layout used before pool.d existed.
func tenantLegacyPoolPath(systemUser string) string {
	return filepath.Join(tenantCfgDir(systemUser), "pool.conf")
}

func tenantSubSocket(systemUser string, subdomainID int64) string {
	return filepath.Join(tenantRunDir(systemUser), fmt.Sprintf("sub-%d.sock", subdomainID))
}

const fpmSocketFcontextSpec = "/run/php-fpm-[^/]+(/.*)?"

// mtaSpoolPaths are the mail spools a sendmail wrapper may need to write into. Only one of
// them exists on a given host, and on a host with no MTA none of them do.
var mtaSpoolPaths = []string{"/var/spool/postfix/public", "/var/spool/postfix/maildrop", "/var/spool/exim"}

// mtaBindLines builds the systemd bind directives that let PHP mail() reach the local MTA
// from inside the tenant's mount namespace. ProtectSystem=strict leaves the whole filesystem
// read-only apart from ReadWritePaths, so without these binds a queue drop fails.
//
// Every path is bound only when it actually exists. Gating on /usr/sbin/sendmail alone is
// wrong: exim installs that same wrapper through alternatives, so a postfix-shaped bind list
// would name a spool that is not there, systemd would fail the namespace setup, the unit
// would never start, and EnableTenantFPM would roll the tenant back onto the shared master,
// losing the isolation the per-tenant unit exists to provide.
func mtaBindLines() string {
	var lines strings.Builder
	if _, err := os.Stat("/usr/sbin/sendmail"); err == nil {
		lines.WriteString("BindReadOnlyPaths=/usr/sbin/sendmail\n")
	}
	for _, spool := range mtaSpoolPaths {
		if _, err := os.Stat(spool); err == nil {
			fmt.Fprintf(&lines, "BindPaths=%s\n", spool)
		}
	}
	if lines.Len() == 0 {
		return ""
	}
	return "\n# Local MTA, bound only where it exists, so mail() works inside the namespace.\n" + lines.String()
}

var (
	fcontextMu       sync.Mutex
	fcontextDone     bool
	httpdBooleanMu   sync.Mutex
	httpdBooleanDone bool
)

// ensureFPMSELinuxFcontext persistently labels per-tenant socket paths for nginx access.
func ensureFPMSELinuxFcontext() {
	fcontextMu.Lock()
	defer fcontextMu.Unlock()
	if fcontextDone {
		return
	}
	if !selinuxActive() {
		fcontextDone = true
		return
	}
	if _, err := exec.LookPath("semanage"); err != nil {
		fcontextDone = true
		return
	}

	output, _ := tenantCommand("semanage", "fcontext", "-l").CombinedOutput()
	if strings.Contains(string(output), "/run/php-fpm-[") {
		fcontextDone = true
		return
	}
	if _, err := tenantCommand("semanage", "fcontext", "-a", "-t", "httpd_var_run_t", fpmSocketFcontextSpec).CombinedOutput(); err == nil {
		fcontextDone = true
	}
}

func selinuxActive() bool {
	output, err := tenantCommand("getenforce").Output()
	if err != nil {
		return false
	}
	status := strings.TrimSpace(string(output))
	return status == "Enforcing" || status == "Permissive"
}

// ensureHTTPDHomeBooleans persistently permits web servers to read tenant home content.
func ensureHTTPDHomeBooleans() {
	httpdBooleanMu.Lock()
	defer httpdBooleanMu.Unlock()
	if httpdBooleanDone {
		return
	}
	if !selinuxActive() {
		httpdBooleanDone = true
		return
	}
	if _, err := exec.LookPath("setsebool"); err != nil {
		httpdBooleanDone = true
		return
	}

	required := []string{"httpd_enable_homedirs", "httpd_read_user_content"}
	disabled := make([]string, 0, len(required))
	for _, boolean := range required {
		output, err := tenantCommand("getsebool", boolean).Output()
		if err != nil {
			continue
		}
		if !strings.Contains(string(output), "--> on") {
			disabled = append(disabled, boolean)
		}
	}
	if len(disabled) == 0 {
		httpdBooleanDone = true
		return
	}

	args := []string{"-P"}
	for _, boolean := range disabled {
		args = append(args, boolean+"=on")
	}
	output, err := tenantCommand("setsebool", args...).CombinedOutput()
	if err != nil {
		log.Printf("SELinux HTTP home boolean update failed: %s: %v", strings.TrimSpace(string(output)), err)
		return
	}
	httpdBooleanDone = true
	log.Printf("SELinux: enabled HTTP home access booleans: %v", disabled)
}

// TenantFPMActive reports whether a tenant PHP-FPM unit is installed.
func TenantFPMActive(systemUser string) bool {
	if !tenantUserPattern.MatchString(systemUser) {
		return false
	}
	_, err := os.Stat(tenantUnitPath(systemUser))
	return err == nil
}

func tenantSanitizeScalar(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return fallback
	}
	return value
}

func resolveTenantPMMaxChildren(pmMaxChildren, ramMB int) int {
	if pmMaxChildren > 0 {
		return pmMaxChildren
	}
	if ramMB > 0 {
		return max(4, ramMB/64)
	}
	return 8
}

func tenantPMMaxChildren(db *sql.DB, domainID int64) int {
	var pmMaxChildren, ramMB int
	if db != nil && domainID > 0 {
		_ = db.QueryRow(`SELECT COALESCE(p.pm_max_children,0), COALESCE(p.ram_mb,0)
			FROM domains d LEFT JOIN service_plans p ON p.id=d.plan_id
			WHERE d.id=?`, domainID).Scan(&pmMaxChildren, &ramMB)
	}
	return resolveTenantPMMaxChildren(pmMaxChildren, ramMB)
}

type tenantPoolSettings struct {
	MemoryLimit       string
	MaxExecutionTime  int
	MaxInputTime      int
	PostMaxSize       string
	UploadMaxFilesize string
	DisableFunctions  string
	PMStrategy        string
	PMMaxRequests     int
	// Logging / Debug Mode (php_settings) -- robust fatal error visibility.
	DisplayErrors  bool
	LogErrors      bool
	ErrorReporting string
	DebugMode      bool
}

const hardenedDisableFunctions = "exec,passthru,shell_exec,system,proc_open,popen,proc_close,proc_get_status,proc_terminate,proc_nice,pcntl_exec,dl,symlink,link,posix_kill,posix_mkfifo,posix_setpgid,posix_setsid,posix_setuid,posix_setgid"

func tenantReadPoolSettings(db *sql.DB, domainID, subdomainID int64) tenantPoolSettings {
	settings := tenantPoolSettings{
		MemoryLimit:       "256M",
		MaxExecutionTime:  30,
		MaxInputTime:      60,
		PostMaxSize:       "64M",
		UploadMaxFilesize: "32M",
		DisableFunctions:  hardenedDisableFunctions,
		PMStrategy:        "ondemand",
		PMMaxRequests:     500,
		DisplayErrors:     false,
		LogErrors:         true,
		ErrorReporting:    "E_ALL & ~E_DEPRECATED & ~E_STRICT",
		DebugMode:         false,
	}
	if db == nil || domainID <= 0 {
		return settings
	}

	var memoryLimit, postMaxSize, uploadMaxFilesize, disableFunctions, strategy string
	var maxExecutionTime, maxInputTime, maxRequests int
	err := db.QueryRow(`SELECT memory_limit, max_execution_time, max_input_time,
		post_max_size, upload_max_filesize, disable_functions, pm_strategy, pm_max_requests
		FROM php_settings WHERE domain_id=? AND subdomain_id=?`, domainID, subdomainID).
		Scan(&memoryLimit, &maxExecutionTime, &maxInputTime, &postMaxSize,
			&uploadMaxFilesize, &disableFunctions, &strategy, &maxRequests)
	if err != nil {
		return settings
	}

	settings.MemoryLimit = tenantSanitizeScalar(memoryLimit, settings.MemoryLimit)
	settings.PostMaxSize = tenantSanitizeScalar(postMaxSize, settings.PostMaxSize)
	settings.UploadMaxFilesize = tenantSanitizeScalar(uploadMaxFilesize, settings.UploadMaxFilesize)
	settings.DisableFunctions = tenantSanitizeScalar(disableFunctions, settings.DisableFunctions)
	settings.PMStrategy = tenantSanitizeScalar(strategy, settings.PMStrategy)
	if maxExecutionTime > 0 {
		settings.MaxExecutionTime = maxExecutionTime
	}
	if maxInputTime > 0 {
		settings.MaxInputTime = maxInputTime
	}
	if maxRequests > 0 {
		settings.PMMaxRequests = maxRequests
	}
	switch settings.PMStrategy {
	case "static", "dynamic", "ondemand":
	default:
		settings.PMStrategy = "ondemand"
	}
	// display_errors/log_errors/error_reporting/debug_mode are read separately
	// (backward-compatible: if debug_mode column is absent, the query errors out
	// and defaults are preserved, main settings remain unaffected).
	var de, le, dm int
	var er string
	if derr := db.QueryRow(`SELECT COALESCE(display_errors,0), COALESCE(log_errors,1),
	        COALESCE(error_reporting,''), COALESCE(debug_mode,0)
	        FROM php_settings WHERE domain_id=? AND subdomain_id=?`, domainID, subdomainID).Scan(&de, &le, &er, &dm); derr == nil {
		settings.DisplayErrors = de != 0
		settings.LogErrors = le != 0
		settings.DebugMode = dm != 0
		if strings.TrimSpace(er) != "" {
			settings.ErrorReporting = tenantSanitizeScalar(er, settings.ErrorReporting)
		}
	}
	return settings
}

func renderTenantPool(db *sql.DB, systemUser string, domainID int64) string {
	return renderTenantPoolScoped(db, systemUser, domainID, 0, "")
}

// renderTenantPoolScoped renders one pool of the tenant's own master. subdomainID 0
// is the domain's pool; a non-zero value is a subdomain pool, which gets its own
// section name and socket and an open_basedir narrowed to that document root, so a
// subdomain cannot read the parent's public_html through PHP.
//
// Both pools run inside the same unit on purpose: that unit carries the tenant mount
// namespace and Slice=servika-<user>.slice, so a subdomain stays inside the plan
// quotas that internal/resourcelimit applies. A pool opened in the shared per-version
// master would sit outside both.
func renderTenantPoolScoped(db *sql.DB, systemUser string, domainID, subdomainID int64, docRoot string) string {
	settings := tenantReadPoolSettings(db, domainID, subdomainID)
	maxChildren := tenantPMMaxChildren(db, domainID)
	startServers := max(1, maxChildren/4)
	maxSpareServers := max(1, maxChildren/2)

	poolName, socket := systemUser, tenantSocket(systemUser)
	openBasedir := fmt.Sprintf("/home/%s/:/tmp/", systemUser)
	if subdomainID > 0 {
		poolName = fmt.Sprintf("sub-%d", subdomainID)
		socket = tenantSubSocket(systemUser, subdomainID)
		if docRoot != "" {
			openBasedir = fmt.Sprintf("%s/:/home/%s/tmp/:/tmp/", strings.TrimRight(docRoot, "/"), systemUser)
		}
	}

	var body strings.Builder
	fmt.Fprintf(&body, "[%s]\n", poolName)
	fmt.Fprintf(&body, "user = %s\n", systemUser)
	fmt.Fprintf(&body, "group = %s\n", systemUser)
	fmt.Fprintf(&body, "listen = %s\n", socket)
	body.WriteString("listen.owner = nginx\nlisten.group = nginx\nlisten.mode = 0660\n")
	fmt.Fprintf(&body, "pm = %s\n", settings.PMStrategy)
	fmt.Fprintf(&body, "pm.max_children = %d\n", maxChildren)
	switch settings.PMStrategy {
	case "dynamic":
		fmt.Fprintf(&body, "pm.start_servers = %d\n", startServers)
		body.WriteString("pm.min_spare_servers = 1\n")
		fmt.Fprintf(&body, "pm.max_spare_servers = %d\n", maxSpareServers)
	case "ondemand":
		body.WriteString("pm.process_idle_timeout = 30s\n")
	}
	fmt.Fprintf(&body, "pm.max_requests = %d\n", settings.PMMaxRequests)
	body.WriteString("; Security settings cannot be overridden by tenant code.\n")
	fmt.Fprintf(&body, "php_admin_value[open_basedir] = %s\n", openBasedir)
	fmt.Fprintf(&body, "php_admin_value[disable_functions] = %s\n", settings.DisableFunctions)
	fmt.Fprintf(&body, "php_admin_value[upload_tmp_dir] = /home/%s/tmp\n", systemUser)
	fmt.Fprintf(&body, "php_admin_value[sys_temp_dir] = /home/%s/tmp\n", systemUser)
	fmt.Fprintf(&body, "php_admin_value[session.save_path] = /home/%s/tmp\n", systemUser)
	fmt.Fprintf(&body, "php_admin_value[memory_limit] = %s\n", settings.MemoryLimit)
	fmt.Fprintf(&body, "php_admin_value[max_execution_time] = %d\n", settings.MaxExecutionTime)
	fmt.Fprintf(&body, "php_admin_value[max_input_time] = %d\n", settings.MaxInputTime)
	fmt.Fprintf(&body, "php_admin_value[post_max_size] = %s\n", settings.PostMaxSize)
	fmt.Fprintf(&body, "php_admin_value[upload_max_filesize] = %s\n", settings.UploadMaxFilesize)
	// Logging / debug mode: log_errors is always on (PHP errors go to stderr
	// and are captured by catch_workers_output). display_errors and
	// error_reporting are conditionally controlled by DebugMode (see below).
	body.WriteString("php_admin_flag[log_errors] = on\n")
	if settings.DebugMode {
		body.WriteString("; ---- Debug Mode (overrides display_errors/error_reporting) ----\n")
		body.WriteString("php_admin_flag[display_errors] = on\n")
		body.WriteString("php_admin_value[error_reporting] = E_ALL\n")
		fmt.Fprintf(&body, "php_admin_value[auto_prepend_file] = %s\n", tenantDebugPrependPath(systemUser))
	} else {
		body.WriteString("php_admin_flag[display_errors] = off\n")
		fmt.Fprintf(&body, "php_admin_value[error_reporting] = %s\n", sanitizeErrorReporting(settings.ErrorReporting))
	}
	body.WriteString("catch_workers_output = yes\n")
	return body.String()
}

// renderTenantGlobalConfig includes a directory rather than a single file so a
// subdomain pool can be added or removed without rewriting the domain's own pool.
func renderTenantGlobalConfig(systemUser string) string {
	return fmt.Sprintf(`[global]
pid = %s/php-fpm.pid
error_log = %s
log_level = warning
daemonize = no
include=%s/*.conf
`, tenantRunDir(systemUser), tenantLogPath(systemUser), tenantPoolDir(systemUser))
}

// migrateTenantPoolLayout moves an installation from the old single pool.conf to the
// pool.d directory. The global config is rewritten by the caller in the same pass, so
// the include never points at a file that has already been moved.
func migrateTenantPoolLayout(systemUser string) error {
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(tenantPoolDir(systemUser), 0755); err != nil {
		return err
	}
	legacy := tenantLegacyPoolPath(systemUser)
	if _, err := os.Stat(legacy); err != nil {
		return nil
	}
	if _, err := os.Stat(tenantMainPoolPath(systemUser)); err == nil {
		// The new layout already exists; the leftover file would be a second copy of
		// the same pool, which php-fpm rejects as a duplicate section.
		return os.Remove(legacy)
	}
	return os.Rename(legacy, tenantMainPoolPath(systemUser))
}

func renderTenantUnit(systemUser, fpmBinary string) string {
	return fmt.Sprintf(`[Unit]
Description=Servika per-tenant PHP-FPM for %s
After=network.target
Before=nginx.service

[Service]
Type=notify
NotifyAccess=all
Slice=servika-%s.slice
ExecStart=%s --nodaemonize --fpm-config %s/php-fpm.conf
ExecReload=/bin/kill -USR2 $MAINPID
RuntimeDirectory=php-fpm-%s
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
ProtectHome=tmpfs
BindPaths=/home/%s
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/home/%s %s
ProtectProc=invisible
NoNewPrivileges=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
LimitCORE=0
Restart=on-failure
RestartSec=2
%s
[Install]
WantedBy=multi-user.target
`, systemUser, systemUser, fpmBinary, tenantCfgDir(systemUser), systemUser, systemUser, systemUser, tenantLogDir(), mtaBindLines())
}

func waitForSocket(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// EnableTenantFPM moves a domain to an isolated PHP-FPM master service.
func EnableTenantFPM(db *sql.DB, domainID int64, systemUser, phpVersion string) (string, error) {
	if !tenantUserPattern.MatchString(systemUser) {
		return "", fmt.Errorf("invalid system user: %q", systemUser)
	}
	phpVersion = normalizePHP(phpVersion)
	config := phpMap[phpVersion]
	if config.FPMBin == "" {
		return "", fmt.Errorf("PHP-FPM binary is undefined for %s", phpVersion)
	}
	if _, err := os.Stat(config.FPMBin); err != nil {
		return "", fmt.Errorf("PHP-FPM binary is unavailable for %s: %w", phpVersion, err)
	}
	if _, err := os.Stat(filepath.Join("/home", systemUser)); err != nil {
		return "", fmt.Errorf("tenant home is unavailable: %w", err)
	}

	firstInstall := !TenantFPMActive(systemUser)
	configDir := tenantCfgDir(systemUser)
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", fmt.Errorf("create tenant configuration directory: %w", err)
	}
	// 0700, unlike the config and pool directories: this one holds whatever the
	// tenant's PHP printed when it died, which routinely includes the contents of
	// the application's own configuration. Refusing here rather than starting a
	// master that cannot open its error log, which php-fpm treats as fatal.
	if err := EnsureTenantFPMLogDir(); err != nil {
		return "", err
	}

	if err := migrateTenantPoolLayout(systemUser); err != nil {
		return "", fmt.Errorf("migrate tenant pool layout: %w", err)
	}
	poolPath := tenantMainPoolPath(systemUser)
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	previousPool, readErr := os.ReadFile(poolPath)
	WriteDebugShim(db, systemUser, domainID)
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(poolPath, []byte(renderTenantPool(db, systemUser, domainID)), 0644); err != nil {
		return "", fmt.Errorf("write tenant pool: %w", err)
	}
	globalPath := filepath.Join(configDir, "php-fpm.conf")
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(globalPath, []byte(renderTenantGlobalConfig(systemUser)), 0644); err != nil {
		return "", fmt.Errorf("write tenant global configuration: %w", err)
	}
	if output, err := tenantCommand(config.FPMBin, "-t", "-y", globalPath).CombinedOutput(); err != nil {
		if readErr == nil {
			// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
			_ = os.WriteFile(poolPath, previousPool, 0644)
		} else {
			_ = os.Remove(poolPath)
		}
		return "", fmt.Errorf("validate tenant PHP-FPM configuration: %s: %w", strings.TrimSpace(string(output)), err)
	}
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(tenantUnitPath(systemUser), []byte(renderTenantUnit(systemUser, config.FPMBin)), 0644); err != nil {
		return "", fmt.Errorf("write tenant service: %w", err)
	}
	if output, err := tenantCommand("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		_ = RollbackToSharedFPM(db, domainID, systemUser, phpVersion)
		return "", fmt.Errorf("reload systemd units: %s: %w", strings.TrimSpace(string(output)), err)
	}

	if firstInstall {
		sharedPool := filepath.Join(config.PoolDir, systemUser+".conf")
		if _, err := os.Stat(sharedPool); err == nil {
			if err := os.Rename(sharedPool, sharedPool+".bak"); err != nil {
				_ = RollbackToSharedFPM(db, domainID, systemUser, phpVersion)
				return "", fmt.Errorf("preserve shared PHP-FPM pool: %w", err)
			}
			_, _ = tenantCommand("systemctl", "reload-or-restart", config.Service).CombinedOutput()
		}
	}

	if output, err := tenantCommand("systemctl", "enable", tenantUnitName(systemUser)).CombinedOutput(); err != nil {
		_ = RollbackToSharedFPM(db, domainID, systemUser, phpVersion)
		return "", fmt.Errorf("enable tenant PHP-FPM: %s: %w", strings.TrimSpace(string(output)), err)
	}
	if output, err := tenantCommand("systemctl", "restart", tenantUnitName(systemUser)).CombinedOutput(); err != nil {
		_ = RollbackToSharedFPM(db, domainID, systemUser, phpVersion)
		return "", fmt.Errorf("restart tenant PHP-FPM: %s: %w", strings.TrimSpace(string(output)), err)
	}

	ensureFPMSELinuxFcontext()
	_, _ = tenantCommand("restorecon", "-R", tenantRunDir(systemUser)).CombinedOutput()
	_, _ = tenantCommand("restorecon", "-R", configDir).CombinedOutput()
	socket := tenantSocket(systemUser)
	if !waitForSocket(socket, 6*time.Second) {
		_ = RollbackToSharedFPM(db, domainID, systemUser, phpVersion)
		return "", fmt.Errorf("tenant PHP-FPM socket was not created: %s", socket)
	}
	_, _ = tenantCommand("restorecon", socket).CombinedOutput()
	if db != nil && domainID > 0 {
		if err := ApplyVhostForDomain(db, domainID, socket, phpVersion); err != nil {
			_ = RollbackToSharedFPM(db, domainID, systemUser, phpVersion)
			return "", fmt.Errorf("render tenant nginx virtual host: %w", err)
		}
	}
	return socket, nil
}

// SubdomainFPMSocket returns the socket a subdomain's nginx vhost must use, WITHOUT
// touching any configuration. It mirrors the decision ApplySubdomainFPM makes, so a
// vhost re-render agrees with the pool that is actually installed.
func SubdomainFPMSocket(db *sql.DB, systemUser string, domainID, subdomainID int64, phpVersion string) (string, error) {
	if subdomainFPMEligible(db, systemUser, domainID, phpVersion) {
		if _, err := os.Stat(tenantSubPoolPath(systemUser, subdomainID)); err == nil {
			return tenantSubSocket(systemUser, subdomainID), nil
		}
	}
	return PHPSocketFor(systemUser, phpVersion)
}

// subdomainFPMEligible reports whether a subdomain's pool can live in the parent
// tenant's own master. That master runs ONE php-fpm binary, so a subdomain asking for
// a different PHP version cannot be served from it and falls back to the shared
// per-version master, exactly as every subdomain did before per-subdomain pools
// existed. The fallback is not a new isolation loss, but it is a real one: state it
// here rather than silently degrading.
func subdomainFPMEligible(db *sql.DB, systemUser string, domainID int64, phpVersion string) bool {
	if !TenantFPMActive(systemUser) || db == nil || domainID <= 0 {
		return false
	}
	var parentPHP string
	if err := db.QueryRow(`SELECT COALESCE(php_version,'') FROM domains WHERE id=?`, domainID).Scan(&parentPHP); err != nil {
		return false
	}
	return SamePHPVersion(parentPHP, phpVersion)
}

// ApplySubdomainFPM installs (or removes) the subdomain's pool inside the parent
// tenant's own FPM unit and returns the socket its vhost must point at.
//
// It is the caller's single entry point: when the subdomain is not eligible it clears
// any pool left from an earlier eligible state, so switching a subdomain to a
// different PHP version cannot leave a stale pool bound to the old socket.
func ApplySubdomainFPM(db *sql.DB, domainID, subdomainID int64, systemUser, docRoot, phpVersion string) (string, error) {
	if !tenantUserPattern.MatchString(systemUser) {
		return "", fmt.Errorf("invalid system user: %q", systemUser)
	}
	if subdomainID <= 0 {
		return "", fmt.Errorf("invalid subdomain id: %d", subdomainID)
	}
	if !subdomainFPMEligible(db, systemUser, domainID, phpVersion) {
		RemoveSubdomainFPM(systemUser, subdomainID)
		return PHPSocketFor(systemUser, phpVersion)
	}
	config := phpMap[normalizePHP(phpVersion)]
	if config.FPMBin == "" {
		return "", fmt.Errorf("PHP-FPM binary is undefined for %s", phpVersion)
	}
	if err := migrateTenantPoolLayout(systemUser); err != nil {
		return "", fmt.Errorf("migrate tenant pool layout: %w", err)
	}
	poolPath := tenantSubPoolPath(systemUser, subdomainID)
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	previous, readErr := os.ReadFile(poolPath)
	body := renderTenantPoolScoped(db, systemUser, domainID, subdomainID, docRoot)
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(poolPath, []byte(body), 0644); err != nil {
		return "", fmt.Errorf("write subdomain pool: %w", err)
	}
	globalPath := filepath.Join(tenantCfgDir(systemUser), "php-fpm.conf")
	if output, err := tenantCommand(config.FPMBin, "-t", "-y", globalPath).CombinedOutput(); err != nil {
		// Restore the previous state so a rejected pool cannot take the whole tenant
		// master down on its next reload.
		if readErr == nil {
			// #nosec G306 G703 -- root-owned system integration file that its daemon must read; no secret stored here.
			_ = os.WriteFile(poolPath, previous, 0644)
		} else {
			_ = os.Remove(poolPath)
		}
		return "", fmt.Errorf("validate subdomain pool: %s: %w", strings.TrimSpace(string(output)), err)
	}
	if output, err := tenantCommand("systemctl", "reload-or-restart", tenantUnitName(systemUser)).CombinedOutput(); err != nil {
		if readErr == nil {
			// #nosec G306 G703 -- root-owned system integration file that its daemon must read; no secret stored here.
			_ = os.WriteFile(poolPath, previous, 0644)
		} else {
			_ = os.Remove(poolPath)
		}
		_, _ = tenantCommand("systemctl", "reload-or-restart", tenantUnitName(systemUser)).CombinedOutput()
		return "", fmt.Errorf("reload tenant PHP-FPM: %s: %w", strings.TrimSpace(string(output)), err)
	}
	socket := tenantSubSocket(systemUser, subdomainID)
	if !waitForSocket(socket, 6*time.Second) {
		_ = os.Remove(poolPath)
		_, _ = tenantCommand("systemctl", "reload-or-restart", tenantUnitName(systemUser)).CombinedOutput()
		return "", fmt.Errorf("subdomain PHP-FPM socket was not created: %s", socket)
	}
	_, _ = tenantCommand("restorecon", socket).CombinedOutput()
	return socket, nil
}

// RemoveSubdomainFPM drops a subdomain's pool from the parent tenant's master. It is
// best effort: the caller has already decided the pool must not serve traffic, and a
// reload failure is reported by the next apply rather than blocking a deletion.
func RemoveSubdomainFPM(systemUser string, subdomainID int64) {
	if !tenantUserPattern.MatchString(systemUser) || subdomainID <= 0 {
		return
	}
	poolPath := tenantSubPoolPath(systemUser, subdomainID)
	if _, err := os.Stat(poolPath); err != nil {
		return
	}
	_ = os.Remove(poolPath)
	if !TenantFPMActive(systemUser) {
		return
	}
	if output, err := tenantCommand("systemctl", "reload-or-restart", tenantUnitName(systemUser)).CombinedOutput(); err != nil {
		log.Printf("remove subdomain pool %d for %s: reload failed: %s", subdomainID, systemUser, strings.TrimSpace(string(output)))
	}
	_ = os.Remove(tenantSubSocket(systemUser, subdomainID))
}

// RollbackToSharedFPM restores a domain to the shared PHP-FPM master service.
func RollbackToSharedFPM(db *sql.DB, domainID int64, systemUser, phpVersion string) error {
	if !tenantUserPattern.MatchString(systemUser) {
		return fmt.Errorf("invalid system user: %q", systemUser)
	}
	phpVersion = normalizePHP(phpVersion)
	config := phpMap[phpVersion]

	_, _ = tenantCommand("systemctl", "disable", "--now", tenantUnitName(systemUser)).CombinedOutput()
	_ = os.Remove(tenantUnitPath(systemUser))
	_, _ = tenantCommand("systemctl", "daemon-reload").CombinedOutput()

	sharedPool := filepath.Join(config.PoolDir, systemUser+".conf")
	backupPool := sharedPool + ".bak"
	var socket string
	if _, err := os.Stat(backupPool); err == nil {
		if err := os.Rename(backupPool, sharedPool); err != nil {
			return fmt.Errorf("restore shared PHP-FPM pool: %w", err)
		}
		_, _ = tenantCommand("systemctl", "reload-or-restart", config.Service).CombinedOutput()
		socket = filepath.Join(config.SockDir, systemUser+".sock")
	} else {
		var err error
		socket, _, err = writePoolValidated(systemUser, phpVersion)
		if err != nil {
			return fmt.Errorf("rebuild shared PHP-FPM pool: %w", err)
		}
	}

	_ = os.RemoveAll(tenantCfgDir(systemUser))
	_ = os.RemoveAll(tenantRunDir(systemUser))
	if db != nil && domainID > 0 {
		if err := ApplyVhostForDomain(db, domainID, socket, phpVersion); err != nil {
			return fmt.Errorf("render shared nginx virtual host: %w", err)
		}
	}
	return nil
}

// TeardownTenantFPM removes tenant service files during domain deletion.
func TeardownTenantFPM(systemUser string) {
	if !tenantUserPattern.MatchString(systemUser) {
		return
	}
	_, _ = tenantCommand("systemctl", "disable", "--now", tenantUnitName(systemUser)).CombinedOutput()
	_ = os.Remove(tenantUnitPath(systemUser))
	_, _ = tenantCommand("systemctl", "daemon-reload").CombinedOutput()
	_ = os.RemoveAll(tenantCfgDir(systemUser))
	_ = os.RemoveAll(tenantRunDir(systemUser))
	for _, config := range phpMap {
		_ = os.Remove(filepath.Join(config.PoolDir, systemUser+".conf.bak"))
	}
}

// EnsureTenantFPMOnStartup starts installed tenant services or rolls them back safely.
func EnsureTenantFPMOnStartup() {
	if packageDB == nil {
		return
	}
	rows, err := packageDB.Query(`SELECT id, system_user, php_version FROM domains`)
	if err != nil {
		log.Printf("tenant PHP-FPM startup check: %v", err)
		return
	}
	type domain struct {
		id         int64
		systemUser string
		phpVersion string
	}
	var domains []domain
	for rows.Next() {
		var item domain
		if err := rows.Scan(&item.id, &item.systemUser, &item.phpVersion); err == nil {
			domains = append(domains, item)
		}
	}
	if err := rows.Close(); err != nil {
		log.Printf("tenant PHP-FPM startup rows: %v", err)
	}
	for _, item := range domains {
		if !TenantFPMActive(item.systemUser) {
			continue
		}
		// Config-drift repair: old provisions may have left pool files with
		// unwritable error_log overrides that silently swallowed PHP fatals.
		repairTenantPoolDrift(item.id, item.systemUser, item.phpVersion)
		if output, _ := tenantCommand("systemctl", "is-active", tenantUnitName(item.systemUser)).CombinedOutput(); strings.TrimSpace(string(output)) == "active" {
			continue
		}
		if output, err := tenantCommand("systemctl", "start", tenantUnitName(item.systemUser)).CombinedOutput(); err != nil {
			log.Printf("tenant PHP-FPM startup failed for %s: %s", item.systemUser, strings.TrimSpace(string(output)))
			if rollbackErr := RollbackToSharedFPM(packageDB, item.id, item.systemUser, item.phpVersion); rollbackErr != nil {
				log.Printf("tenant PHP-FPM rollback failed for %s: %v", item.systemUser, rollbackErr)
			}
		}
	}
}

// repairTenantPoolDrift rewrites a tenant pool.conf if it has drifted from the
// current renderTenantPool template. Old provisions may have left unwritable
// php_admin_value[error_log] overrides that silently swallowed PHP fatal errors.
// Validates with php-fpm -t before committing; rolls back on failure. Graceful
// reload (USR2) avoids site downtime.
func repairTenantPoolDrift(domainID int64, systemUser, phpVersion string) {
	if packageDB == nil || systemUser == "" || !strings.HasPrefix(systemUser, "c_") {
		return
	}
	configDir := tenantCfgDir(systemUser)
	legacyMoved := false
	if _, err := os.Stat(tenantLegacyPoolPath(systemUser)); err == nil {
		if err := migrateTenantPoolLayout(systemUser); err != nil {
			log.Printf("repairTenantPoolDrift: %s pool layout migration failed: %v", systemUser, err)
			return
		}
		legacyMoved = true
	}
	poolPath := tenantMainPoolPath(systemUser)
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	current, err := os.ReadFile(poolPath)
	if err != nil {
		return // main pool missing -- EnableTenantFPM handles creation
	}
	expected := renderTenantPool(packageDB, systemUser, domainID)
	if string(current) == expected && !legacyMoved {
		return // no drift, no-op
	}
	phpVersion = normalizePHP(phpVersion)
	config := phpMap[phpVersion]
	if config.FPMBin == "" {
		return
	}
	// Write the new pool config, validate, and rollback on failure.
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(poolPath, []byte(expected), 0644); err != nil {
		return
	}
	globalPath := filepath.Join(configDir, "php-fpm.conf")
	// The global config must be rewritten in the same pass: an installation coming
	// from the old layout still includes pool.conf, which no longer exists.
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(globalPath, []byte(renderTenantGlobalConfig(systemUser)), 0644); err != nil {
		return
	}
	if output, err := tenantCommand(config.FPMBin, "-t", "-y", globalPath).CombinedOutput(); err != nil {
		// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
		_ = os.WriteFile(poolPath, current, 0644) // rollback
		log.Printf("repairTenantPoolDrift: %s php-fpm -t failed, rolled back: %s", systemUser, strings.TrimSpace(string(output)))
		return
	}
	// Graceful reload (USR2) -- does not drop active requests.
	if output, err := tenantCommand("systemctl", "reload", tenantUnitName(systemUser)).CombinedOutput(); err != nil {
		log.Printf("repairTenantPoolDrift: %s reload warning: %s", systemUser, strings.TrimSpace(string(output)))
	}
	log.Printf("repairTenantPoolDrift: %s pool.conf updated (logging hardening + config drift repair)", systemUser)
}

// ---- PHP Debug Mode (robust fatal error visibility) ----

// tenantServikaDir returns the panel-managed .servika directory for a tenant (root:root 0755).
func tenantServikaDir(systemUser string) string {
	return filepath.Join("/home", systemUser, ".servika")
}

// tenantDebugLogPath returns the per-domain debug log path (tenant:tenant 0644).
func tenantDebugLogPath(systemUser string) string {
	return filepath.Join(tenantServikaDir(systemUser), "php_debug.log")
}

// tenantDebugPrependPath returns the auto_prepend shim path (root:root 0644).
func tenantDebugPrependPath(systemUser string) string {
	return filepath.Join(tenantServikaDir(systemUser), "debug_prepend.php")
}

// errReportingRe matches valid error_reporting values (E_* tokens and operators only).
var errReportingRe = regexp.MustCompile(`^[A-Za-z0-9_ &|~()]+$`)

// sanitizeErrorReporting restricts error_reporting to [A-Za-z0-9_ &|~()] tokens only,
// preventing line/directive injection into pool config. Falls back to E_ALL on empty/invalid.
func sanitizeErrorReporting(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || !errReportingRe.MatchString(v) {
		return "E_ALL"
	}
	return v
}

// tenantDocRoot resolves the domain document root from the DB web_root column;
// falls back to /home/<systemUser>/public_html when empty.
func tenantDocRoot(db *sql.DB, systemUser string, domainID int64) string {
	if db != nil && domainID > 0 {
		var webRoot string
		if err := db.QueryRow(`SELECT COALESCE(web_root,'') FROM domains WHERE id=?`, domainID).Scan(&webRoot); err == nil {
			if webRoot = strings.TrimSpace(webRoot); webRoot != "" {
				return webRoot
			}
		}
	}
	return filepath.Join("/home", systemUser, "public_html")
}

// readUserIniAutoPrepend reads the auto_prepend_file value from docroot/.user.ini.
// In debug mode, the pool's php_admin_value[auto_prepend_file] OVERRIDES the app's
// .user.ini prepend; this value is chained back inside the shim so the app's own
// prepend is preserved.
func readUserIniAutoPrepend(docRoot string) string {
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	data, err := os.ReadFile(filepath.Join(docRoot, ".user.ini"))
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "auto_prepend_file") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// renderDebugPrependPHP generates the auto_prepend shim content. A
// register_shutdown_function + error_get_last() catches fatals even when the
// app calls error_reporting(0), writes them to the per-domain debug log, and
// displays them if display_errors is on. The original app's own .user.ini
// auto_prepend (orig) is embedded at render time and chained via require_once,
// so the app's own prepend is NOT broken.
func renderDebugPrependPHP(systemUser, orig string) string {
	logPath := tenantDebugLogPath(systemUser)
	var b strings.Builder
	// phpPrepend is embedded as a raw string so \\n produces literal backslash-n in PHP output.
	const phpPrepend = `<?php
// Servika PHP Debug Mode -- auto-generated, DO NOT EDIT.
register_shutdown_function(function(){
  $e=error_get_last();
  if($e && in_array($e['type'],[E_ERROR,E_PARSE,E_CORE_ERROR,E_COMPILE_ERROR,E_RECOVERABLE_ERROR],true)){
    @file_put_contents('`
	b.WriteString(phpPrepend)
	fmt.Fprintf(&b, "%s", logPath)
	b.WriteString(`',
      date('c').' ['.($_SERVER['REQUEST_URI']??'?').'] '.$e['message'].' @ '.$e['file'].':'.$e['line']."\n",
      FILE_APPEND|LOCK_EX);
    if(ini_get('display_errors')) echo "\n<pre style='background:#111;color:#f66;padding:8px'>PHP Fatal: ".htmlspecialchars($e['message'])." @ ".$e['file'].':'.$e['line']."</pre>";
  }
});
`)
	if orig != "" {
		esc := strings.ReplaceAll(orig, "\\", "\\\\")
		esc = strings.ReplaceAll(esc, "'", "\\'")
		fmt.Fprintf(&b, "@require_once '%s';\n", esc)
	}
	return b.String()
}

// WriteDebugShim idempotently creates the .servika directory, debug log, and
// auto_prepend shim when DebugMode is enabled.
//   - /home/<sk>/.servika        root:root 0755 (tenant cannot modify the shim)
//   - .../php_debug.log         tenant:tenant 0644 (worker appends as tenant UID)
//   - .../debug_prepend.php     root:root 0644 (tenant reads, root writes)
//
// All paths are labeled with restorecon for correct SELinux context.
func WriteDebugShim(db *sql.DB, systemUser string, domainID int64) {
	if systemUser == "" || !strings.HasPrefix(systemUser, "c_") {
		return
	}
	home := filepath.Join("/home", systemUser)
	if _, err := os.Stat(home); err != nil {
		return // tenant home missing
	}
	orig := readUserIniAutoPrepend(tenantDocRoot(db, systemUser, domainID))
	if orig == tenantDebugPrependPath(systemUser) {
		orig = "" // do not require itself
	}
	installDebugShim(home, systemUser, []byte(renderDebugPrependPHP(systemUser, orig)))
}

// installDebugShim is the FS-writing core of WriteDebugShim (extracted for testability).
// Symlink/TOCTOU-safe: /home/<sk> is tenant-owned (0710) so all operations use
// dir-fd + *at-syscall + O_NOFOLLOW. .servika is validated as a real root:root 0755
// directory (symlink/file/tenant-owned entries are removed and recreated), preventing
// cross-tenant chown DoS and arbitrary root-write.
func installDebugShim(home, sk string, content []byte) {
	homeFd, err := unix.Open(home, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(homeFd) }()

	gpFd, ok := ensureRootDirAt(homeFd, ".servika")
	if !ok {
		return
	}
	defer func() { _ = unix.Close(gpFd) }()
	restoreconFdPath(gpFd) // SELinux: relabel via pinned fd-path (no symlink -R).

	// Debug log: tenant:tenant 0644. O_NOFOLLOW + fd-based Fchown/Fchmod.
	clearUnsafeEntryAt(gpFd, "php_debug.log")
	if lf, e := unix.Openat(gpFd, "php_debug.log",
		unix.O_WRONLY|unix.O_CREAT|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0644); e == nil {
		if uid, gid, ue := uidGid(sk); ue == nil {
			_ = unix.Fchown(lf, uid, gid)
		}
		_ = unix.Fchmod(lf, 0644)
		restoreconFdPath(lf)
		_ = unix.Close(lf)
	}

	// auto_prepend shim: root:root -- tenant reads, cannot modify.
	clearUnsafeEntryAt(gpFd, "debug_prepend.php")
	if pf, e := unix.Openat(gpFd, "debug_prepend.php",
		unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0644); e == nil {
		_, _ = unix.Write(pf, content)
		_ = unix.Fchown(pf, 0, 0)
		_ = unix.Fchmod(pf, 0644)
		restoreconFdPath(pf)
		_ = unix.Close(pf)
	}
}

// clearUnsafeEntryAt removes name under parentFd when it is anything other than
// a regular file, so the O_NOFOLLOW open that follows creates the real thing.
//
// ensureRootDirAt gives .servika the same treatment and leaves it root:root
// 0755, which is what stops a tenant planting an entry inside it, so this is the
// second line rather than the first. It matters because O_NOFOLLOW only refuses
// to follow a symlink; it does not remove one. Without this the two opens below
// fail with ELOOP and silently do nothing, leaving the planted link in place,
// and a tenant who wins the window before .servika is created keeps their debug
// log permanently broken.
func clearUnsafeEntryAt(parentFd int, name string) {
	var st unix.Stat_t
	if unix.Fstatat(parentFd, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return // absent, or unreadable: let the O_NOFOLLOW open decide
	}
	if st.Mode&unix.S_IFMT == unix.S_IFREG {
		return
	}
	_ = removeAtRecursive(parentFd, name)
}

// ensureRootDirAt guarantees that `name` under parentFd is a real root:root 0755 directory.
// If the entry is a symlink, file, or tenant-owned directory, it is treated as unsafe,
// recursively removed (symlink-safe), and recreated. Uses O_NOFOLLOW open + fd-based
// Fstat to close the TOCTOU final-step race. Idempotent. Returns the dir fd on success.
func ensureRootDirAt(parentFd int, name string) (int, bool) {
	for range 3 {
		var st unix.Stat_t
		serr := unix.Fstatat(parentFd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if serr == nil {
			if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Gid != 0 {
				// Symlink, file, or wrong owner -- unsafe, remove.
				if removeAtRecursive(parentFd, name) != nil {
					return -1, false
				}
				serr = unix.ENOENT
			}
		}
		if serr == unix.ENOENT {
			if e := unix.Mkdirat(parentFd, name, 0755); e != nil && e != unix.EEXIST {
				return -1, false
			}
		} else if serr != nil {
			return -1, false
		}
		fd, e := unix.Openat(parentFd, name,
			unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if e != nil {
			continue // symlink-swap race -- retry
		}
		var fst unix.Stat_t
		if unix.Fstat(fd, &fst) != nil ||
			fst.Mode&unix.S_IFMT != unix.S_IFDIR || fst.Uid != 0 || fst.Gid != 0 {
			_ = unix.Close(fd)
			_ = removeAtRecursive(parentFd, name)
			continue
		}
		_ = unix.Fchmod(fd, 0755)
		return fd, true
	}
	return -1, false
}

// removeAtRecursive removes a file, symlink, or directory at dirfd-relative name
// without following any symlinks. Directories are traversed fd-recursively with
// O_NOFOLLOW to prevent jail-escape.
func removeAtRecursive(dirfd int, name string) error {
	if err := unix.Unlinkat(dirfd, name, 0); err == nil {
		return nil // file or symlink
	}
	fd, err := unix.Openat(dirfd, name,
		unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	buf := make([]byte, 4096)
	for {
		n, readErr := unix.ReadDirent(fd, buf)
		if n <= 0 {
			break
		}
		_, _, names := unix.ParseDirent(buf[:n], -1, nil)
		for _, childName := range names {
			if childName == "." || childName == ".." {
				continue
			}
			if err := unix.Unlinkat(fd, childName, 0); err != nil {
				_ = removeAtRecursive(fd, childName)
			}
		}
		if readErr != nil {
			break
		}
	}
	return unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR)
}

// restoreconFdPath runs restorecon on a pinned /proc/self/fd/<fd> path (no symlink risk).
func restoreconFdPath(fd int) {
	real, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_, _ = exec.Command("restorecon", real).CombinedOutput()
}
