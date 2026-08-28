// Package php manages per-domain PHP settings.
// It provides version listing, pool configuration rendering, and settings CRUD.
package php

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"servika/internal/httpx"
	"servika/internal/middleware"
	"servika/internal/phpdefaults"
	"servika/internal/phpversion"
	"servika/internal/provisioner"
	"servika/internal/subdomain"

	"github.com/go-chi/chi/v5"
)

// Version describes an installed PHP runtime and its PHP-FPM paths.
type Version struct {
	Version     string `json:"version"`
	PoolDir     string `json:"pool_dir"`
	SockDir     string `json:"sock_dir"`
	Service     string `json:"service"`
	Description string `json:"description"`
}

// InstalledVersions lists the statically supported PHP runtimes. They carry no
// description for the same reason Versions no longer builds one.
var InstalledVersions = []Version{
	{Version: "8.3", PoolDir: "/etc/php-fpm.d", SockDir: "/run/php-fpm", Service: "php-fpm"},
	{Version: "8.2", PoolDir: "/etc/opt/remi/php82/php-fpm.d", SockDir: "/var/opt/remi/php82/run/php-fpm", Service: "php82-php-fpm"},
	{Version: "7.4", PoolDir: "/etc/opt/remi/php74/php-fpm.d", SockDir: "/var/opt/remi/php74/run/php-fpm", Service: "php74-php-fpm"},
}

func versionInfo(version string) (Version, bool) {
	// Check the static list first for backward compatibility.
	for _, installedVersion := range InstalledVersions {
		if installedVersion.Version == version {
			return installedVersion, true
		}
	}
	// Discover dynamic versions through phpversion.
	for _, discoveredVersion := range phpversion.AllVersions() {
		if discoveredVersion.Version == version && discoveredVersion.Loaded {
			return Version{
				Version:     discoveredVersion.Version,
				PoolDir:     discoveredVersion.PoolDir,
				SockDir:     discoveredVersion.SockDir,
				Service:     discoveredVersion.Service,
				Description: discoveredVersion.Description,
			}, true
		}
	}
	return Version{}, false
}

// Settings contains all fields on the PHP settings page.
type Settings struct {
	// Performance & Security
	MemoryLimit       string `json:"memory_limit"`
	MaxExecutionTime  int    `json:"max_execution_time"`
	MaxInputTime      int    `json:"max_input_time"`
	PostMaxSize       string `json:"post_max_size"`
	UploadMaxFilesize string `json:"upload_max_filesize"`
	OpcacheEnable     bool   `json:"opcache_enable"`
	DisableFunctions  string `json:"disable_functions"`

	// Common
	DisplayErrors            bool   `json:"display_errors"`
	LogErrors                bool   `json:"log_errors"`
	AllowURLFopen            bool   `json:"allow_url_fopen"`
	FileUploads              bool   `json:"file_uploads"`
	ShortOpenTag             bool   `json:"short_open_tag"`
	ErrorReporting           string `json:"error_reporting"`
	IncludePath              string `json:"include_path"`
	OpenBasedir              string `json:"open_basedir"`
	SessionSavePath          string `json:"session_save_path"`
	MailForceExtraParameters string `json:"mail_force_extra_parameters"`

	// PHP-FPM
	PMStrategy        string `json:"pm_strategy"`
	PMMaxChildren     int    `json:"pm_max_children"`
	PMMaxRequests     int    `json:"pm_max_requests"`
	PMStartServers    int    `json:"pm_start_servers"`
	PMMinSpareServers int    `json:"pm_min_spare_servers"`
	PMMaxSpareServers int    `json:"pm_max_spare_servers"`

	// Additional
	ExtraDirectives string `json:"extra_directives"`
	DebugMode       bool   `json:"debug_mode"`
}

// Defaults returns the default per-domain PHP settings.
func Defaults() Settings {
	return Settings{
		MemoryLimit:       phpdefaults.MemoryLimit,
		MaxExecutionTime:  phpdefaults.MaxExecutionTime,
		MaxInputTime:      phpdefaults.MaxInputTime,
		PostMaxSize:       phpdefaults.PostMaxSize,
		UploadMaxFilesize: phpdefaults.UploadMaxFilesize,
		OpcacheEnable:     true,
		DisableFunctions:  "exec,passthru,shell_exec,system,proc_open,popen",
		DisplayErrors:     false,
		LogErrors:         true,
		AllowURLFopen:     true,
		FileUploads:       true,
		ShortOpenTag:      false,
		ErrorReporting:    "E_ALL & ~E_DEPRECATED & ~E_STRICT",
		IncludePath:       ".:/usr/share/php",
		OpenBasedir:       "",
		SessionSavePath:   "",
		PMStrategy:        "ondemand",
		PMMaxChildren:     8,
		PMMaxRequests:     500,
		PMStartServers:    2,
		PMMinSpareServers: 1,
		PMMaxSpareServers: 3,
		ExtraDirectives:   "",
		DebugMode:         false,
	}
}

// Get returns saved settings for a domain or defaults when no record exists.
func Get(ctx context.Context, db *sql.DB, domainID, subdomainID int64) (Settings, error) {
	s := Defaults()
	row := db.QueryRowContext(ctx, `SELECT memory_limit, max_execution_time, max_input_time, post_max_size,
		upload_max_filesize, opcache_enable, disable_functions,
		display_errors, log_errors, allow_url_fopen, file_uploads, short_open_tag,
		error_reporting, include_path, open_basedir, session_save_path, mail_force_extra_parameters,
		pm_strategy, pm_max_children, pm_max_requests, pm_start_servers, pm_min_spare_servers, pm_max_spare_servers,
		extra_directives, debug_mode FROM php_settings WHERE domain_id=? AND subdomain_id=?`, domainID, subdomainID)
	err := row.Scan(&s.MemoryLimit, &s.MaxExecutionTime, &s.MaxInputTime, &s.PostMaxSize,
		&s.UploadMaxFilesize, &s.OpcacheEnable, &s.DisableFunctions,
		&s.DisplayErrors, &s.LogErrors, &s.AllowURLFopen, &s.FileUploads, &s.ShortOpenTag,
		&s.ErrorReporting, &s.IncludePath, &s.OpenBasedir, &s.SessionSavePath, &s.MailForceExtraParameters,
		&s.PMStrategy, &s.PMMaxChildren, &s.PMMaxRequests, &s.PMStartServers, &s.PMMinSpareServers, &s.PMMaxSpareServers,
		&s.ExtraDirectives, &s.DebugMode)
	if errors.Is(err, sql.ErrNoRows) {
		return s, nil // Return defaults.
	}
	return s, err
}

// Save persists PHP settings for a domain.
func Save(ctx context.Context, db *sql.DB, domainID, subdomainID int64, s Settings) error {
	sanitized, err := sanitizeSettings(s)
	if err != nil {
		return err
	}
	s = sanitized
	_, err = db.ExecContext(ctx,
		`INSERT INTO php_settings(domain_id, subdomain_id, memory_limit, max_execution_time, max_input_time, post_max_size,
			upload_max_filesize, opcache_enable, disable_functions,
			display_errors, log_errors, allow_url_fopen, file_uploads, short_open_tag,
			error_reporting, include_path, open_basedir, session_save_path, mail_force_extra_parameters,
			pm_strategy, pm_max_children, pm_max_requests, pm_start_servers, pm_min_spare_servers, pm_max_spare_servers,
			extra_directives, debug_mode)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE
			memory_limit=VALUES(memory_limit),
			max_execution_time=VALUES(max_execution_time),
			max_input_time=VALUES(max_input_time),
			post_max_size=VALUES(post_max_size),
			upload_max_filesize=VALUES(upload_max_filesize),
			opcache_enable=VALUES(opcache_enable),
			disable_functions=VALUES(disable_functions),
			display_errors=VALUES(display_errors),
			log_errors=VALUES(log_errors),
			allow_url_fopen=VALUES(allow_url_fopen),
			file_uploads=VALUES(file_uploads),
			short_open_tag=VALUES(short_open_tag),
			error_reporting=VALUES(error_reporting),
			include_path=VALUES(include_path),
			open_basedir=VALUES(open_basedir),
			session_save_path=VALUES(session_save_path),
			mail_force_extra_parameters=VALUES(mail_force_extra_parameters),
			pm_strategy=VALUES(pm_strategy),
			pm_max_children=VALUES(pm_max_children),
			pm_max_requests=VALUES(pm_max_requests),
			pm_start_servers=VALUES(pm_start_servers),
			pm_min_spare_servers=VALUES(pm_min_spare_servers),
			pm_max_spare_servers=VALUES(pm_max_spare_servers),
			extra_directives=VALUES(extra_directives),
			debug_mode=VALUES(debug_mode)`,
		domainID, subdomainID, s.MemoryLimit, s.MaxExecutionTime, s.MaxInputTime, s.PostMaxSize,
		s.UploadMaxFilesize, b2i(s.OpcacheEnable), s.DisableFunctions,
		b2i(s.DisplayErrors), b2i(s.LogErrors), b2i(s.AllowURLFopen), b2i(s.FileUploads), b2i(s.ShortOpenTag),
		s.ErrorReporting, s.IncludePath, s.OpenBasedir, s.SessionSavePath, s.MailForceExtraParameters,
		s.PMStrategy, s.PMMaxChildren, s.PMMaxRequests, s.PMStartServers, s.PMMinSpareServers, s.PMMaxSpareServers,
		s.ExtraDirectives, b2i(s.DebugMode))
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func onoff(b bool) string {
	if b {
		return "On"
	}
	return "Off"
}

var extraDirectivePattern = regexp.MustCompile(`^php_(?:value|flag)\[([a-zA-Z0-9_.]+)\]\s*=`)

var prohibitedExtraDirectives = map[string]bool{
	"open_basedir": true, "disable_functions": true, "disable_classes": true,
	"extension": true, "zend_extension": true,
	"auto_prepend_file": true, "auto_append_file": true,
	"error_log": true, "sys_temp_dir": true, "upload_tmp_dir": true,
	"session.save_path": true, "mail.force_extra_parameters": true,
	"curl.cainfo": true, "openssl.capath": true, "include_path": true,
}

func sanitizeExtraDirectives(raw string) (string, error) {
	if strings.ContainsRune(raw, '\x00') {
		return "", errors.New("extra directives contain a NUL character")
	}
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	lines := strings.Split(raw, "\n")
	cleaned := make([]string, 0, len(lines))
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			cleaned = append(cleaned, trimmed)
			continue
		}
		match := extraDirectivePattern.FindStringSubmatch(trimmed)
		if match == nil {
			return "", fmt.Errorf("extra directive line %d is not an allowed php_value or php_flag directive", i+1)
		}
		key := strings.ToLower(match[1])
		if prohibitedExtraDirectives[key] {
			return "", fmt.Errorf("extra directive line %d cannot override %s", i+1, key)
		}
		cleaned = append(cleaned, trimmed)
	}
	return strings.Join(cleaned, "\n"), nil
}

// phpSizePattern is the shorthand PHP itself accepts for a byte quantity:
// digits with an optional K, M or G multiplier in either case, plus the special
// -1 for unlimited. Measured against PHP 8.3.32: `2048M`, `1g`, `1048576` and
// `-1` are taken as written, while `2048MB` answers `unknown multiplier "B"`,
// `2.5G` answers `Invalid quantity "2.5G"` and `notasize` answers
// `no valid leading digits, interpreting as "0"`.
//
// The check is on the WRITE path because nothing downstream performs it. The
// same measurement showed php-fpm -t reporting `test is successful` and exiting
// 0 for a pool carrying `php_admin_value[memory_limit] = notasize`, so a typo
// reaches the interpreter as a memory limit of zero and the site fails on every
// request with no configuration error anywhere to explain it.
var phpSizePattern = regexp.MustCompile(`^(?:-1|[0-9]+[KkMmGg]?)$`)

// Reason codes for a refused setting. The API is English and the interface
// ships twelve languages, so the screen receives a code and words it.
const (
	reasonControlCharacter = "php_setting_contains_control_character"
	reasonInvalidSize      = "php_size_value_invalid"
)

// settingError carries the stable reason code beside a detail for the log. The
// handler answers the code alone, so the screen has something it can translate
// rather than one flat "invalid PHP settings" for every cause.
type settingError struct {
	Reason string
	Detail string
}

func (e settingError) Error() string { return e.Reason + ": " + e.Detail }

func sanitizeSettings(s Settings) (Settings, error) {
	// Sizes are trimmed before they are checked and stored. PHP ignores the
	// surrounding whitespace, so refusing " 2048M" would be refusing a value
	// that works, and storing it would put the space into the pool file.
	s.MemoryLimit = strings.TrimSpace(s.MemoryLimit)
	s.PostMaxSize = strings.TrimSpace(s.PostMaxSize)
	s.UploadMaxFilesize = strings.TrimSpace(s.UploadMaxFilesize)
	for name, value := range map[string]string{
		"memory_limit":        s.MemoryLimit,
		"post_max_size":       s.PostMaxSize,
		"upload_max_filesize": s.UploadMaxFilesize,
	} {
		if !phpSizePattern.MatchString(value) {
			return Settings{}, settingError{Reason: reasonInvalidSize, Detail: name + " is not a PHP size value"}
		}
	}

	scalars := map[string]string{
		"memory_limit":                s.MemoryLimit,
		"post_max_size":               s.PostMaxSize,
		"upload_max_filesize":         s.UploadMaxFilesize,
		"disable_functions":           s.DisableFunctions,
		"error_reporting":             s.ErrorReporting,
		"include_path":                s.IncludePath,
		"open_basedir":                s.OpenBasedir,
		"session_save_path":           s.SessionSavePath,
		"mail_force_extra_parameters": s.MailForceExtraParameters,
		"pm_strategy":                 s.PMStrategy,
	}
	for name, value := range scalars {
		if strings.ContainsAny(value, "\r\n\x00") {
			return Settings{}, settingError{Reason: reasonControlCharacter, Detail: name + " contains a line break or NUL character"}
		}
	}
	cleaned, err := sanitizeExtraDirectives(s.ExtraDirectives)
	if err != nil {
		return Settings{}, err
	}
	s.ExtraDirectives = cleaned
	return s, nil
}

// poolTmpl contains the complete PHP-FPM pool configuration.
var poolTmpl = template.Must(template.New("pool").Funcs(template.FuncMap{"onoff": onoff}).Parse(`[{{.SystemUser}}]
user = {{.SystemUser}}
group = {{.SystemUser}}
listen = {{.SockDir}}/{{.SystemUser}}.sock
listen.owner = nginx
listen.group = nginx
listen.mode = 0660

pm = {{.S.PMStrategy}}
pm.max_children = {{.S.PMMaxChildren}}
pm.max_requests = {{.S.PMMaxRequests}}
pm.start_servers = {{.S.PMStartServers}}
pm.min_spare_servers = {{.S.PMMinSpareServers}}
pm.max_spare_servers = {{.S.PMMaxSpareServers}}
pm.process_idle_timeout = 30s

; ---- Performance & Security ----
php_admin_value[memory_limit] = {{.S.MemoryLimit}}
php_admin_value[max_execution_time] = {{.S.MaxExecutionTime}}
php_admin_value[max_input_time] = {{.S.MaxInputTime}}
php_admin_value[post_max_size] = {{.S.PostMaxSize}}
php_admin_value[upload_max_filesize] = {{.S.UploadMaxFilesize}}
php_admin_value[max_input_vars] = 10000
php_admin_value[disable_functions] = {{.S.DisableFunctions}}

; ---- Common ----
php_admin_flag[log_errors] = {{onoff .S.LogErrors}}
php_admin_flag[allow_url_fopen] = {{onoff .S.AllowURLFopen}}
php_admin_flag[file_uploads] = {{onoff .S.FileUploads}}
php_admin_flag[short_open_tag] = {{onoff .S.ShortOpenTag}}
{{if .S.DebugMode}}; ---- Debug Mode (overrides display_errors/error_reporting) ----
php_admin_flag[display_errors] = on
php_admin_value[error_reporting] = E_ALL
php_admin_value[auto_prepend_file] = /home/{{.SystemUser}}/.servika/debug_prepend.php
{{else}}php_admin_flag[display_errors] = {{onoff .S.DisplayErrors}}
php_admin_value[error_reporting] = {{.S.ErrorReporting}}
{{end}}
php_admin_value[include_path] = {{.S.IncludePath}}
php_admin_value[open_basedir] = {{if .S.OpenBasedir}}{{.S.OpenBasedir}}{{else}}/home/{{.SystemUser}}/:/tmp/{{end}}
{{if .S.MailForceExtraParameters}}php_admin_value[mail.force_extra_parameters] = {{.S.MailForceExtraParameters}}{{end}}
php_admin_value[session.save_path] = {{if .S.SessionSavePath}}{{.S.SessionSavePath}}{{else}}/home/{{.SystemUser}}/tmp{{end}}
php_admin_value[upload_tmp_dir] = /home/{{.SystemUser}}/tmp
php_admin_value[sys_temp_dir] = /home/{{.SystemUser}}/tmp

catch_workers_output = yes

; ---- BEGIN_CUSTOM ----
{{.S.ExtraDirectives}}
; ---- END_CUSTOM ----
`))

// RenderPool generates pool configuration from settings, system user, and socket directory.
func RenderPool(systemUser string, sockDir string, s Settings) (string, error) {
	sanitized, err := sanitizeSettings(s)
	if err != nil {
		return "", err
	}
	// The mandatory floor is merged at render time so a shared-master pool blocks
	// the same LPE primitives a tenant's own master does. An empty disable_functions
	// must not leave the tenant fully open. It is applied here, not on the stored
	// value, so the settings screen keeps showing exactly what the operator set.
	sanitized.DisableFunctions = provisioner.MergeMandatoryDisableFunctions(sanitized.DisableFunctions)
	var buf bytes.Buffer
	err = poolTmpl.Execute(&buf, map[string]any{"SystemUser": systemUser, "SockDir": sockDir, "S": sanitized})
	return buf.String(), err
}

// ApplyToFilesystem writes pool configuration, removes old-version pools, and reloads PHP-FPM.
func ApplyToFilesystem(systemUser, version string, s Settings) (socket string, err error) {
	sb, ok := versionInfo(version)
	if !ok {
		return "", fmt.Errorf("unsupported PHP version: %s", version)
	}
	// Remove pools from previous versions.
	for _, other := range InstalledVersions {
		if other.Version == version {
			continue
		}
		// #nosec G703 -- systemUser is the provisioned tenant account read from the domains row (^c_[A-Za-z0-9_]+$), never raw request input; PoolDir is a fixed system path.
		old := filepath.Join(other.PoolDir, systemUser+".conf")
		// #nosec G703 -- old is <fixed per-version PoolDir>/<provisioned tenant account>.conf; neither component comes from the request.
		if _, err := os.Stat(old); err == nil {
			// #nosec G703 -- same path as the stat above: fixed PoolDir plus the provisioned tenant account.
			_ = os.Remove(old)
			// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
			_, _ = exec.Command("systemctl", "reload-or-restart", other.Service).CombinedOutput()
		}
	}

	// #nosec G301 G703 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; the path is a fixed per-version constant, not request input.
	_ = os.MkdirAll(sb.PoolDir, 0755)
	// #nosec G301 G703 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; the path is a fixed per-version constant, not request input.
	_ = os.MkdirAll(sb.SockDir, 0755)
	body, err := RenderPool(systemUser, sb.SockDir, s)
	if err != nil {
		return "", err
	}
	// #nosec G703 -- systemUser is the provisioned tenant account read from the domains row (^c_[A-Za-z0-9_]+$), never raw request input; PoolDir is a fixed system path.
	poolPath := filepath.Join(sb.PoolDir, systemUser+".conf")
	// #nosec G306 G703 -- root-owned PHP-FPM pool file its daemon must read; the path is a fixed PoolDir plus the provisioned tenant account, and no secret is stored here.
	if err := os.WriteFile(poolPath, []byte(body), 0644); err != nil {
		return "", err
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	if out, err := exec.Command("systemctl", "reload-or-restart", sb.Service).CombinedOutput(); err != nil {
		return "", fmt.Errorf("php-fpm reload (%s): %s: %w", sb.Service, strings.TrimSpace(string(out)), err)
	}
	socket = filepath.Join(sb.SockDir, systemUser+".sock")
	return socket, nil
}

// ----- HTTP handlers -----

// Handlers provides HTTP handlers for PHP runtime and settings operations.
type Handlers struct {
	DB *sql.DB
}

// Versions returns dynamically discovered installed versions.
// loadedRuntimes returns the runtimes that are actually installed, one entry per
// version number. Discovery reports the same version once per repository, so
// without the dedupe a version installed from two sources would be offered twice.
func loadedRuntimes(all []phpversion.Version) []phpversion.Version {
	unique := []phpversion.Version{}
	seen := map[string]bool{}
	for _, discovered := range all {
		if !discovered.Loaded || seen[discovered.Version] {
			continue
		}
		seen[discovered.Version] = true
		unique = append(unique, discovered)
	}
	return unique
}

// sourceLabel names the repository a runtime came from, and nothing else.
//
// It is deliberately this short. The label it replaced on the create form read
// "Remi · Remi modular, development/test/legacy", which repeated the word Remi
// and described current 8.4 and 8.5 as legacy, while the AppStream one promised
// OPcache that the base package set does not install.
func sourceLabel(resource string) string {
	if resource == "appstream" {
		return "AppStream"
	}
	return "Remi"
}

// runtimeChoices lists the installed runtimes WITHOUT a source label. It feeds
// the domain create form, where the version number is the whole decision and any
// label can only mislead. The source is shown on the PHP Versions screen, which
// already renders it as its own badge.
func runtimeChoices(all []phpversion.Version) []Version {
	choices := []Version{}
	for _, runtime := range loadedRuntimes(all) {
		choices = append(choices, Version{
			Version: runtime.Version,
			PoolDir: runtime.PoolDir,
			SockDir: runtime.SockDir,
			Service: runtime.Service,
		})
	}
	return choices
}

// runtimeChoicesWithSource lists the installed runtimes WITH their source. It
// feeds the per-domain PHP screen, where the label is the only thing that says
// where a version came from.
func runtimeChoicesWithSource(all []phpversion.Version) []Version {
	choices := []Version{}
	for _, runtime := range loadedRuntimes(all) {
		choices = append(choices, Version{
			Version:     runtime.Version,
			PoolDir:     runtime.PoolDir,
			SockDir:     runtime.SockDir,
			Service:     runtime.Service,
			Description: sourceLabel(runtime.Resource),
		})
	}
	return choices
}

func (h *Handlers) Versions(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, runtimeChoices(phpversion.AllVersions()))
}

// scope resolves the target of a settings request. The route carries an optional
// {sid}; when present the request targets that subdomain and everything below it
// (the stored row, the reported version, the display name) follows the subdomain
// rather than the parent domain. ResolveScope rejects a subdomain that belongs to a
// different domain, so a tenant cannot reach another domain's settings by id.
func (h *Handlers) scope(r *http.Request) (domainID, subdomainID int64, displayName, systemUser, version string, ok bool) {
	domainID, _ = strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain_name, system_user, php_version FROM domains WHERE id=?`, domainID).
		Scan(&displayName, &systemUser, &version); err != nil {
		return domainID, 0, "", "", "", false
	}
	sid, _ := strconv.ParseInt(chi.URLParam(r, "sid"), 10, 64)
	if sid <= 0 {
		return domainID, 0, displayName, systemUser, version, true
	}
	sc, found := subdomain.ResolveScope(r.Context(), h.DB, domainID, sid)
	if !found {
		return domainID, 0, "", "", "", false
	}
	return domainID, sc.SubdomainID, sc.FQDN, systemUser, sc.PHPVersion, true
}

// GetSettings returns domain PHP settings and the active version.
func (h *Handlers) GetSettings(w http.ResponseWriter, r *http.Request) {
	id, sid, domainName, systemUser, version, ok := h.scope(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	s, err := Get(r.Context(), h.DB, id, sid)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load PHP settings")
		return
	}
	// List modules installed for the domain PHP version.
	modules := versionModules(version)

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"domain_name":  domainName,
		"system_user":  systemUser,
		"php_version":  version,
		"subdomain_id": sid,
		"settings":     s,
		"modules":      modules,
		"versions":     runtimeChoicesWithSource(phpversion.AllVersions()),
	})
}

// PutSettings saves settings and an optional version, then rewrites pool configuration.
func (h *Handlers) PutSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PHPVersion string   `json:"php_version,omitempty"` // Optional. Changes the version when provided.
		Settings   Settings `json:"settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	id, sid, _, systemUser, version, ok := h.scope(r)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	var demo int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT is_demo FROM domains WHERE id=?`, id).Scan(&demo); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	if demo == 1 {
		httpx.WriteError(w, http.StatusForbidden, "PHP settings are fixed for demo subscriptions")
		return
	}
	if req.PHPVersion != "" && req.PHPVersion != version {
		if _, ok := versionInfo(req.PHPVersion); !ok {
			httpx.WriteError(w, http.StatusBadRequest, "unsupported PHP version")
			return
		}
		version = req.PHPVersion
	}

	// disable_functions is an ISOLATION control, so only an admin may change it.
	// A customer or reseller (or a hijacked customer session) could otherwise send
	// disable_functions="" and open system/exec/shell_exec in their own PHP, a
	// proven isolation escape. For a non-admin the incoming value is IGNORED: the
	// stored value is kept, or the hardened default when no row exists yet. This
	// runs BEFORE sanitizeSettings so a non-admin's value is never even validated,
	// and it fails closed (a missing claim is treated as non-admin). The tenant
	// PHP-FPM mandatory floor is applied at render time regardless.
	if claims := middleware.ClaimsFrom(r); claims == nil || claims.Role != middleware.RoleAdmin {
		var current sql.NullString
		_ = h.DB.QueryRowContext(r.Context(),
			`SELECT disable_functions FROM php_settings WHERE domain_id=? AND subdomain_id=?`, id, sid).Scan(&current)
		if current.Valid {
			req.Settings.DisableFunctions = current.String
		} else {
			req.Settings.DisableFunctions = Defaults().DisableFunctions
		}
	}

	sanitized, err := sanitizeSettings(req.Settings)
	if err != nil {
		// Answer the reason CODE. With the size fields now free text, "invalid
		// PHP settings" leaves an operator staring at a form with no idea which
		// box the server refused or why.
		reason := "invalid PHP settings"
		var refused settingError
		if errors.As(err, &refused) {
			reason = refused.Reason
		}
		httpx.WriteError(w, http.StatusBadRequest, reason)
		return
	}
	req.Settings = sanitized
	if err := Save(r.Context(), h.DB, id, sid, req.Settings); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to save PHP settings")
		return
	}
	if sid > 0 {
		h.applySubdomain(w, r, id, sid, systemUser, version, req.PHPVersion != "")
		return
	}
	var socket string
	provisioner.WriteDebugShim(h.DB, systemUser, id)
	if provisioner.TenantFPMActive(systemUser) {
		// The GUARDED variant: this is a person saving one domain's settings, so
		// a master that starts and then dies is worth watching for and putting
		// back. The watching is asynchronous and adds nothing to this response.
		// The startup and drift paths keep calling the plain EnableTenantFPM.
		socket, err = provisioner.EnableTenantFPMGuarded(h.DB, id, systemUser, version)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to apply tenant PHP-FPM configuration")
			return
		}
	} else {
		socket, err = ApplyToFilesystem(systemUser, version, req.Settings)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to apply PHP pool configuration")
			return
		}
		if err := provisioner.ApplyVhostForDomain(h.DB, id, socket, version); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to apply nginx virtual host")
			return
		}
	}

	if req.PHPVersion != "" {
		_, _ = h.DB.ExecContext(r.Context(),
			`UPDATE domains SET php_version=? WHERE id=?`, version, id)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"php_version": version,
		"socket":      socket,
	})
}

// applySubdomain publishes settings that were just saved for a subdomain. The version
// is written before the pool is rendered because the pool's eligibility check reads it,
// and it is rolled back when the pool cannot be installed so the record never claims a
// version nginx is not serving.
func (h *Handlers) applySubdomain(w http.ResponseWriter, r *http.Request, domainID, subdomainID int64, systemUser, version string, versionChanged bool) {
	var previousVersion string
	if versionChanged {
		if err := h.DB.QueryRowContext(r.Context(),
			`SELECT COALESCE(php_version,'') FROM subdomains WHERE id=? AND domain_id=?`, subdomainID, domainID).
			Scan(&previousVersion); err != nil {
			httpx.WriteError(w, http.StatusNotFound, "subdomain not found")
			return
		}
		if _, err := h.DB.ExecContext(r.Context(),
			`UPDATE subdomains SET php_version=? WHERE id=? AND domain_id=?`, version, subdomainID, domainID); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "failed to save the PHP version")
			return
		}
	}
	scope, found := subdomain.ResolveScope(r.Context(), h.DB, domainID, subdomainID)
	if !found {
		httpx.WriteError(w, http.StatusNotFound, "subdomain not found")
		return
	}
	socket, err := provisioner.ApplySubdomainFPM(h.DB, domainID, subdomainID, systemUser, scope.DocRoot, version)
	if err == nil {
		err = subdomain.ReRender(h.DB, subdomainID)
	}
	if err != nil {
		if versionChanged {
			if _, rollbackErr := h.DB.ExecContext(r.Context(),
				`UPDATE subdomains SET php_version=? WHERE id=? AND domain_id=?`, previousVersion, subdomainID, domainID); rollbackErr != nil {
				// #nosec G706 -- the logged values are an integer id and a database error, never raw tenant text.
				log.Printf("subdomain %d PHP version rollback failed: %v", subdomainID, rollbackErr)
			}
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to apply PHP pool configuration")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"php_version": version,
		"socket":      socket,
	})
}

// GetDebugLog returns the last 200 lines of the per-domain PHP debug log.
func (h *Handlers) GetDebugLog(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var systemUser string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).Scan(&systemUser); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	p, err := debugLogPath(systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	f, openErr := os.Open(p)
	if openErr != nil {
		// File missing or unreadable -- debug may never have been triggered.
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"lines": []string{}})
		return
	}
	defer func() { _ = f.Close() }()
	// DoS-safe: only read the last ~64KB instead of the entire file.
	const tailBytes = 64 * 1024
	var data []byte
	if st, statErr := f.Stat(); statErr == nil && st.Size() > tailBytes {
		buf := make([]byte, tailBytes)
		if _, e := f.ReadAt(buf, st.Size()-tailBytes); e == nil || e == io.EOF {
			if i := bytes.IndexByte(buf, '\n'); i >= 0 {
				buf = buf[i+1:] // skip the partial first line
			}
			data = buf
		}
	} else {
		data, _ = io.ReadAll(f)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = []string{}
	}
	const maxLines = 200
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"lines": lines})
}

// ClearDebugLog truncates the per-domain PHP debug log.
func (h *Handlers) ClearDebugLog(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	var systemUser string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT system_user FROM domains WHERE id=?`, id).Scan(&systemUser); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "domain not found")
		return
	}
	p, err := debugLogPath(systemUser)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := os.Truncate(p, 0); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to clear debug log")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// debugLogPath returns the per-domain PHP debug log path. The systemUser value
// originates from the domain record and is validated for the c_ prefix, so
// there is no path traversal risk.
func debugLogPath(systemUser string) (string, error) {
	if systemUser == "" || !strings.HasPrefix(systemUser, "c_") {
		return "", fmt.Errorf("invalid system user")
	}
	return "/home/" + systemUser + "/.servika/php_debug.log", nil
}

// versionModules lists modules loaded by PHP-FPM for a version.
func versionModules(version string) []string {
	sb, ok := versionInfo(version)
	if !ok {
		return nil
	}
	// Find the PHP binary.
	phpBin := "/usr/bin/php"
	if sb.Service != "php-fpm" {
		// "php82-php-fpm" -> "/opt/remi/php82/root/usr/bin/php"
		// Extract the service prefix.
		// Query phpversion for the precise path.
		for _, discoveredVersion := range phpversion.AllVersions() {
			if discoveredVersion.Version == version && discoveredVersion.Loaded {
				phpBin = discoveredVersion.PHPBin
				break
			}
		}
	}
	out, err := exec.Command(phpBin, "-m").Output()
	if err != nil {
		return nil
	}
	modules := []string{}
	for ln := range strings.SplitSeq(string(out), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "[") {
			continue
		}
		modules = append(modules, ln)
	}
	return modules
}
