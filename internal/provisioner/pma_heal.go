package provisioner

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"servika/internal/config"
)

const (
	pmaPoolPath   = "/etc/php-fpm.d/phpmyadmin.conf"
	pmaSocketPath = "/var/lib/mysql/mysql.sock"
)

func pmaSignonDir() string { return config.PMASignonDir() }

func pmaSignonPath() string { return filepath.Join(pmaSignonDir(), "pma-signon.php") }

func pmaTokenPath() string { return config.PMATokenPath() }

func pmaConfigPath() string { return config.PHPMyAdminConfig() }

var (
	pmaTokenPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	pmaConfigHost   = regexp.MustCompile(`(?m)(\$cfg\['Servers'\]\[\$i\]\['host'\]\s*=\s*)'[^']*';`)
)

const pmaSignonPHPTemplate = `<?php
/**
 * Exchanges a short-lived Servika token for phpMyAdmin signon credentials.
 */
declare(strict_types=1);

session_name('pma_signon');
ini_set('session.cookie_path', '/');
session_start();

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    exit('Open phpMyAdmin from Servika.');
}

$token = isset($_POST['t']) ? (string) $_POST['t'] : '';
if (!preg_match('/^[a-f0-9]{16,128}$/', $token)) {
    http_response_code(400);
    exit('Invalid signon token. Open phpMyAdmin from Servika.');
}

$internalToken = trim((string) @file_get_contents('{{PMA_TOKEN_PATH}}'));
if ($internalToken === '') {
    http_response_code(500);
    exit('phpMyAdmin signon is not configured.');
}

$payload = json_encode(['token' => $token], JSON_THROW_ON_ERROR);
$curl = curl_init('http://127.0.0.1:8080/api/v1/internal/pma-redeem');
if ($curl === false) {
    http_response_code(500);
    exit('phpMyAdmin signon could not be initialized.');
}

curl_setopt_array($curl, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $payload,
    CURLOPT_HTTPHEADER => [
        'Content-Type: application/json',
        'X-Internal-Auth: ' . $internalToken,
    ],
    CURLOPT_CONNECTTIMEOUT => 3,
    CURLOPT_TIMEOUT => 5,
]);
$response = curl_exec($curl);
$status = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
curl_close($curl);

if ($status !== 200 || !is_string($response)) {
    http_response_code(401);
    exit('The signon token could not be redeemed. Open phpMyAdmin from Servika again.');
}

$data = json_decode($response, true);
if (!is_array($data)
    || !is_string($data['username'] ?? null)
    || !is_string($data['password'] ?? null)
    || !is_string($data['db'] ?? null)
) {
    http_response_code(500);
    exit('The signon service returned an invalid response.');
}

session_regenerate_id(true);
$_SESSION['PMA_single_signon_user'] = $data['username'];
$_SESSION['PMA_single_signon_password'] = $data['password'];
$_SESSION['PMA_single_signon_host'] = 'localhost';
$_SESSION['PMA_single_signon_only_db'] = [$data['db']];
session_write_close();

header('Location: /pma/', true, 302);
exit;
`

func pmaSignonPHP() string {
	return strings.ReplaceAll(pmaSignonPHPTemplate, "{{PMA_TOKEN_PATH}}", addcslashes(pmaTokenPath()))
}

func addcslashes(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `'`, `\'`)
}

func ensurePMAStartup() {
	ensurePMASignon()
	ensurePMAToken()
	ensurePMAPoolSocket()
	ensurePMAConfigHost()
	// Last, because ensurePMAConfigHost rewrites config.inc.php. os.WriteFile
	// leaves an existing file's mode alone, so the order is not load-bearing
	// today, but a writer added later would be covered without anyone noticing
	// it had to be.
	ensurePMAOwnership()
	ensurePMASELinux()
}

// phpMyAdmin's two trees carry different types because one is served and the
// other is written: the installation is content the web server reads, and the
// session and temporary directory is content it also writes. These are the
// types assets/ops/servika-repair already applies.
const (
	pmaRootSELinuxType   = "httpd_sys_content_t"
	pmaVarLibSELinuxType = "httpd_sys_rw_content_t"
)

// ensurePMASELinux labels the phpMyAdmin trees with a persistent rule.
//
// The installer ran a bare `restorecon`, which only applies rules that already
// exist. Neither path is known to the distribution's policy, so they inherit
// the default for their parent and the next full relabel puts that default back
// however the permissions read. On an Enforcing host that is phpMyAdmin
// answering 403, which is why the label is read back and a wrong one is
// reported rather than assumed to have worked.
func ensurePMASELinux() {
	for _, target := range []struct {
		path     string
		typeName string
	}{
		{config.PHPMyAdminRoot(), pmaRootSELinuxType},
		{config.PHPMyAdminVarLib(), pmaVarLibSELinuxType},
	} {
		if _, err := os.Stat(target.path); err != nil {
			continue // phpMyAdmin is not installed on this host
		}
		if err := ensureSELinuxType(target.path, target.typeName); err != nil {
			log.Printf("phpMyAdmin repair: %v; phpMyAdmin may be refused on an Enforcing host", err)
		}
	}
}

// pmaPoolUser reads the account the phpMyAdmin PHP-FPM pool runs as.
//
// It is read rather than assumed because the value decides who may read the
// panel's phpMyAdmin secrets. Guessing wrong in one direction leaves them
// world-readable and in the other stops phpMyAdmin from reading its own
// configuration, which is a full outage rather than a degraded feature.
// `apache` is the pool shipped in assets/php-fpm/phpmyadmin.conf and the
// fallback when the file cannot be read.
func pmaPoolUser() string {
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	body, err := os.ReadFile(pmaPoolPath)
	if err != nil {
		return "apache"
	}
	return pmaPoolUserFrom(string(body))
}

// pmaPoolUserFrom takes the `user` directive out of a php-fpm pool body.
func pmaPoolUserFrom(body string) string {
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(name) != "user" {
			continue
		}
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return "apache"
}

// ensurePMAOwnership gives the phpMyAdmin secrets to the account that has to
// read them, and to nobody else.
//
// config.inc.php carries `blowfish_secret`, which encrypts the MySQL
// credentials phpMyAdmin stores in the visitor's cookie, and `controlpass` for
// the `pma` account that holds ALL PRIVILEGES on the phpmyadmin schema. The
// installer left the tree owned by nginx while the pool runs as apache, so the
// file only worked by being world-readable, and every c_* tenant on the host
// could read both secrets over SSH, cron or PHP.
//
// The session directory is 0700 rather than 0755 for the same reason: a
// phpMyAdmin session file holds the credentials of whoever is signed in.
//
// This runs on every startup because the repair belongs where an existing
// installation reaches it. assets/ops/servika-repair already applied these
// modes, so an operator who ran it was covered and one who never did was not.
// pmaLookupAccount and pmaChown are seams: a test cannot create the `apache`
// account and cannot chown to it, so it supplies both and asserts the modes,
// which are the half that decides who can read the secrets.
var (
	pmaLookupAccount = lookupUserAndGroup
	pmaChown         = os.Chown
)

func ensurePMAOwnership() {
	poolUser := pmaPoolUser()
	uid, gid, err := pmaLookupAccount(poolUser)
	if err != nil {
		log.Printf("phpMyAdmin repair: %v, ownership left alone", err)
		return
	}

	varLib := config.PHPMyAdminVarLib()
	// root keeps the configuration and the pool reads it through the group. The
	// pool WRITES the other three, so it owns those outright.
	for _, target := range []struct {
		path string
		uid  int
		mode os.FileMode
	}{
		{pmaConfigPath(), 0, 0640},
		{varLib, uid, 0755},
		{filepath.Join(varLib, "tmp"), uid, 0755},
		{filepath.Join(varLib, "sessions"), uid, 0700},
	} {
		if _, err := os.Stat(target.path); err != nil {
			continue
		}
		// The order is load-bearing and so is the refusal to continue past a
		// failed chown. Tightening the mode while the file still belongs to the
		// wrong account does not protect the secret, it locks phpMyAdmin out of
		// its own configuration, which is an outage rather than a weaker
		// permission. Leaving the old mode is the lesser of the two.
		if err := pmaChown(target.path, target.uid, gid); err != nil {
			log.Printf("phpMyAdmin repair: could not set ownership of %s: %v; permissions left as they were", target.path, err)
			continue
		}
		// #nosec G302 -- root-owned system file or directory its daemon must read; 0640 on config.inc.php is what keeps the blowfish secret and the control-user password off every other account.
		if err := os.Chmod(target.path, target.mode); err != nil {
			log.Printf("phpMyAdmin repair: could not set permissions of %s: %v", target.path, err)
		}
	}
}

// lookupUserAndGroup resolves an account name to its numeric ids.
func lookupUserAndGroup(name string) (uid, gid int, err error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("the %q account is unavailable: %w", name, err)
	}
	if uid, err = strconv.Atoi(account.Uid); err != nil {
		return 0, 0, fmt.Errorf("the %q account has a non-numeric uid: %w", name, err)
	}
	if gid, err = strconv.Atoi(account.Gid); err != nil {
		return 0, 0, fmt.Errorf("the %q account has a non-numeric gid: %w", name, err)
	}
	return uid, gid, nil
}

func ensurePMASignon() {
	signonDir := pmaSignonDir()
	signonPath := pmaSignonPath()
	signonPHP := pmaSignonPHP()
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(signonDir, 0755); err != nil {
		log.Printf("phpMyAdmin repair: could not create signon directory: %v", err)
		return
	}
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	current, err := os.ReadFile(signonPath)
	if err == nil && string(current) == signonPHP {
		return
	}
	// #nosec G306 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(signonPath, []byte(signonPHP), 0644); err != nil {
		log.Printf("phpMyAdmin repair: could not write signon endpoint: %v", err)
		return
	}
	_, _ = tenantCommand("restorecon", signonPath).CombinedOutput()
}

func ensurePMAToken() {
	tokenPath := pmaTokenPath()
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	current, err := os.ReadFile(tokenPath)
	token := strings.TrimSpace(string(current))
	if err != nil || !pmaTokenPattern.MatchString(token) {
		// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
		if err := os.MkdirAll(filepath.Dir(tokenPath), 0755); err != nil {
			log.Printf("phpMyAdmin repair: could not create token directory: %v", err)
			return
		}
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			log.Printf("phpMyAdmin repair: could not generate internal token: %v", err)
			return
		}
		if err := os.WriteFile(tokenPath, []byte(hex.EncodeToString(raw)+"\n"), 0600); err != nil {
			log.Printf("phpMyAdmin repair: could not write internal token: %v", err)
			return
		}
	}

	group, err := user.LookupGroup("apache")
	if err != nil {
		_ = os.Chown(tokenPath, 0, 0)
		_ = os.Chmod(tokenPath, 0600)
		log.Printf("phpMyAdmin repair: apache group unavailable, internal token remains root-only")
		return
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		log.Printf("phpMyAdmin repair: invalid apache group ID")
		return
	}
	if err := os.Chown(tokenPath, 0, gid); err != nil {
		log.Printf("phpMyAdmin repair: could not set internal token ownership: %v", err)
		return
	}
	// #nosec G302 -- root-owned system file its daemon must read; secrets use 0600/0640 elsewhere.
	if err := os.Chmod(tokenPath, 0640); err != nil {
		log.Printf("phpMyAdmin repair: could not set internal token permissions: %v", err)
	}
}

func ensurePMAPoolSocket() {
	current, err := os.ReadFile(pmaPoolPath)
	if err != nil {
		return
	}
	updated := string(current)
	changed := false
	for _, setting := range []string{"mysqli.default_socket", "pdo_mysql.default_socket"} {
		pattern := regexp.MustCompile(`(?m)^\s*php_value\[` + regexp.QuoteMeta(setting) + `\]\s*=.*$`)
		line := "php_value[" + setting + "] = " + pmaSocketPath
		if pattern.MatchString(updated) {
			replaced := pattern.ReplaceAllString(updated, line)
			changed = changed || replaced != updated
			updated = replaced
		} else {
			updated = strings.TrimRight(updated, "\n") + "\n" + line + "\n"
			changed = true
		}
	}
	if !changed {
		return
	}
	// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(pmaPoolPath, []byte(updated), 0644); err != nil {
		log.Printf("phpMyAdmin repair: could not update PHP-FPM socket settings: %v", err)
		return
	}
	if output, err := tenantCommand("systemctl", "reload-or-restart", "php-fpm").CombinedOutput(); err != nil {
		log.Printf("phpMyAdmin repair: PHP-FPM reload failed: %s", strings.TrimSpace(string(output)))
	}
}

func ensurePMAConfigHost() {
	configPath := pmaConfigPath()
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	current, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	updated := pmaConfigHost.ReplaceAllString(string(current), `${1}'localhost';`)
	if updated == string(current) {
		return
	}
	// #nosec G306 G703 -- root-owned system integration file (nginx/php-fpm/named/systemd config, script, or web content) that its daemon must read/execute; no secret stored here (secrets use 0600/0640).
	if err := os.WriteFile(configPath, []byte(updated), 0644); err != nil {
		log.Printf("phpMyAdmin repair: could not update database host: %v", err)
	}
}
