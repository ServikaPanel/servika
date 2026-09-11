package mail

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"servika/internal/config"
)

// Installing the Roundcube side of the panel's one-click webmail sign-in.
//
// Roundcube has no notion of a panel session, so the only supported way to log
// a mailbox in from outside is its plugin API: the documented `authenticate`
// hook supplies the credentials and may waive the form token, which is exactly
// what a sign-in that did not come from Roundcube's own form needs.
//
// The plugin source lives here as well as under assets/, kept identical by a
// test, for the same reason the phpMyAdmin signon endpoint does: an existing
// installation is repaired at panel startup, not by the updater, because the
// updater running through an update is the OLD copy of itself.

var (
	roundcubePluginDir = config.RoundcubePlugins
	// roundcubePluginList matches the plugin list assignment in the Roundcube
	// config. The list is a single-line array in the template shipped here.
	roundcubePluginList = regexp.MustCompile(`(?m)^(\$config\['plugins'\]\s*=\s*\[)([^\]]*)(\];)`)
)

const webmailPluginName = "servika_signon"

// errNoPluginList is returned when the Roundcube config carries no plugin list.
// Adding one would mean guessing what the operator had enabled, so the repair
// stops and says so instead.
var errNoPluginList = errors.New("the Roundcube config has no $config['plugins'] assignment")

// webmailPluginPHPTemplate is the plugin Roundcube loads.
//
// The token check, the loopback exchange and the shared-secret header mirror the
// phpMyAdmin signon endpoint. What differs is the last step: phpMyAdmin reads
// its credentials out of a PHP session, while Roundcube takes them from the
// hook return value.
const webmailPluginPHPTemplate = `<?php
/**
 * Signs a mailbox in to Roundcube with a one-time Servika token.
 *
 * The panel posts the token to /webmail/index.php. Nothing is read from the
 * query string, so the token cannot reach browser history or a proxy log.
 */
declare(strict_types=1);

class servika_signon extends rcube_plugin
{
    /** This plugin has no reason to load outside the login task. */
    public $task = 'login';

    public function init()
    {
        $this->add_hook('startup', [$this, 'startup']);
        $this->add_hook('authenticate', [$this, 'authenticate']);
    }

    /**
     * Force the login action when a signon token is present, so the panel does
     * not have to depend on Roundcube's own form fields.
     *
     * @param array $args
     * @return array
     */
    public function startup($args)
    {
        if ($this->token() !== '') {
            $args['action'] = 'login';
        }

        return $args;
    }

    /**
     * Supply the credentials for a token-carrying request.
     *
     * @param array $args
     * @return array
     */
    public function authenticate($args)
    {
        $token = $this->token();
        if ($token === '') {
            return $args;
        }

        $credentials = $this->redeem($token);
        if ($credentials === null) {
            $args['abort'] = true;
            $args['error'] = 'The webmail signon token could not be redeemed. Open webmail from Servika again.';

            return $args;
        }

        $args['user'] = $credentials['username'];
        $args['pass'] = $credentials['password'];
        // The panel opens webmail in a new tab, so there is no earlier Roundcube
        // page to have set a test cookie or issued a form token. The request is
        // instead vouched for by the single-use token redeemed above.
        $args['cookiecheck'] = false;
        $args['valid'] = true;

        return $args;
    }

    /**
     * Read the signon token out of the POST body, or an empty string.
     */
    private function token(): string
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            return '';
        }
        $token = isset($_POST['_servika_token']) ? (string) $_POST['_servika_token'] : '';

        return preg_match('/^[a-f0-9]{16,128}$/', $token) === 1 ? $token : '';
    }

    /**
     * Exchange the token for the master credential over the loopback.
     *
     * @return array{username: string, password: string}|null
     */
    private function redeem(string $token): ?array
    {
        $internalToken = trim((string) @file_get_contents('{{TOKEN_PATH}}'));
        if ($internalToken === '') {
            return null;
        }

        $payload = json_encode(['token' => $token]);
        if (!is_string($payload)) {
            return null;
        }

        $curl = curl_init('http://{{BACKEND}}/api/v1/internal/webmail-redeem');
        if ($curl === false) {
            return null;
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
            return null;
        }

        $data = json_decode($response, true);
        if (!is_array($data)
            || !is_string($data['username'] ?? null)
            || !is_string($data['password'] ?? null)
        ) {
            return null;
        }

        return ['username' => $data['username'], 'password' => $data['password']];
    }
}
`

// webmailPluginPHP is the plugin with the shared-secret path substituted.
// webmailPluginPHP renders the signon plugin for THIS host.
//
// The backend address is substituted rather than written into the template. It
// used to be the literal 127.0.0.1:8080, which the shipped port-move feature
// does not rewrite: that rewrite reaches the two panel vhosts, and this plugin
// goes direct to the backend rather than through nginx, so moving the port
// broke every "Open webmail" click with no sign of why.
func webmailPluginPHP() string {
	plugin := strings.ReplaceAll(webmailPluginPHPTemplate, "{{TOKEN_PATH}}", phpSingleQuoted(config.PMATokenPath()))
	return strings.ReplaceAll(plugin, "{{BACKEND}}", config.LoopbackBackend())
}

// phpSingleQuoted escapes a value for a PHP single-quoted string literal.
func phpSingleQuoted(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `'`, `\'`)
}

// HealWebmailPlugin installs the signon plugin and enables it in the Roundcube
// configuration. It does nothing when Roundcube is not installed.
func HealWebmailPlugin(ctx context.Context) {
	configPath := roundcubeConfigPath()
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	current, err := os.ReadFile(configPath)
	if err != nil {
		return // Roundcube is not installed on this host.
	}

	pluginChanged, err := writeWebmailPlugin()
	if err != nil {
		log.Printf("webmail signon plugin: %v", err)
		return
	}
	configChanged, err := enableWebmailPlugin(configPath, string(current))
	if err != nil {
		log.Printf("webmail signon plugin: %v", err)
		return
	}
	if !pluginChanged && !configChanged {
		return
	}

	// PHP opcache may still hold the previous plugin file or config; the reload
	// is best effort because a failure here only delays the change by a restart.
	reloadCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	if _, err := exec.CommandContext(reloadCtx, "systemctl", "reload", "php-fpm").CombinedOutput(); err != nil {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		_, _ = exec.CommandContext(reloadCtx, "systemctl", "restart", "php-fpm").CombinedOutput()
	}
	log.Printf("webmail signon plugin installed; panel-initiated webmail sessions are available")
}

// writeWebmailPlugin puts the plugin in place and reports whether it changed.
func writeWebmailPlugin() (bool, error) {
	dir := filepath.Join(roundcubePluginDir(), webmailPluginName)
	// #nosec G301 -- root-owned system directory whose daemon (nginx/php-fpm/named) must traverse it; contains no secret material.
	if err := os.MkdirAll(dir, 0755); err != nil {
		return false, err
	}
	path := filepath.Join(dir, webmailPluginName+".php")
	wanted := webmailPluginPHP()
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	if existing, err := os.ReadFile(path); err == nil && string(existing) == wanted {
		return false, nil
	}
	// #nosec G306 G703 -- root-owned system integration file that its daemon must read; the credential it names lives in a 0640 file elsewhere.
	if err := os.WriteFile(path, []byte(wanted), 0644); err != nil {
		return false, err
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	_, _ = exec.Command("restorecon", "-R", dir).CombinedOutput()
	return true, nil
}

// enableWebmailPlugin adds the plugin to the Roundcube plugin list.
//
// The list is rewritten rather than appended to, because a second
// `$config['plugins']` assignment would replace the first one and silently drop
// whatever plugins the operator had enabled.
func enableWebmailPlugin(path, content string) (bool, error) {
	if strings.Contains(content, "'"+webmailPluginName+"'") {
		return false, nil
	}
	match := roundcubePluginList.FindStringSubmatchIndex(content)
	if match == nil {
		return false, errNoPluginList
	}
	entries := strings.TrimSpace(content[match[4]:match[5]])
	if entries != "" && !strings.HasSuffix(entries, ",") {
		entries += ","
	}
	if entries != "" {
		entries += " "
	}
	updated := content[:match[2]] + content[match[2]:match[3]] +
		entries + "'" + webmailPluginName + "'" + content[match[6]:]

	// The mode is 0 because O_CREATE is deliberately absent: the caller read the
	// file, so it exists, and its own root:apache 0640 must be preserved.
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file-manager paths use safeio (openat2) instead.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return false, err
	}
	if _, err := file.WriteString(updated); err != nil {
		_ = file.Close()
		return false, err
	}
	if err := file.Close(); err != nil {
		return false, err
	}
	return true, nil
}
