package mail

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"servika/internal/config"
	"servika/internal/logx"
)

// roundcubeConfigPath is a function value so tests can point the heal at a
// temporary file.
var roundcubeConfigPath = config.RoundcubeConfig

// roundcubeSMTPPatch is appended when the setting is missing.
//
// The config file is only `$config[...] = ...;` assignments with no closing
// `?>` tag, so assignments added at the end legitimately override earlier ones.
const roundcubeSMTPPatch = `
// --- Servika repair: Roundcube 1.5+ option names and submission STARTTLS ---
// The old template wrote smtp_server/smtp_port, which Roundcube 1.7 IGNORES,
// leaving it on its own default of a plaintext connection to localhost:587.
// Postfix serves submission with smtpd_tls_security_level=encrypt, so it
// advertises AUTH only after STARTTLS; the client never saw AUTH and reported
// an authentication failure it had not attempted.
$config['imap_host'] = 'localhost:143';
$config['smtp_host'] = 'tls://localhost:587';
$config['smtp_user'] = '%u';
$config['smtp_pass'] = '%p';
// The certificate belongs to the server hostname while the connection is made
// to localhost, so the names cannot match. The traffic never leaves the machine,
// so name and chain checking are relaxed; the session stays encrypted, which is
// the precondition Postfix imposes before offering AUTH.
$config['smtp_conn_options'] = [
    'ssl' => [
        'verify_peer'       => false,
        'verify_peer_name'  => false,
        'allow_self_signed' => true,
    ],
];
`

// HealRoundcubeSMTP repairs the missing smtp_host setting that leaves webmail
// able to read mail but not send it. It is idempotent and leaves a config that
// already carries the setting untouched.
//
// It runs at panel startup rather than from servika-update because the updater
// replaces itself: the copy running through an update is the OLD script, so a
// repair added there would only take effect one update later. Startup is the
// first thing that runs with the new release in place, since the panel is
// restarted as part of every update.
//
// The old smtp_server lines are kept. Roundcube 1.7 ignores them already, and
// rewriting an operator's config file is a larger risk than leaving a dead
// assignment in it.
func HealRoundcubeSMTP(ctx context.Context) {
	path := roundcubeConfigPath()
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file reads go through safeio (openat2), not this call.
	content, err := os.ReadFile(path)
	if err != nil {
		return // Roundcube is not installed; nothing to repair.
	}
	if strings.Contains(string(content), "smtp_host") {
		return // already repaired, or written from the corrected template
	}

	// The mode is 0 because O_CREATE is deliberately absent: the file was read
	// above, so it exists, and creating it here would produce a config without
	// the substituted database password. Its own root:apache 0640 is preserved.
	// #nosec G304 -- path is a fixed system/config path, a server-internal temp/archive path, or built from a validated identifier; tenant file-manager paths use safeio (openat2) instead.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		logx.Errorf("roundcube smtp heal: could not open the config: %v", err)
		return
	}
	// Keep the appended block off the end of an unterminated last line.
	prefix := ""
	if n := len(content); n > 0 && content[n-1] != '\n' {
		prefix = "\n"
	}
	if _, err := file.WriteString(prefix + roundcubeSMTPPatch); err != nil {
		_ = file.Close()
		logx.Errorf("roundcube smtp heal: could not write the config: %v", err)
		return
	}
	if err := file.Close(); err != nil {
		logx.Errorf("roundcube smtp heal: could not close the config: %v", err)
		return
	}

	// PHP opcache may still hold the old config; the reload is best effort.
	reloadCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	if _, err := exec.CommandContext(reloadCtx, "systemctl", "reload", "php-fpm").CombinedOutput(); err != nil {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
		_, _ = exec.CommandContext(reloadCtx, "systemctl", "restart", "php-fpm").CombinedOutput()
	}
	logx.Infof("roundcube smtp heal applied; webmail outgoing mail authentication repaired")
}
