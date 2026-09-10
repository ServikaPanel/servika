package wordpress

import (
	"errors"
	"os"
	"path/filepath"

	"servika/internal/files"
)

// maintenanceMessage is the default 503 body the plugin falls back to and the
// initial content of the flag file.
const maintenanceMessage = "This website is temporarily undergoing maintenance. Please try again later."

const maintenancePluginPHP = `<?php
/*
 * Plugin Name: Servika Maintenance Mode
 * Description: Persistent maintenance mode managed by Servika.
 */
if (php_sapi_name() === 'cli') { return; }
$servika_flag = __DIR__ . '/../.servika-maintenance';
if (!file_exists($servika_flag)) { return; }
$servika_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
$servika_path = parse_url($servika_uri, PHP_URL_PATH);
if (!is_string($servika_path)) { $servika_path = ''; }
$servika_is_admin = $servika_path === '/wp-admin' || strpos($servika_path, '/wp-admin/') === 0;
if ($servika_is_admin || $servika_path === '/wp-login.php' || $servika_path === '/wp-cron.php') { return; }
if (!headers_sent()) {
    header($_SERVER['SERVER_PROTOCOL'] . ' 503 Service Unavailable', true, 503);
    header('Retry-After: 3600');
    header('Content-Type: text/html; charset=utf-8');
}
$servika_message = @file_get_contents($servika_flag);
if (!$servika_message) { $servika_message = 'This website is temporarily undergoing maintenance. Please try again later.'; }
echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Maintenance Mode</title>';
echo '<style>body{font-family:system-ui,Segoe UI,sans-serif;background:#f8fafc;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}.card{max-width:520px;background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:48px;text-align:center;box-shadow:0 10px 25px rgba(0,0,0,.05)}h1{font-size:22px;color:#0f172a;margin:0 0 10px}p{color:#64748b;line-height:1.6;margin:0}</style></head>';
echo '<body><div class="card"><h1>Maintenance Mode</h1><p>' . htmlspecialchars($servika_message, ENT_QUOTES, 'UTF-8') . '</p></div></body></html>';
exit;
`

// maintenancePaths derives the three maintenance paths from dir. It is used with
// an absolute directory for the read-only state probe and with a home-relative
// one for every write, because filepath.Join preserves whichever form it is given.
func maintenancePaths(dir string) (pluginDir, pluginFile, flag string) {
	contentDir := filepath.Join(dir, "wp-content")
	pluginDir = filepath.Join(contentDir, "mu-plugins")
	pluginFile = filepath.Join(pluginDir, "servika-maintenance.php")
	flag = filepath.Join(contentDir, ".servika-maintenance")
	return
}

func maintenanceEnabled(dir string) bool {
	_, _, flag := maintenancePaths(dir)
	_, err := os.Stat(flag)
	return err == nil
}

// enableMaintenance installs the mu-plugin and the flag file that make the site
// answer 503.
//
// Every write goes through a files.*Beneath primitive rather than os.MkdirAll and
// os.WriteFile. dir is bounded to the document root by resolveDirectory, but that
// check is a string comparison and everything below the directory (wp-content, and
// the leaf names inside it) belongs to the tenant. A path-resolving write follows a
// symlink at any component, so a tenant who replaces wp-content with a link makes
// root create a directory and two files wherever they point. openat2 refuses the
// link instead, and the primitives chown what they create to the tenant, which is
// what the chown -R here used to do.
func enableMaintenance(systemUser, dir string) error {
	home, rel, err := homeRel(systemUser, dir)
	if err != nil {
		return err
	}
	pluginDir, pluginFile, flag := maintenancePaths(rel)
	if err := files.MkdirAllBeneath(home, pluginDir, systemUser); err != nil {
		return err
	}
	if err := files.WriteFileBeneath(home, pluginFile, []byte(maintenancePluginPHP), 0644, systemUser); err != nil {
		return err
	}
	if err := files.WriteFileBeneath(home, flag, []byte(maintenanceMessage), 0644, systemUser); err != nil {
		return err
	}
	// WriteFileBeneath already relabels each file it writes; the created directories are not.
	files.RestoreconBeneath(home, pluginDir)
	return nil
}

// disableMaintenance removes the flag file. It is pinned the same way as the
// write: os.Remove resolves by path, so a symlinked wp-content aimed the deletion
// at a root-owned file of the tenant's choosing.
func disableMaintenance(systemUser, dir string) error {
	home, rel, err := homeRel(systemUser, dir)
	if err != nil {
		return err
	}
	_, _, flag := maintenancePaths(rel)
	if err := files.RemoveAllBeneath(home, flag); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
