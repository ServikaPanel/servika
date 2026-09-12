package provisioner

import (
	"os"
	"path/filepath"
	"strings"

	"servika/internal/logx"
)

// nginxLogDir holds one access, error and cache log per domain, each named after
// the domain itself.
const nginxLogDir = "/var/log/nginx"

// HealNginxLogPerms closes the nginx access and error logs to tenants.
//
// Root cause: nginx leaves /var/log/nginx/<domain>.access.log and .error.log
// world readable (0644) inside a directory that is traversable by everyone
// (0755/0711). Because the file name is derived from the domain, a tenant with
// shell access could read a NEIGHBOUR's HTTP logs with
// `cat /var/log/nginx/<neighbour>.access.log` and harvest visitor IP addresses
// plus any session id, token or API key that appears in a query string.
//
// Fix: take the execute bit away from other on the directory (0700), which stops
// a tenant from reaching a file even when the exact name is known, and drop the
// world-readable bit on the files themselves (0640) as defence in depth. Neither
// nginx nor logrotate is affected: the nginx master opens and reopens these files
// as root before dropping privileges, and logrotate runs as root, so both bypass
// the DAC check. Every panel-side reader (internal/logs, internal/stats,
// internal/monitor) also runs as root.
//
// The repair is idempotent and runs at startup, so a package update, a logrotate
// `create` directive or a manual chmod that loosens the mode again is corrected
// on the next panel restart.
func HealNginxLogPerms() {
	info, err := os.Stat(nginxLogDir)
	if err != nil {
		return
	}
	// Directory: only root may traverse it. This also blocks access by name.
	if info.Mode().Perm() != 0o700 {
		// #nosec G302 -- 0700 is the minimum for a DIRECTORY; root still needs the execute bit to traverse it, and this tightens the mode rather than loosening it.
		if err := os.Chmod(nginxLogDir, 0o700); err != nil {
			logx.Errorf("could not harden the nginx log directory permissions: %v", err)
		} else {
			logx.Infof("nginx log directory set to 0700 (cross-tenant log reading closed)")
		}
	}
	entries, err := os.ReadDir(nginxLogDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.Contains(entry.Name(), ".log") {
			continue
		}
		fi, err := entry.Info()
		if err != nil || fi.Mode().Perm()&0o007 == 0 {
			continue // already closed to other
		}
		// #nosec G302 G703 -- fixed system log directory; the mode is tightened, not loosened, and the name comes from a ReadDir entry of that directory.
		_ = os.Chmod(filepath.Join(nginxLogDir, entry.Name()), 0o640)
	}
}
