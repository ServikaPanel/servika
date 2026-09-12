package apps

import (
	"database/sql"
	"os/exec"

	"servika/internal/appruntime"
	"servika/internal/provisioner"
)

// Test seams for the host this package acts on: tenant homes, systemd, the
// installed interpreters and the nginx re-render. Each is a package-level
// variable whose default is the production value, replaced by a test for the
// duration of one case. They are NOT operator configuration: no SERVIKA_*
// variable and no paths.go entry.

// tenantHomeRoot is where tenant home directories live.
var tenantHomeRoot = "/home"

// runSystemCommand runs a privileged tool without inheriting panel secrets.
var runSystemCommand = systemCommand

// resolveRuntimePath finds the interpreter for a runtime and version.
var resolveRuntimePath = appruntime.Resolve

// phpSocketFor and applyVhostForDomain rewrite the parent domain's vhost, which
// is what carries an application's proxy block.
var (
	phpSocketFor        = provisioner.PHPSocketFor
	applyVhostForDomain = func(db *sql.DB, domainID int64, socket, phpVersion string) error {
		return provisioner.ApplyVhostForDomain(db, domainID, socket, phpVersion)
	}
)

// systemCommand builds the command runSystemCommand runs by default.
func systemCommand(name string, arguments ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); every value is validated before exec.
	command := exec.Command(name, arguments...)
	command.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
	}
	return command
}
