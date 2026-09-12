package phpext

import (
	"os/exec"

	"servika/internal/provisioner"
)

// The values below are variables only so a characterization test can point them
// somewhere other than the host. Each default is the call this package made
// before the seam existed. None of them is operator configuration: there is no
// environment variable, no paths.go entry and no README row.
var (
	// installedVersions lists the PHP runtimes found on the host.
	installedVersions = Versions

	// runCommand runs a host command and returns its combined output.
	runCommand = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}

	// reloadTenantMasters reloads the isolated per-tenant PHP-FPM masters.
	reloadTenantMasters = provisioner.ReloadAllTenantFPM
)
