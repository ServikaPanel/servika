package php

import (
	"os/exec"

	"servika/internal/provisioner"
)

// The values below are variables only so a characterization test can point them
// somewhere other than the host. Each default is the call this package made
// before the seam existed. None of them is operator configuration: there is no
// environment variable, no paths.go entry and no README row.
var (
	// tenantHomeRoot is the parent of every tenant home.
	tenantHomeRoot = "/home"

	// runCommand runs a host command and returns its combined output.
	runCommand = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}

	// fpmBinaryFor names the php-fpm binary a version's pool is tested with.
	fpmBinaryFor = provisioner.FPMBinaryFor

	// applyPool installs the pool file and reloads the shared master.
	applyPool = ApplyToFilesystem

	writeDebugShim         = provisioner.WriteDebugShim
	tenantFPMActive        = provisioner.TenantFPMActive
	enableTenantFPMGuarded = provisioner.EnableTenantFPMGuarded
	applyVhostForDomain    = provisioner.ApplyVhostForDomain
)
