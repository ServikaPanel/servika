package siteimport

import (
	"os/exec"

	"servika/internal/archivex"
	"servika/internal/sqlimport"
)

// Seams: unexported package variables whose defaults are exactly what this
// package does on a real host. A characterization test replaces one so an
// import can be exercised without /home, without an extractor that drops to a
// tenant account, and without MariaDB.
//
// They are NOT operator configuration: there is no environment variable, no
// paths.go entry and no README row, and only the call sites the tests reach are
// routed through them.
var (
	// tenantHomeRoot is where a tenant home lives. Every path this package
	// resolves is beneath it.
	tenantHomeRoot = "/home"

	// runCommand hands the extracted tree to the tenant. lookPath decides
	// whether the host carries setfacl at all.
	runCommand = func(name string, args ...string) error {
		// #nosec G204 G702 -- fixed binary with separate args (no shell); systemUser matched managedSystemUser and the path is home-relative and openat2-resolved.
		return exec.Command(name, args...).Run()
	}
	lookPath = exec.LookPath

	// extractArchive runs the extractor as the tenant, which needs a real
	// account and a real unzip or tar on the host.
	extractArchive = archivex.ExtractStrip

	// truncateDatabase and importDump apply a dump as an account granted on the
	// one target schema.
	truncateDatabase = sqlimport.Truncate
	importDump       = sqlimport.Import
)
