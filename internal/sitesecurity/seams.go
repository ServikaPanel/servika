package sitesecurity

import (
	"servika/internal/files"
	"servika/internal/wordpress"
)

// Seams: unexported package variables whose defaults are exactly what this
// package reads on a real host. A characterization test replaces one so a scan
// can be exercised without wp-cli, without a tenant home and without openat2,
// which only the Linux build has.
//
// They are NOT operator configuration: there is no environment variable, no
// paths.go entry and no README row, and only the call sites the tests reach are
// routed through them.
var (
	// tenantHomeRoot is the directory that holds every tenant home.
	tenantHomeRoot = "/home"

	discoverInstalls = wordpress.Discover
	coreVersion      = wordpress.CoreVersion
	wpComponents     = wordpress.Components

	listNamesBeneath = files.ListNamesBeneath
	readFileBeneath  = files.ReadFileBeneath
)
