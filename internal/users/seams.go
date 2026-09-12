package users

import "servika/internal/domains"

// Seams: unexported package variables whose defaults are exactly what this
// package calls on a real host. A characterization test replaces one so a
// decision can be exercised without nginx, without systemd and without a
// tenant on disk.
//
// They are NOT operator configuration: there is no environment variable, no
// paths.go entry and no README row, and only the call sites the tests reach are
// routed through them.
var (
	// suspendResellerDomains carries an account status down to the hosting of
	// every domain the reseller's customers own.
	suspendResellerDomains = domains.SuspendResellerDomains
)
