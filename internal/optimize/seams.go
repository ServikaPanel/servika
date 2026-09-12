package optimize

// Seams: unexported package variables whose defaults are exactly what this
// package does on a real host. A characterization test replaces one so an apply
// can be exercised without /etc, without systemctl and without a running nginx.
//
// They are NOT operator configuration: there is no environment variable, no
// paths.go entry and no README row, and only the call sites the tests reach are
// routed through them.
var (
	runCommand = run

	// targetAllowed is the guard every write goes through. Its default is the
	// specs table, so production still refuses any path this package does not
	// own; a test points it at its own temporary file.
	targetAllowed = knownTarget

	// procSysRoot is where a sysctl's current value is read from.
	procSysRoot = "/proc/sys"
)
