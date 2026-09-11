package files

// Seams: unexported package variables whose defaults are exactly the calls this
// package makes on a real host. A characterization test replaces one so a
// handler can be exercised against a temporary home, without the tenant's uid,
// the external file tools or the host's disk.
//
// They are NOT operator configuration: there is no environment variable, no
// paths.go entry and no README row, and only the call sites the tests reach are
// routed through them.
var (
	// homeRoot is where tenant homes live, so a test can point one at a
	// temporary directory.
	homeRoot = "/home"
)

var (
	fileCommand     = newFileCommand
	tenantCommand   = tenantFileCommand
	startExtractJob = runExtractJob
	reserveSpace    = reserveUploadSpace
	releaseSpace    = releaseUploadSpace
	quotaAvailable  = uploadQuotaAvailable
)
