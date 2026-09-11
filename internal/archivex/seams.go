package archivex

import "os/exec"

// Seams: unexported package variables whose defaults are exactly what this
// package runs on a real host. A characterization test replaces one so the
// command an extraction builds can be read without running an extractor under
// runuser, and so the RAR tool choice does not depend on what happens to be
// installed on the machine running the test.
//
// They are NOT operator configuration: there is no environment variable, no
// paths.go entry and no README row, and only the call sites the tests reach are
// routed through them.
var (
	scanArchive    = scan
	extractCommand = tenantCommand
	lookPath       = exec.LookPath
	rarTool        = detectRARTool
)
