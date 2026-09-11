package dns

import "os/exec"

// What this package reaches on the host: the BIND zone directory, the generated
// include file and the commands that validate and reload named. Each is a
// variable whose default is what the package used before, so a test can write a
// zone into a temporary directory and answer the commands itself. None of them
// is operator configuration.
var (
	zoneDirectory        = ZoneDir
	namedConfIncludePath = NamedConfInclude
	zoneCommand          = exec.Command
)

// The package functions a handler reaches through a variable, so the handler's
// own decisions run without writing a zone, seeding a template or generating an
// RSA key.
var (
	writeZone    = WriteZone
	seedDefaults = SeedDefaults
	ensureDKIM   = EnsureDKIM
)
