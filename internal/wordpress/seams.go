package wordpress

import (
	"os/exec"

	"servika/internal/credentials"
)

// Seams: unexported package variables whose defaults are exactly what this
// package runs on a real host. A characterization test replaces one so a
// decision can be exercised without wp-cli, without runuser and without
// MariaDB.
//
// They are NOT operator configuration: there is no environment variable, no
// paths.go entry and no README row, and only the call sites the tests reach are
// routed through them.
var (
	// tenantHomeRoot is the directory that holds every tenant home.
	tenantHomeRoot = "/home"
	// wpInput runs wp-cli as the tenant with data on its standard input and
	// returns the combined output.
	wpInput = execWPInput
	// wpOutput runs wp-cli as the tenant and returns only its standard output.
	wpOutput = execWPStdout
	// wpCommand builds the host commands that follow an install (chown,
	// restorecon).
	wpCommand = exec.Command

	createMySQLDB = credentials.MySQLCreateDB
	dropMySQLDB   = credentials.MySQLDropDB

	// removeInstall deletes an installation directory through openat2, which
	// only the Linux build has.
	removeInstall = removeBeneathHome
)
