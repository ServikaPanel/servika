package dbremote

import (
	"context"
	"database/sql"

	"servika/internal/credentials"
)

// The handler's three host actions, as variables a test can substitute.
//
// Each one leaves the machine: applySwitch rewrites a file under /etc/my.cnf.d
// and restarts MariaDB, and the two grant calls run SQL as root through the
// mysql client. Neither can run on a laptop, and neither is what a handler test
// is about, which is the ORDER of the steps and the answer each failure gives.
//
// They are not operator configuration: nothing reads an environment variable
// here, and the defaults are the production functions.
var (
	applySwitch  = Apply
	grantRemote  = credentials.MySQLGrantRemote
	revokeRemote = credentials.MySQLRevokeRemote
)

// Kept as named types so a substitute cannot silently drift from the call.
var (
	_ func(context.Context, *sql.DB, bool) error   = applySwitch
	_ func(string, string, string, []string) error = grantRemote
	_ func(string, string) error                   = revokeRemote
)
