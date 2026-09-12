package serverip

// Seams: unexported package variables whose defaults are exactly what this
// package does on a real host. A characterization test replaces one so a
// handler can be exercised without "ip addr", without /proc/net/tcp and without
// writing a systemd unit into /etc.
//
// They are NOT operator configuration: there is no environment variable, no
// paths.go entry and no README row, and only the call sites the tests reach are
// routed through them.
var (
	readHostAddresses  = HostAddresses
	readBoundAddresses = BoundAddresses
	addToHost          = AddToHost
	removeFromHost     = RemoveFromHost
	writePersistence   = WritePersistence

	// The two files the persistence unit is written to, and the command that
	// installs it.
	scriptPath = defaultScriptPath
	unitPath   = defaultUnitPath
	runCommand = run
)
