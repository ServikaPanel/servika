package system

import "net"

// Seams: unexported package variables whose defaults are exactly what this
// package reads and runs on a real host. A characterization test replaces one
// so a reading can be exercised against a fixture instead of the kernel, the
// package manager or the live network interfaces.
//
// They are NOT operator configuration: there is no environment variable, no
// paths.go entry and no README row, and only the call sites the tests reach are
// routed through them.
var (
	procMounts = "/proc/mounts"
	procNetDev = "/proc/net/dev"
)

var (
	readDiskUsage = ReadDisk
	netInterfaces = net.Interfaces
	netAddrs      = func(iface net.Interface) ([]net.Addr, error) { return iface.Addrs() }
	cveShell      = cveRunShell
	kcShell       = kcRunShell
	kcInstalled   = kernelcareInstalled
	kcRunning     = kernelcareUpdateRunning
)
