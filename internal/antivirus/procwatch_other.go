//go:build !linux

package antivirus

import "errors"

// runProcWatcher is Linux-only: the netlink proc connector is a Linux facility.
// The stub lets the package build on macOS for the pure-core tests, and refuses
// at run time on any non-Linux host.
func runProcWatcher() error {
	return errors.New("the process watcher requires Linux (netlink proc connector)")
}
