//go:build darwin

package antivirus

import "syscall"

// ctimeNanos reads the inode change time. Darwin spells the field differently
// from Linux; the panel only runs the sweep on Linux, and this exists so the
// package still builds and tests on a development machine.
func ctimeNanos(st *syscall.Stat_t) int64 {
	return st.Ctimespec.Sec*1_000_000_000 + st.Ctimespec.Nsec
}
