//go:build linux

package antivirus

import "syscall"

// ctimeNanos reads the inode change time.
//
// This is the field the cache key stands on. No syscall writes it: the kernel
// sets it on every metadata or content change, so a file edited in place and
// then handed back its old mtime still has a ctime that moved.
func ctimeNanos(st *syscall.Stat_t) int64 {
	return st.Ctim.Sec*1_000_000_000 + st.Ctim.Nsec
}
