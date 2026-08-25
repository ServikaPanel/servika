//go:build !linux && !darwin

package antivirus

import "syscall"

// ctimeNanos has no answer on a platform this panel does not run on. A zero
// makes fileKey report no key at all, so the cache is simply never used rather
// than used on a weaker key.
func ctimeNanos(_ *syscall.Stat_t) int64 { return 0 }
