package dbmigrate

import (
	"fmt"
	"os"
	"syscall"

	"servika/internal/logx"
)

// A migration file is SQL the panel runs as the database superuser, so anyone
// who can write one owns the database. The files ship with the release and live
// under a root-owned directory; the checks here refuse to run them from anywhere
// else, so a writable path is a stop rather than a privilege handover.
//
// The rule is "nobody but the panel's own account may write here": the owner
// must be the running process, and the group and other write bits must be clear.
// It is not spelled as uid 0, so the same check holds when the binary is run
// under a developer account or from a test.

// trustedDir reports whether a migration directory is safe to read. It returns
// the reason when it is not, so the operator is told what to fix.
func trustedDir(dir string) (bool, string) {
	info, err := os.Lstat(dir)
	if err != nil {
		return false, fmt.Sprintf("it could not be read: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, "it is a symlink or not a directory"
	}
	return trustedMode(info)
}

// trustedFile reports whether one migration file is safe to apply. A symlink is
// refused even when its target would pass, because the link can be repointed
// after the check.
func trustedFile(entry os.DirEntry) (bool, string) {
	if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
		return false, "it is a symlink or not a regular file"
	}
	info, err := entry.Info()
	if err != nil {
		return false, fmt.Sprintf("it could not be read: %v", err)
	}
	return trustedMode(info)
}

// trustedMode applies the ownership and permission rule both checks share.
func trustedMode(info os.FileInfo) (bool, string) {
	if info.Mode().Perm()&0o022 != 0 {
		return false, fmt.Sprintf("it is group or world writable (%#o)", info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, "its owner could not be read"
	}
	if uint64(stat.Uid) != uint64(os.Geteuid()) {
		return false, fmt.Sprintf("it belongs to uid %d, not to the panel's own account", stat.Uid)
	}
	return true, ""
}

// refuseMigrationDir logs why the directory was refused. The panel keeps
// running: an installation whose migrations were never applied is a broken
// panel, but one that ran SQL from a path another account can write is a lost
// database.
func refuseMigrationDir(dir, reason string) {
	logx.Errorf("migrations are disabled: %s %s. Fix it with chown -R root:root %s && chmod 755 %s",
		dir, reason, dir, dir)
}
