package sshaccess

import (
	"os/exec"

	"servika/internal/credentials"
	"servika/internal/files"
)

// Test seams for the host work an SSH change does: the commands it runs
// (usermod, gpasswd, servika-jail, getent), the tenant home it writes under,
// the two symlink-safe primitives that touch authorized_keys, and the password
// synchronisation that follows the shell.
//
// The primitives are seams rather than the raw calls because they are openat2
// syscalls: they exist on Linux only, so a handler that reaches them cannot be
// exercised anywhere else. Their own behaviour is tested in internal/files.
//
// None of these is operator configuration: no SERVIKA_* variable, no paths.go
// entry and no README row. Each is a package-level variable whose default is
// the production value.

// runCommand builds this package's fixed commands.
var runCommand = exec.Command

// tenantHomeRoot is the directory the c_* homes live in.
var tenantHomeRoot = "/home"

// sshDirReady creates ~/.ssh and pins its mode.
var sshDirReady = prepareSSHDir

// writeAuthorizedKeys replaces the key file beneath the tenant home.
var writeAuthorizedKeys = files.WriteFileBeneath

// chmodAuthorizedKeys pins the key file's mode beneath the tenant home.
var chmodAuthorizedKeys = files.ChmodBeneath

// syncSSHPassword gives the account the password its FTP login already has.
var syncSSHPassword = credentials.SyncSSHPassword

// lockSSHPassword takes the password away when SSH is switched off.
var lockSSHPassword = credentials.LockSSHPassword
