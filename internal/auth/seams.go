package auth

import (
	"os/exec"
	"strings"
)

// Test seams for the two host operations this package performs.
//
// Both read or write /etc/shadow, which no test can supply, so the root login
// branch and the root password change were unreachable from a test. They are
// package-level variables with their production value as the default, and a
// test replaces them for the duration of one case. They are NOT operator
// configuration: no SERVIKA_* variable and no paths.go entry.

// rootPasswordOK verifies a password against root's /etc/shadow entry.
var rootPasswordOK = verifyRootPassword

// setRootPassword writes a new root password through chpasswd.
var setRootPassword = chpasswdRoot

// chpasswdRoot hands "root:<password>" to chpasswd on stdin, so the password
// never appears in argv (/proc/<pid>/cmdline is world-readable).
func chpasswdRoot(password string) error {
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader("root:" + password)
	_, err := cmd.CombinedOutput()
	return err
}
