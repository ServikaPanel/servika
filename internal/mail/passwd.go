package mail

import (
	"fmt"
	"os/exec"
	"strings"
)

const opensslBin = "/usr/bin/openssl"

var subprocessEnv = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}

// lookPath, execCommand and execCommandContext are how this package finds and
// starts a host tool. They are variables so a test can answer them without a
// mail stack on the machine running it.
var (
	lookPath           = exec.LookPath
	execCommand        = exec.Command
	execCommandContext = exec.CommandContext
)

// HashPassword returns a SHA512-CRYPT password hash compatible with Dovecot.
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", fmt.Errorf("password is empty")
	}
	cmd := execCommand(opensslBin, "passwd", "-6", "-stdin")
	cmd.Env = subprocessEnv
	cmd.Stdin = strings.NewReader(plain)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("openssl passwd: %w", err)
	}
	hash := strings.TrimSpace(string(out))
	if !strings.HasPrefix(hash, "$6$") {
		return "", fmt.Errorf("unexpected hash format")
	}
	return hash, nil
}
