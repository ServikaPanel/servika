package system

import (
	"strings"
	"testing"
)

// /proc/<pid>/cmdline is mode 444 while /proc/<pid>/environ is 400, so a
// credential passed as a flag is readable by every local account for as long as
// the process runs. servika-install.sh is explicitly re-runnable on a live
// server, where every c_* tenant has a shell, cron and PHP while this step
// executes.
//
// The DSN is the sharper of the two: it carries the panel MariaDB password,
// which holds GRANT ALL on panel.* — every user row and password hash, every
// stored credential ciphertext, and the write access with which a tenant makes
// itself an administrator of a panel that runs as root.
func TestTheInstallerKeepsTheSeedCredentialsOutOfArgv(t *testing.T) {
	body := readScript(t, "../../servika-install.sh")

	for _, flag := range []string{`-dsn "$DSN"`, `-password "$ADMIN_PASSWORD"`} {
		if strings.Contains(body, flag) {
			t.Errorf("the installer still passes %s on the command line", flag)
		}
	}
	if !strings.Contains(body, `SERVIKA_DB_DSN="$DSN" SERVIKA_SEED_PASSWORD="$ADMIN_PASSWORD"`) {
		t.Error("the installer does not hand the seed credentials through the environment")
	}
}

// The seed binary has to accept the DSN from the environment, or the installer's
// call above silently seeds nothing.
func TestTheSeedBinaryReadsTheDSNFromTheEnvironment(t *testing.T) {
	body := readScript(t, "../../scripts/seed_admin.go")

	if !strings.Contains(body, `os.Getenv("SERVIKA_DB_DSN")`) {
		t.Error("seed_admin.go has no SERVIKA_DB_DSN fallback")
	}
	if !strings.Contains(body, `os.Getenv("SERVIKA_SEED_PASSWORD")`) {
		t.Error("seed_admin.go lost its SERVIKA_SEED_PASSWORD fallback")
	}
}
