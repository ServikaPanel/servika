package system

import (
	"regexp"
	"strings"
	"testing"
)

// secretFiles are the host files that hold a shared secret and are written by a
// shell redirect. Every c_* tenant has a shell on this host, so the window
// between the redirect and a later chmod is a window in which the secret is
// readable by all of them.
//
// Root's umask on AlmaLinux is 022 (selected in /etc/profile for uid < 200), so
// a bare redirect creates the file 0644 and keeps the full contents there for
// the lifetime of the writing process. A chmod afterwards closes the file, not
// the window.
var secretFiles = []string{
	"/etc/servika/pma-internal.token",
	"/opt/phpmyadmin/config.inc.php",
}

// opsSecretWrites are the same defect in the setup scripts, listed as the script
// and the path it redirects into. The Postfix maps are written in a loop over a
// variable name, so the target there is the loop's expression rather than a
// literal path.
var opsSecretWrites = []struct{ script, target, holds string }{
	{"../../assets/ops/servika-mail-setup", `"/etc/postfix/${f}"`,
		"the mailro password, which has SELECT on panel.mailboxes"},
	{"../../assets/ops/servika-mail-setup", "/etc/dovecot/dovecot-sql.conf.ext",
		"the mailro password"},
	{"../../assets/ops/servika-mail-setup", "/opt/roundcube/config/config.inc.php",
		"the Roundcube database password and des_key"},
	{"../../assets/ops/servika-redis-setup.sh", `"$ACLF"`,
		"the Valkey default account password, which carries ~* &* +@all"},
}

// The setup scripts relied on a trailing chmod for confidentiality and never
// considered the window between open(O_CREAT) and it. An operator re-runs
// servika-mail-setup to repair mail, so the window opens again on a host that
// already has tenants on it.
func TestTheOpsScriptsCreateEveryCredentialFileUnderAUmask(t *testing.T) {
	for _, write := range opsSecretWrites {
		lines := strings.Split(readScript(t, write.script), "\n")
		at := redirectLines(lines, write.target)
		if len(at) == 0 {
			t.Errorf("%s no longer writes %s; this list is out of date", write.script, write.target)
			continue
		}
		for _, line := range at {
			if !umaskGuards(lines, line) {
				t.Errorf("%s creates %s by a bare redirect on line %d, so %s is world-readable "+
					"until the later chmod runs", write.script, write.target, line+1, write.holds)
			}
		}
	}
}

// guardWindow is how many lines before the redirect may carry the umask. The
// config.inc.php write opens its subshell on one line and redirects on the
// next, so the guard is not always on the same line as the `>`.
const guardWindow = 3

// redirectLines returns the 1-based line numbers of every shell redirect into
// path.
func redirectLines(lines []string, path string) []int {
	// The terminator is any character a path cannot continue with, so
	// /etc/postfix/x does not match /etc/postfix/xy. It is not \b: several of
	// these targets end in a quote or a brace, which \b does not follow.
	pattern := regexp.MustCompile(`>\s*` + regexp.QuoteMeta(path) + `(?:[^A-Za-z0-9._/-]|$)`)
	var at []int
	for i, line := range lines {
		if pattern.MatchString(line) {
			at = append(at, i)
		}
	}
	return at
}

// umaskGuards reports whether a umask is in force for the redirect on line at.
func umaskGuards(lines []string, at int) bool {
	from := max(at-guardWindow, 0)
	return strings.Contains(strings.Join(lines[from:at+1], "\n"), "umask")
}

// The installer already wrote config.inc.php under `( umask 027; ... )` with a
// comment naming this exact defect. The token beside it was not converted, and
// that token is one of the two factors guarding the exchange of a signon token
// for a tenant's live MariaDB user and password.
func TestTheInstallerCreatesEverySharedSecretUnderAUmask(t *testing.T) {
	lines := strings.Split(readScript(t, "../../servika-install.sh"), "\n")
	for _, path := range secretFiles {
		at := redirectLines(lines, path)
		if len(at) == 0 {
			t.Errorf("the installer no longer writes %s; this list is out of date", path)
			continue
		}
		for _, line := range at {
			if !umaskGuards(lines, line) {
				t.Errorf("%s is created by a bare redirect on line %d, so it exists "+
					"world-readable until the later chmod runs: %s",
					path, line+1, strings.TrimSpace(lines[line]))
			}
		}
	}
}

// The umask does not replace the chmod. A umask cannot fix a file that already
// exists with the wrong mode, which is the case on every re-run of the
// installer, so both have to stay.
func TestTheInstallerStillRestrictsTheModeAfterwards(t *testing.T) {
	body := readScript(t, "../../servika-install.sh")
	for _, path := range secretFiles {
		if !strings.Contains(body, "chmod 0640 "+path) {
			t.Errorf("%s is left at whatever mode it already had on a re-run", path)
		}
	}
}
