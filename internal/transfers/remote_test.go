package transfers

import (
	"strings"
	"testing"
)

// mysqlAdminAuth decides the source MySQL credentials per panel type. cPanel
// stays credential-less (root reads ~/.my.cnf); Plesk and DirectAdmin keep the
// admin account password-protected, so the dump and the discovery must carry
// credentials or the database step is refused with 1045. The password must be
// read on the REMOTE side via $(...), never embedded, so it stays out of argv.
func TestMySQLAdminAuth(t *testing.T) {
	cases := []struct {
		typ        string
		wantEnvSub string
		wantUser   string
	}{
		{"cpanel", "", ""},
		{"plesk", "/etc/psa/.psa.shadow", "-uadmin "},
		{"directadmin", "/usr/local/directadmin/conf/mysql.conf", `-u"$(sed`},
	}
	for _, c := range cases {
		s := &RemoteSource{Type: c.typ}
		env, user := s.mysqlAdminAuth()

		if c.typ == "cpanel" {
			if env != "" || user != "" {
				t.Fatalf("cpanel must add no credentials, got env=%q user=%q", env, user)
			}
			continue
		}
		if !strings.Contains(env, c.wantEnvSub) {
			t.Fatalf("%s env %q missing %q", c.typ, env, c.wantEnvSub)
		}
		if !strings.Contains(user, c.wantUser) {
			t.Fatalf("%s user %q missing %q", c.typ, user, c.wantUser)
		}
		// The password is read remotely with command substitution, so it never
		// enters an argument list here or the remote host's `ps`.
		if !strings.Contains(env, `MYSQL_PWD="$(`) {
			t.Fatalf("%s must read the password via $(...), got %q", c.typ, env)
		}
	}
}

// The DirectAdmin discovery script must authenticate its mysql call the same
// way, because a credential-less mysql there returns an empty database list in
// silence rather than an error.
func TestDirectAdminDiscoveryAuthenticatesMySQL(t *testing.T) {
	if !strings.Contains(discoverDirectAdmin, `MYSQL_PWD="$dbp" mysql -u"$dbu"`) {
		t.Fatalf("DirectAdmin discovery runs mysql without credentials")
	}
	if !strings.Contains(discoverDirectAdmin, "/usr/local/directadmin/conf/mysql.conf") {
		t.Fatalf("DirectAdmin discovery does not read the DA MySQL config")
	}
}
