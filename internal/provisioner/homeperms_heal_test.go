package provisioner

import (
	"database/sql/driver"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
)

// HealHomePerms isolates every existing tenant home: the per-user ACL model when
// setfacl works and nginx can read through it, the nginx group otherwise, and a
// one-time recursive ACL migration whose sentinel is written only when every
// tenant went through the ACL model. These tests pin the commands each model runs
// and when the sentinel is written.

const homeUsersQuery = "SELECT DISTINCT system_user FROM domains"

type homePermsFixture struct {
	home     string
	public   string
	sentinel string
	accounts map[string]*user.User
	aclTools bool
	fail     [][]string
	script   *sqlScript
	commands *commandRecorder
}

func withHomePerms(t *testing.T) *homePermsFixture {
	t.Helper()
	homes := withTenantHome(t)
	f := &homePermsFixture{
		home:     filepath.Join(homes, "c_example_com"),
		public:   filepath.Join(homes, "c_example_com", "public_html"),
		sentinel: filepath.Join(t.TempDir(), "lib", "servika", ".home_acl_v1_done"),
		accounts: map[string]*user.User{
			"c_example_com": {Username: "c_example_com", Uid: "1500", Gid: "1500"},
			"nginx":         {Username: "nginx", Uid: "990", Gid: "990"},
		},
		aclTools: true,
		script: &sqlScript{
			rows: map[string][][]driver.Value{homeUsersQuery: {{"c_example_com"}}},
			fail: map[string]error{},
		},
	}
	if err := os.MkdirAll(f.public, 0o755); err != nil {
		t.Fatal(err)
	}
	setForTest(t, &homeACLSentinel, f.sentinel)
	setForTest(t, &lookPath, func(file string) (string, error) {
		if f.aclTools {
			return "/usr/bin/" + file, nil
		}
		return "", exec.ErrNotFound
	})
	setForTest(t, &nginxAccount, "nginx")
	setForTest(t, &chown, func(string, int, int) error { return nil })
	withAccounts(t, f.accounts)
	withScript(t, f.script)
	f.commands = withCommandScript(t, func(argv []string) (string, int) {
		for _, prefix := range f.fail {
			if hasArgvPrefix(argv, prefix) {
				return "", 1
			}
		}
		return "", 0
	})
	return f
}

func (f *homePermsFixture) aclCommands() [][]string {
	return [][]string{
		{"setfacl", "-m", "u:nginx:--x", f.home},
		{"setfacl", "-m", "u:nginx:rX", f.public},
		{"setfacl", "-d", "-m", "u:nginx:rX", f.public},
		{"runuser", "-u", "nginx", "--", "test", "-r", f.public},
	}
}

func TestATenantHomeMovesToTheACLModelAndTheMigrationIsRecorded(t *testing.T) {
	f := withHomePerms(t)

	HealHomePerms()

	assertArgvs(t, f.commands.argvs(), append(f.aclCommands(), []string{"setfacl", "-R", "-P", "-m", "u:nginx:rX", f.public}))
	assertFileHolds(t, f.sentinel, "done\n")
	for path, mode := range map[string]os.FileMode{f.home: 0o710, f.public: 0o750} {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != mode {
			t.Errorf("%s has mode %v, %v; want %v", filepath.Base(path), info.Mode().Perm(), err, mode)
		}
	}
}

func TestAMigrationAlreadyRecordedIsNotRepeated(t *testing.T) {
	f := withHomePerms(t)
	plantFile(t, f.sentinel)

	HealHomePerms()

	assertArgvs(t, f.commands.argvs(), f.aclCommands())
}

// Anything short of every tenant in the working ACL model leaves the migration
// unrecorded, so the next startup tries the recursive pass again.
func TestAHomeOutsideTheACLModelLeavesTheMigrationUnrecorded(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *homePermsFixture)
		mode    os.FileMode
	}{
		{"setfacl is not installed", func(_ *testing.T, f *homePermsFixture) { f.aclTools = false }, 0o710},
		{"setfacl is missing and there is no nginx account", func(_ *testing.T, f *homePermsFixture) {
			f.aclTools = false
			delete(f.accounts, "nginx")
		}, 0o711},
		{"the home ACL fails", func(_ *testing.T, f *homePermsFixture) {
			f.fail = [][]string{{"setfacl", "-m", "u:nginx:--x"}}
		}, 0o710},
		{"the document root ACL fails", func(_ *testing.T, f *homePermsFixture) {
			f.fail = [][]string{{"setfacl", "-m", "u:nginx:rX"}}
		}, 0o710},
		{"the default ACL fails", func(_ *testing.T, f *homePermsFixture) {
			f.fail = [][]string{{"setfacl", "-d"}}
		}, 0o710},
		{"nginx still cannot read through the ACL", func(_ *testing.T, f *homePermsFixture) {
			f.fail = [][]string{{"runuser"}}
		}, 0o710},
		{"the recursive ACL fails", func(_ *testing.T, f *homePermsFixture) {
			f.fail = [][]string{{"setfacl", "-R"}}
		}, 0o710},
		{"the document root is not the managed one", func(t *testing.T, f *homePermsFixture) {
			removePath(t, f.public)
		}, 0o755},
		{"the tenant list is cut short", func(_ *testing.T, f *homePermsFixture) {
			f.script.endWith = map[string]error{homeUsersQuery: errors.New(lostConnectionTo)}
		}, 0o710},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withHomePerms(t)
			tc.prepare(t, f)

			HealHomePerms()

			assertPathsGone(t, f.sentinel)
			if info, err := os.Stat(f.home); err != nil || info.Mode().Perm() != tc.mode {
				t.Errorf("the home has mode %v, %v; want %v", info.Mode().Perm(), err, tc.mode)
			}
		})
	}
}

// A tenant the heal cannot touch is skipped without running anything. The
// migration of the tenants that were handled is still recorded.
func TestATenantHomeTheHealCannotTouchIsSkipped(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *homePermsFixture)
	}{
		{"the row cannot be read", func(_ *testing.T, f *homePermsFixture) {
			f.script.rows[homeUsersQuery] = [][]driver.Value{{nil}}
		}},
		{"the system user is not a tenant", func(_ *testing.T, f *homePermsFixture) {
			f.script.rows[homeUsersQuery] = [][]driver.Value{{"root"}}
		}},
		{"the home is missing", func(t *testing.T, f *homePermsFixture) { removePath(t, f.home) }},
		{"the home is a symlink", func(t *testing.T, f *homePermsFixture) {
			removePath(t, f.home)
			if err := os.Symlink(t.TempDir(), f.home); err != nil {
				t.Fatal(err)
			}
		}},
		{"the account does not exist", func(_ *testing.T, f *homePermsFixture) { delete(f.accounts, "c_example_com") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withHomePerms(t)
			tc.prepare(t, f)

			HealHomePerms()

			assertArgvs(t, f.commands.argvs(), [][]string{})
			assertFileHolds(t, f.sentinel, "done\n")
		})
	}
}

func TestTheHomeHealWithoutATenantListDoesNothing(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *homePermsFixture)
	}{
		{"there is no database", func(t *testing.T, _ *homePermsFixture) { withoutDatabase(t) }},
		{"the tenant list cannot be read", func(_ *testing.T, f *homePermsFixture) {
			f.script.fail[homeUsersQuery] = errors.New(lostConnectionTo)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withHomePerms(t)
			tc.prepare(t, f)

			HealHomePerms()

			assertArgvs(t, f.commands.argvs(), [][]string{})
			assertPathsGone(t, f.sentinel)
		})
	}
}

func TestAMigrationSentinelThatCannotBeWrittenIsOnlyLogged(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *homePermsFixture)
	}{
		// The sentinel has to read as missing for the migration to run at all, so
		// its directory is refused by permissions rather than by a file in the way,
		// which would report "not a directory" and skip the migration instead.
		{"its directory cannot be created", func(t *testing.T, _ *homePermsFixture) {
			skipAsRoot(t)
			locked := t.TempDir()
			lockDirectory(t, locked)
			homeACLSentinel = filepath.Join(locked, "lib", "servika", ".home_acl_v1_done")
		}},
		{"the sentinel itself cannot be written", func(t *testing.T, f *homePermsFixture) {
			skipAsRoot(t)
			if err := os.MkdirAll(filepath.Dir(f.sentinel), 0o755); err != nil {
				t.Fatal(err)
			}
			lockDirectory(t, filepath.Dir(f.sentinel))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := withHomePerms(t)
			tc.prepare(t, f)

			HealHomePerms()

			if _, err := os.Stat(homeACLSentinel); err == nil {
				t.Error("the sentinel was written")
			}
			if len(f.commands.argvs()) != 5 {
				t.Errorf("ran %q, want the full ACL pass", f.commands.argvs())
			}
		})
	}
}
