package mail

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// masterPaths is where one test's master passdb files live.
type masterPaths struct {
	dir, passwd, conf string
	chowned           []string
}

func masterEnvironment(t *testing.T) *masterPaths {
	t.Helper()
	dir := t.TempDir()
	paths := &masterPaths{dir: dir, passwd: filepath.Join(dir, "servika-master-users"), conf: filepath.Join(dir, "25-servika-master.conf")}
	setForTest(t, &masterPasswdTarget, paths.passwd)
	setForTest(t, &masterConfTarget, paths.conf)
	setForTest(t, &chownFile, func(name string, uid, gid int) error {
		paths.chowned = append(paths.chowned, fmt.Sprintf("%s %d:%d", name, uid, gid))
		return nil
	})
	withLookPath(t, "doveconf")
	return paths
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// A first install writes the credential root-owned and private, the drop-in
// readable, and asks Dovecot to accept and reload it.
func TestWriteMasterUserInstallsThePassdb(t *testing.T) {
	paths := masterEnvironment(t)
	commands := withCommands(t)

	if err := writeMasterUser(context.Background(), "$6$hash"); err != nil {
		t.Fatalf("writeMasterUser: %v", err)
	}
	if got := readFile(t, paths.passwd); got != "servika-webmail:$6$hash\n" {
		t.Fatalf("password file = %q", got)
	}
	if readFile(t, paths.conf) != masterConf {
		t.Fatal("the drop-in is not the managed content")
	}
	if info, err := os.Stat(paths.passwd); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("password file mode = %v (%v)", info.Mode(), err)
	}
	if !slices.Equal(paths.chowned, []string{paths.passwd + ".new 0:0"}) {
		t.Fatalf("chowned %q", paths.chowned)
	}
	want := [][]string{{"doveconf", "-n"}, {"systemctl", "reload", "dovecot"}}
	if !slices.EqualFunc(commands.argvs(), want, slices.Equal) {
		t.Fatalf("commands = %q, want %q", commands.argvs(), want)
	}
}

// An installed drop-in is not validated or reloaded again, and without Dovecot
// nothing is written at all.
func TestWriteMasterUserSkipsWhatIsNotNeeded(t *testing.T) {
	t.Run("an installed drop-in", func(t *testing.T) {
		paths := masterEnvironment(t)
		commands := withCommands(t)
		writeTestFile(t, paths.conf, masterConf)
		if err := writeMasterUser(context.Background(), "$6$hash"); err != nil || len(commands.argvs()) != 0 {
			t.Fatalf("err = %v, commands = %q", err, commands.argvs())
		}
	})
	t.Run("no Dovecot", func(t *testing.T) {
		paths := masterEnvironment(t)
		withLookPath(t)
		commands := withCommands(t)
		if err := writeMasterUser(context.Background(), "$6$hash"); err != nil || len(commands.argvs()) != 0 {
			t.Fatalf("err = %v, commands = %q", err, commands.argvs())
		}
		if _, err := os.Stat(paths.passwd); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("a password file was written without Dovecot: %v", err)
		}
	})
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// Every failure names its step, and a drop-in Dovecot refuses is rolled back to
// what was there, or removed when nothing was.
func TestWriteMasterUserFailures(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*testing.T, *masterPaths)
		fail  [][]string
		text  string
		check func(*testing.T, *masterPaths)
	}{
		{"the password file cannot be written", pointPasswdIntoMissingDir, nil, "write the master password file", noMasterCheck},
		{"its ownership cannot be set", failChown, nil, "set the master password file ownership", noTempFileLeft},
		{"it cannot be installed", putDirAtPasswd, nil, "install the master password file", noTempFileLeft},
		{"the drop-in cannot be written", pointConfIntoMissingDir, nil, "write the master passdb drop-in", noMasterCheck},
		{"doveconf refuses a replacement", presetConf("old\n"), [][]string{{"doveconf"}}, "doveconf rejected the master passdb, it was rolled back: refused", confHolds("old\n")},
		{"doveconf refuses a first install", noMasterSetup, [][]string{{"doveconf"}}, "doveconf rejected the master passdb, it was rolled back: refused", confRemoved},
		{"dovecot does not reload", noMasterSetup, [][]string{{"systemctl"}}, "reload dovecot: refused", confHolds(masterConf)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			paths := masterEnvironment(t)
			withCommands(t, c.fail...)
			c.setup(t, paths)
			err := writeMasterUser(context.Background(), "$6$hash")
			if err == nil || !strings.Contains(err.Error(), c.text) {
				t.Fatalf("err = %v, want %q", err, c.text)
			}
			c.check(t, paths)
		})
	}
}

func noMasterSetup(*testing.T, *masterPaths) {}
func noMasterCheck(*testing.T, *masterPaths) {}

func pointPasswdIntoMissingDir(t *testing.T, paths *masterPaths) {
	setForTest(t, &masterPasswdTarget, filepath.Join(paths.dir, "missing", "users"))
}

func pointConfIntoMissingDir(t *testing.T, paths *masterPaths) {
	setForTest(t, &masterConfTarget, filepath.Join(paths.dir, "missing", "conf"))
}

func failChown(t *testing.T, _ *masterPaths) {
	setForTest(t, &chownFile, func(string, int, int) error { return errScripted })
}

func putDirAtPasswd(t *testing.T, paths *masterPaths) {
	t.Helper()
	if err := os.Mkdir(paths.passwd, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
}

func presetConf(content string) func(*testing.T, *masterPaths) {
	return func(t *testing.T, paths *masterPaths) { writeTestFile(t, paths.conf, content) }
}

func noTempFileLeft(t *testing.T, paths *masterPaths) {
	t.Helper()
	if _, err := os.Stat(masterPasswdTarget + ".new"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the temporary password file was left behind: %v", err)
	}
}

func confHolds(content string) func(*testing.T, *masterPaths) {
	return func(t *testing.T, paths *masterPaths) {
		t.Helper()
		if got := readFile(t, paths.conf); got != content {
			t.Fatalf("drop-in = %q, want %q", got, content)
		}
	}
}

func confRemoved(t *testing.T, paths *masterPaths) {
	t.Helper()
	if _, err := os.Stat(paths.conf); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the refused drop-in was left in place: %v", err)
	}
}
