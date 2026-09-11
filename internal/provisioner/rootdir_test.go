package provisioner

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// ensureRootDirAt guarantees that a name under a directory the tenant owns is a
// real directory with the expected owner, replacing a file, a symlink or a
// directory someone else owns. The owner is root in production; these tests set
// it to the account running them, so every check runs without root, and pin
// which entries are replaced, which are kept, and when the function gives up.

// withShimOwnerOf makes the owner ensureRootDirAt expects the owner of what the
// test creates under dir. A new entry takes the directory's group on BSD and the
// process group on Linux, and dir's own group is that group on both.
func withShimOwnerOf(t *testing.T, dir string) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}
	setForTest(t, &shimOwnerUID, uint32(os.Getuid()))
	setForTest(t, &shimOwnerGID, st.Gid)
}

func openDirectory(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Open(path, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func assertRealDirectory(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o755 {
		t.Fatalf("%s is %v, %v; want a real 0755 directory", filepath.Base(path), info, err)
	}
}

func TestTheShimDirectoryIsCreatedOrReplacedUntilItIsReal(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, parent string)
	}{
		{"an absent directory is created", func(*testing.T, string) {}},
		{"a file in its place is replaced", func(t *testing.T, parent string) {
			plantFile(t, filepath.Join(parent, ".servika"))
		}},
		{"a symlink in its place is replaced without touching its target", func(t *testing.T, parent string) {
			target := filepath.Join(t.TempDir(), "victim")
			plantFile(t, filepath.Join(target, "keep"))
			if err := os.Symlink(target, filepath.Join(parent, ".servika")); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { assertPathsKept(t, filepath.Join(target, "keep")) })
		}},
		{"a directory with the right owner is kept and made 0755", func(t *testing.T, parent string) {
			plantFile(t, filepath.Join(parent, ".servika", "php_debug.log"))
			if err := os.Chmod(filepath.Join(parent, ".servika"), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { assertPathsKept(t, filepath.Join(parent, ".servika", "php_debug.log")) })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			withShimOwnerOf(t, parent)
			tc.prepare(t, parent)

			fd, ok := ensureRootDirAt(openDirectory(t, parent), ".servika")

			if !ok || fd < 0 {
				t.Fatalf("ensureRootDirAt() = %d, %v; want an open directory", fd, ok)
			}
			_ = unix.Close(fd)
			assertRealDirectory(t, filepath.Join(parent, ".servika"))
		})
	}
}

func TestTheShimDirectoryGivesUpWhenItCannotBeMadeSafe(t *testing.T) {
	cases := []struct {
		name    string
		entry   string
		prepare func(t *testing.T, parent string)
	}{
		{"every directory it creates has the wrong owner", ".servika", func(t *testing.T, _ string) {
			shimOwnerUID++
		}},
		{"the name cannot be inspected", "a-file/.servika", func(t *testing.T, parent string) {
			plantFile(t, filepath.Join(parent, "a-file"))
		}},
		{"a directory with the wrong owner cannot be removed", ".servika", func(t *testing.T, parent string) {
			skipAsRoot(t)
			locked := filepath.Join(parent, ".servika", "locked")
			plantFile(t, filepath.Join(locked, "pinned"))
			lockDirectory(t, locked)
			shimOwnerUID++
		}},
		{"the directory cannot be created", ".servika", func(t *testing.T, parent string) {
			skipAsRoot(t)
			lockDirectory(t, parent)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			withShimOwnerOf(t, parent)
			fd := openDirectory(t, parent)
			tc.prepare(t, parent)

			if got, ok := ensureRootDirAt(fd, tc.entry); ok || got != -1 {
				t.Fatalf("ensureRootDirAt() = %d, %v; want a refusal", got, ok)
			}
		})
	}
}

func skipAsRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
}

// lockDirectory makes dir read-only for the test and writable again before the
// temporary tree is removed.
func lockDirectory(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}
