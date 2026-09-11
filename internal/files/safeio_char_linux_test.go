//go:build linux

package files

// Characterization of the three tree helpers behind the file manager:
// mkdirAllBeneath, the recursive delete (removeAt) and the recursive copy
// (copyEntryAt). Every one of them walks a tenant-controlled tree as root, so
// what they refuse matters as much as what they do.

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMkdirAllBeneathCreatesEveryComponentAndRefusesALink(t *testing.T) {
	cases := []struct {
		name    string
		rel     string
		setup   func(t *testing.T, home string)
		wantErr bool
		exists  string
	}{
		{name: "a nested directory", rel: docrootRel + "/storage/logs",
			exists: docrootRel + "/storage/logs"},
		{name: "a directory that is already there", rel: docrootRel,
			setup: func(t *testing.T, home string) {
				if err := os.MkdirAll(filepath.Join(home, docrootRel), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			exists: docrootRel},
		{name: "the home itself", rel: "/"},
		{name: "a component that is a symlink", rel: "link/inside", wantErr: true,
			setup: func(t *testing.T, home string) {
				if err := os.Symlink(t.TempDir(), filepath.Join(home, "link")); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "a leaf that is a symlink to elsewhere", rel: "escape", wantErr: true,
			setup: func(t *testing.T, home string) {
				if err := os.Symlink("/etc", filepath.Join(home, "escape")); err != nil {
					t.Fatal(err)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if tc.setup != nil {
				tc.setup(t, home)
			}
			// The system user does not exist in the test environment, so the
			// chown step is skipped and the directories stay root's.
			err := mkdirAllBeneath(home, tc.rel, "c_test")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want an error: %v", err, tc.wantErr)
			}
			assertDirectory(t, home, tc.exists)
		})
	}
}

// assertDirectory checks that rel is a directory under home, when a case names
// one.
func assertDirectory(t *testing.T, home, rel string) {
	t.Helper()
	if rel == "" {
		return
	}
	info, err := os.Lstat(filepath.Join(home, rel))
	if err != nil {
		t.Fatalf("%s was not created: %v", rel, err)
	}
	if !info.IsDir() {
		t.Errorf("%s is %v, want a directory", rel, info.Mode())
	}
}

// The component walk answers for every shape a path can take before a single
// directory is created.
func TestMkdirAllBeneathWalksEveryComponentShape(t *testing.T) {
	t.Run("a home that is not there", func(t *testing.T) {
		if err := mkdirAllBeneath(filepath.Join(t.TempDir(), "missing"), "a", ""); err == nil {
			t.Error("a missing home was accepted")
		}
	})
	t.Run("a path with an empty component", func(t *testing.T) {
		home := t.TempDir()
		if err := mkdirAllBeneath(home, "a//b", ""); err != nil {
			t.Fatalf("err = %v", err)
		}
		assertDirectory(t, home, "a/b")
	})
	t.Run("a name the filesystem refuses", func(t *testing.T) {
		home := t.TempDir()
		if err := mkdirAllBeneath(home, strings.Repeat("n", 300), ""); err == nil {
			t.Error("a name past the length limit was accepted")
		}
	})
	t.Run("a directory an account owns", func(t *testing.T) {
		home := t.TempDir()
		// root is the one account every environment has, so the chown branch
		// runs here rather than being skipped for a missing tenant.
		if err := mkdirAllBeneath(home, "owned", "root"); err != nil {
			t.Fatalf("err = %v", err)
		}
		assertDirectory(t, home, "owned")
	})
}

// A copy for an account that exists chowns what it creates, so the tenant owns
// their own files rather than root.
func TestCopyTreeBeneathChownsWhatItCreates(t *testing.T) {
	home := t.TempDir()
	writeUnder(t, home, "src/index.html", "<h1>hello</h1>")

	if err := copyTreeBeneath(home, "src", "dst", "root"); err != nil {
		t.Fatalf("err = %v", err)
	}
	assertFileHolds(t, filepath.Join(home, "dst", "index.html"), "<h1>hello</h1>")
}

// The delete walks the tree itself rather than handing a path to os.RemoveAll,
// so a link inside it must be removed as a link and never followed.
func TestRemoveAllBeneathWalksTheTreeItself(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	writeUnder(t, outside, "keep.txt", "not the tenant's")
	writeUnder(t, home, docrootRel+"/index.html", "<h1>hello</h1>")
	writeUnder(t, home, docrootRel+"/nested/deep.txt", "deep")
	if err := os.Symlink(outside, filepath.Join(home, docrootRel, "link")); err != nil {
		t.Fatal(err)
	}

	if err := removeAllBeneath(home, docrootRel); err != nil {
		t.Fatalf("the tree could not be removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(home, docrootRel)); !os.IsNotExist(err) {
		t.Errorf("the tree survived: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "keep.txt")); err != nil {
		t.Errorf("the delete followed the link out of the home: %v", err)
	}
}

// A name that is not there is not an error: the delete is what a repeated
// request runs, and the second one must not fail.
func TestRemoveAllBeneathAcceptsAPathThatIsNotThere(t *testing.T) {
	home := t.TempDir()
	if err := removeAllBeneath(home, "never-existed"); err != nil {
		t.Errorf("err = %v, want none", err)
	}
}

// The copy recreates what it meets rather than reading through it: a link stays
// a link, and a socket is skipped instead of being opened.
func TestCopyTreeBeneathRecreatesEveryEntryKind(t *testing.T) {
	home := t.TempDir()
	writeUnder(t, home, "src/index.html", "<h1>hello</h1>")
	writeUnder(t, home, "src/nested/deep.txt", "deep")
	if err := os.Symlink("index.html", filepath.Join(home, "src", "link")); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(home, "src", "app.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	if err := copyTreeBeneath(home, "src", "dst", "c_test"); err != nil {
		t.Fatalf("the tree could not be copied: %v", err)
	}
	assertFileHolds(t, filepath.Join(home, "dst", "index.html"), "<h1>hello</h1>")
	assertFileHolds(t, filepath.Join(home, "dst", "nested", "deep.txt"), "deep")
	target, err := os.Readlink(filepath.Join(home, "dst", "link"))
	if err != nil || target != "index.html" {
		t.Errorf("link = %q, %v; want it recreated as a link to index.html", target, err)
	}
	if _, err := os.Lstat(filepath.Join(home, "dst", "app.sock")); !os.IsNotExist(err) {
		t.Errorf("the socket was copied: %v", err)
	}
}

func assertFileHolds(t *testing.T, path, want string) {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- a file this test just created.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(body) != want {
		t.Errorf("%s = %q, want %q", path, body, want)
	}
}

// A copy whose source is a symlink copies the LINK, never what it points at.
// Reading through it is what would hand a tenant the content of anything their
// link reaches, read as root.
func TestCopyTreeBeneathCopiesALinkedSourceAsALink(t *testing.T) {
	home := t.TempDir()
	writeUnder(t, home, "real/index.html", "<h1>hello</h1>")
	if err := os.Symlink("real", filepath.Join(home, "src")); err != nil {
		t.Fatal(err)
	}
	if err := copyTreeBeneath(home, "src", "dst", "c_test"); err != nil {
		t.Fatalf("err = %v", err)
	}
	target, err := os.Readlink(filepath.Join(home, "dst"))
	if err != nil || target != "real" {
		t.Fatalf("dst = %q, %v; want a link to real", target, err)
	}
	if _, err := os.Lstat(filepath.Join(home, "dst", "index.html")); err == nil {
		// Reading the link's own target through the copy would mean the tree
		// behind it had been walked as root.
		if info, statErr := os.Lstat(filepath.Join(home, "real", "index.html")); statErr != nil || info == nil {
			t.Error("the link's target was not left alone")
		}
	}
}
