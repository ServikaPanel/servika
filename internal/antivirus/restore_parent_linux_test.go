//go:build linux

package antivirus

// Restoring a file whose folder is gone.
//
// Containment happens at one moment and a restore at another, so by the time an
// operator decides a finding was a false positive the tenant may have deleted
// the directory the file sat in. `open(2)` never creates a parent, so the
// restore's own write refuses with ENOENT and the screen can only report the
// generic failure. The handler therefore creates the path first.
//
// The two tests below are the two directions that matter, and the second is the
// one that keeps the first safe: creating a path as root through a directory a
// TENANT writes to is exactly how a planted symlink turns into an arbitrary
// write outside the home. `files.MkdirAllBeneath` opens every component with
// `O_NOFOLLOW`, so it must refuse rather than follow.
//
// These are Linux-only for the reason every safeio test is: the macOS build
// compiles against the stub, which returns an error for everything.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"servika/internal/files"
)

// A directory the tenant deleted is recreated, so a legitimate restore is not
// refused for a reason that has nothing to do with the file.
func TestARestoreRecreatesTheFolderTheTenantDeleted(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "public_html"), 0o755); err != nil {
		t.Fatal(err)
	}
	rel := "public_html/wp-content/plugins/gone/loader.php"

	// Without the directory, the write alone refuses. This is what the handler
	// used to answer, and it is why the fix exists.
	if _, err := files.StreamIntoBeneath(home, rel, strings.NewReader("x"), ""); err == nil {
		t.Fatal("the write created a missing parent by itself, so this test proves nothing")
	}

	if err := files.MkdirAllBeneath(home, filepath.Dir(rel), ""); err != nil {
		t.Fatalf("the folder could not be recreated: %v", err)
	}
	if _, err := files.StreamIntoBeneath(home, rel, strings.NewReader("payload"), ""); err != nil {
		t.Fatalf("the restore still failed after the folder was recreated: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(home, rel))
	if err != nil {
		t.Fatalf("the restored file is not there: %v", err)
	}
	if string(body) != "payload" {
		t.Errorf("the restored file holds %q", body)
	}
}

// A symlink planted in the path is REFUSED, not followed. The panel runs as
// root and every component of this path belongs to the tenant, so following one
// would create the directory, and then the file, wherever the link points.
func TestRecreatingTheFolderRefusesASymlinkTheTenantPlanted(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "public_html"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The tenant replaces an intermediate component with a link out of the home.
	if err := os.Symlink(outside, filepath.Join(home, "public_html", "wp-content")); err != nil {
		t.Fatal(err)
	}

	rel := "public_html/wp-content/plugins/gone/loader.php"
	err := files.MkdirAllBeneath(home, filepath.Dir(rel), "")
	if err == nil {
		t.Fatal("a symlinked component was followed, so root would write outside the home")
	}
	// The refusal must not be reported as "already there", which the handler
	// answers with a different reason code.
	if errors.Is(err, os.ErrExist) {
		t.Errorf("a refused symlink was reported as an occupied target: %v", err)
	}

	// Nothing was created through the link.
	if _, statErr := os.Stat(filepath.Join(outside, "plugins")); statErr == nil {
		t.Error("a directory was created outside the tenant home")
	}
}
