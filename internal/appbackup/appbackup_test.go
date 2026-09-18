package appbackup

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run the real tar against a temporary tree. The archive members
// are stored relative to /, so an absolute temporary directory is put back
// exactly where it came from and the restore path can be exercised without a
// host to run it on.

// unit records what a Target's unit control was asked to do.
type unit struct {
	calls []string
	stop  error
	start error
}

func (u *unit) target(t *testing.T, root string) Target {
	t.Helper()
	return Target{
		Dir:  realTemp(t),
		Root: root,
		Stop: func(context.Context) error {
			u.calls = append(u.calls, "stop")
			return u.stop
		},
		Start: func(context.Context) error {
			u.calls = append(u.calls, "start")
			return u.start
		},
	}
}

// realTemp is a temporary directory with every symlink resolved.
//
// An archive member is stored relative to /, so the restore extracts into the
// real path. On macOS /var is a symlink to /private/var and tar refuses to
// extract through it; resolving the path here keeps the test measuring this
// package rather than the host's directory layout.
func realTemp(t *testing.T) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve the temporary directory: %v", err)
	}
	return real
}

// tree writes a directory holding one file and returns both paths.
func tree(t *testing.T, contents string) (string, string) {
	t.Helper()
	root := filepath.Join(realTemp(t), "app")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("create the tree: %v", err)
	}
	file := filepath.Join(root, "marker")
	if err := os.WriteFile(file, []byte(contents), 0o644); err != nil {
		t.Fatalf("write the marker: %v", err)
	}
	return root, file
}

// An archive carries the tree, records its own digest, and is readable by root
// alone because it holds the application's EnvironmentFile.
func TestAnArchiveCarriesTheTreeAndItsDigest(t *testing.T) {
	root, _ := tree(t, "first")
	u := &unit{}

	archive, err := Create(context.Background(), u.target(t, root))

	if err != nil {
		t.Fatalf("create: %v", err)
	}
	digest, err := Digest(archive.Path)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if digest != archive.SHA256 {
		t.Errorf("the recorded digest %s does not match the file %s", archive.SHA256, digest)
	}
	info, err := os.Stat(archive.Path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("the archive is mode %v, want 0600", info.Mode().Perm())
	}
	if archive.Size != info.Size() {
		t.Errorf("size = %d, want %d", archive.Size, info.Size())
	}
}

// The unit is stopped before tar reads the tree and started again afterwards.
// Reading a tree that is being written is exactly what the stop exists to stop.
func TestTheUnitIsStoppedForTheArchiveAndStartedAgain(t *testing.T) {
	root, _ := tree(t, "first")
	u := &unit{}

	if _, err := Create(context.Background(), u.target(t, root)); err != nil {
		t.Fatalf("create: %v", err)
	}

	if strings.Join(u.calls, ",") != "stop,start" {
		t.Errorf("the unit control ran %v, want stop then start", u.calls)
	}
}

// A failed archive still starts the application. A backup that left the service
// down would be worse than no backup.
func TestAFailedArchiveStillStartsTheApplication(t *testing.T) {
	u := &unit{}
	target := u.target(t, filepath.Join(t.TempDir(), "missing"))

	if _, err := Create(context.Background(), target); err == nil {
		t.Fatal("archiving a tree that does not exist reported success")
	}
	if strings.Join(u.calls, ",") != "stop,start" {
		t.Errorf("the unit control ran %v, want stop then start", u.calls)
	}
}

// No .part file survives a failed run, so a truncated file can never be read
// back as a backup.
func TestAFailedArchiveLeavesNoPartialFile(t *testing.T) {
	u := &unit{}
	target := u.target(t, filepath.Join(t.TempDir(), "missing"))

	if _, err := Create(context.Background(), target); err == nil {
		t.Fatal("archiving a tree that does not exist reported success")
	}

	left, err := os.ReadDir(target.Dir)
	if err != nil {
		t.Fatalf("read the backup directory: %v", err)
	}
	if len(left) != 0 {
		t.Errorf("the backup directory holds %d files, want none", len(left))
	}
}

// A target with no unit control is a programming error, and it is refused
// before anything on the host is touched.
func TestATargetWithNoUnitControlIsRefused(t *testing.T) {
	root, _ := tree(t, "first")

	_, err := Create(context.Background(), Target{Dir: t.TempDir(), Root: root})

	if err == nil {
		t.Fatal("a target with no unit control was accepted")
	}
}

// A relative path in Extra is refused. Every member is stored relative to /, so
// a path that is not absolute would archive something other than what it names.
func TestARelativeExtraPathIsRefused(t *testing.T) {
	root, _ := tree(t, "first")
	u := &unit{}
	target := u.target(t, root)
	target.Extra = []string{"etc/servika/env"}

	if _, err := Create(context.Background(), target); err == nil {
		t.Fatal("a relative extra path was accepted")
	}
	if len(u.calls) != 0 {
		t.Errorf("the unit was touched before the target was checked: %v", u.calls)
	}
}

// A corrupt archive costs nothing: it is caught before the unit is stopped and
// before the tree is deleted.
func TestACorruptArchiveIsRefusedBeforeAnythingStops(t *testing.T) {
	root, _ := tree(t, "first")
	u := &unit{}
	target := u.target(t, root)
	archive, err := Create(context.Background(), target)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	u.calls = nil
	archive.SHA256 = strings.Repeat("0", 64)

	err = Restore(context.Background(), target, archive)

	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
	if len(u.calls) != 0 {
		t.Errorf("a corrupt archive still touched the unit: %v", u.calls)
	}
}

// A restore puts the archived contents back over whatever is there now.
func TestARestoreReplacesTheTree(t *testing.T) {
	root, marker := tree(t, "first")
	u := &unit{}
	target := u.target(t, root)
	archive, err := Create(context.Background(), target)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := os.WriteFile(marker, []byte("second"), 0o644); err != nil {
		t.Fatalf("overwrite the marker: %v", err)
	}

	if err := Restore(context.Background(), target, archive); err != nil {
		t.Fatalf("restore: %v", err)
	}

	assertMarker(t, marker, "first")
}

// A restore of an application that binds a port waits for it to answer, and
// passes when something does.
func TestARestoreWaitsForTheApplicationToAnswer(t *testing.T) {
	root, marker := tree(t, "first")
	u := &unit{}
	target := u.target(t, root)
	target.Port = listeningPort(t)
	archive, err := Create(context.Background(), target)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := os.WriteFile(marker, []byte("second"), 0o644); err != nil {
		t.Fatalf("overwrite the marker: %v", err)
	}

	if err := Restore(context.Background(), target, archive); err != nil {
		t.Fatalf("restore: %v", err)
	}

	assertMarker(t, marker, "first")
}

// A restore the application will not start from is rolled back, and the copy of
// what it replaced is KEPT on disk so a manual recovery is possible.
func TestAFailedStartRollsTheTreeBackAndKeepsTheCopy(t *testing.T) {
	root, marker := tree(t, "first")
	u := &unit{}
	target := u.target(t, root)
	archive, err := Create(context.Background(), target)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := os.WriteFile(marker, []byte("second"), 0o644); err != nil {
		t.Fatalf("overwrite the marker: %v", err)
	}
	u.start = errors.New("the unit refused to start")

	if err := Restore(context.Background(), target, archive); err == nil {
		t.Fatal("a restore the application would not start from reported success")
	}

	assertMarker(t, marker, "second")
	if _, err := os.Stat(filepath.Join(target.Dir, "pre-restore.tar.gz")); err != nil {
		t.Errorf("the copy of the replaced tree was not kept: %v", err)
	}
}

// A successful restore deletes the copy it took, so the backup directory does
// not grow a stale pre-restore archive per run.
func TestASuccessfulRestoreDropsTheCopyItTook(t *testing.T) {
	root, _ := tree(t, "first")
	u := &unit{}
	target := u.target(t, root)
	archive, err := Create(context.Background(), target)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := Restore(context.Background(), target, archive); err != nil {
		t.Fatalf("restore: %v", err)
	}

	if _, err := os.Stat(filepath.Join(target.Dir, "pre-restore.tar.gz")); !os.IsNotExist(err) {
		t.Errorf("the copy was left behind: %v", err)
	}
}

// Remove accepts only a normalised file directly under the backup directory.
func TestRemoveRefusesAPathOutsideTheDirectory(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "elsewhere.tar.gz")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := Remove(dir, outside); err == nil {
		t.Error("a path outside the backup directory was accepted")
	}
	if err := Remove(dir, filepath.Join(dir, "..", "escape.tar.gz")); err == nil {
		t.Error("a path that needs normalising was accepted")
	}
	if err := Remove(dir, ""); err == nil {
		t.Error("an empty path was accepted")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("the refused file was deleted anyway: %v", err)
	}
}

// Remove deletes the archive, and a second call is not an error: the rotation
// and an operator's delete can race on the same row.
func TestRemoveDeletesAnArchiveAndToleratesAMissingOne(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "one.tar.gz")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := Remove(dir, path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := Remove(dir, path); err != nil {
		t.Errorf("removing a missing archive reported %v", err)
	}
}

func assertMarker(t *testing.T, path, want string) {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- a path this test wrote.
	if err != nil {
		t.Fatalf("read the marker: %v", err)
	}
	if string(body) != want {
		t.Errorf("the marker reads %q, want %q", body, want)
	}
}

// listeningPort returns a port something answers on for the whole test.
func listeningPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.Addr().(*net.TCPAddr).Port
}
