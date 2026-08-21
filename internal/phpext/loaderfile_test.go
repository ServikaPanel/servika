package phpext

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The measured defect: the handler stat'ed the member path and then copied from
// it, and os.Stat FOLLOWS a symlink. Measured on AlmaLinux 10 with GNU tar 1.35,
// an archive whose member carries the expected name as a link to /etc/shadow was
// extracted verbatim, the stat succeeded, and the copy wrote 410 bytes of the
// shadow file into extension_dir at mode 0644, readable by every c_* tenant on
// the server.
//
// tar is what creates such a member, but the guard is in the open, so the test
// plants the link directly: it is the same file on disk either way, and this
// runs on every platform the repository builds for.
func TestASymlinkMemberIsRefused(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("root:$6$measured"), 0o600); err != nil {
		t.Fatal(err)
	}
	member := filepath.Join(dir, "ioncube_loader_lin_8.3.so")
	if err := os.Symlink(secret, member); err != nil {
		t.Fatal(err)
	}

	// The old shape: stat succeeds, which is exactly why it was not a boundary.
	if _, err := os.Stat(member); err != nil {
		t.Fatalf("os.Stat refused the link, so this test proves nothing: %v", err)
	}

	handle, err := openArchiveMember(member)
	if err == nil {
		_ = handle.Close()
		t.Fatal("a symlink member was opened; the copy would read its target")
	}
	if errors.Is(err, errMemberMissing) {
		t.Error("a symlink member was reported as an absent one; the operator would be told the PHP version is unsupported")
	}
}

// The guard is not vacuous in the other direction: an ordinary member is opened
// and its bytes reach the destination.
func TestAPlainMemberIsCopied(t *testing.T) {
	dir := t.TempDir()
	member := filepath.Join(dir, "ioncube_loader_lin_8.3.so")
	body := []byte("\x7fELF measured loader body")
	if err := os.WriteFile(member, body, 0o644); err != nil {
		t.Fatal(err)
	}

	handle, err := openArchiveMember(member)
	if err != nil {
		t.Fatalf("a plain member was refused: %v", err)
	}
	defer func() { _ = handle.Close() }()

	destination := filepath.Join(dir, "installed.so")
	if err := copyFromMember(handle, destination); err != nil {
		t.Fatalf("copy: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Errorf("copied %q, want %q", got, body)
	}
}

// An absent member and a refused one are different answers. The first means the
// archive carries no loader for this PHP version, which is an ordinary thing to
// tell an operator; the second means the download was not what it claimed to be.
func TestAnAbsentMemberIsItsOwnAnswer(t *testing.T) {
	_, err := openArchiveMember(filepath.Join(t.TempDir(), "ioncube_loader_lin_9.9.so"))
	if !errors.Is(err, errMemberMissing) {
		t.Fatalf("an absent member answered %v, want errMemberMissing", err)
	}
}

// A named pipe is why the open carries O_NONBLOCK: without it the open itself
// blocks waiting for a writer, before any check can run. With it the open
// returns and the regular-file test on the DESCRIPTOR refuses the member.
func TestANamedPipeMemberIsRefused(t *testing.T) {
	dir := t.TempDir()
	member := filepath.Join(dir, "ioncube_loader_lin_8.3.so")
	if err := syscall.Mkfifo(member, 0o644); err != nil {
		t.Skipf("this platform would not create a fifo: %v", err)
	}
	handle, err := openArchiveMember(member)
	if err == nil {
		_ = handle.Close()
		t.Fatal("a named pipe was accepted as a loader")
	}
	if errors.Is(err, errMemberMissing) {
		t.Error("a named pipe was reported as an absent member")
	}
}
