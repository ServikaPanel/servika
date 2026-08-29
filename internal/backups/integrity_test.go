package backups

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// fileSHA256 streams the file's real SHA-256, and refuses a non-regular file so a
// planted symlink or pipe where an archive belongs is not hashed as if it were
// the archive.
func TestFileSHA256(t *testing.T) {
	body := []byte("servika backup archive bytes")
	want := sha256.Sum256(body)
	p := filepath.Join(t.TempDir(), "a.tar.gz")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := fileSHA256(p)
	if err != nil {
		t.Fatalf("fileSHA256: %v", err)
	}
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("fileSHA256 = %s, want %s", got, hex.EncodeToString(want[:]))
	}
	if _, err := fileSHA256(filepath.Join(t.TempDir(), "missing.tar.gz")); err == nil {
		t.Error("a missing file was hashed without error")
	}
}

// classifyIntegrity turns the stored checksum, the current checksum and the read
// outcome into a verdict. A missing-but-off-site backup is 'remote', never
// 'corrupt', so a healthy delete-local backup does not raise a false alarm.
func TestClassifyIntegrity(t *testing.T) {
	cases := []struct {
		name       string
		stored     string
		current    string
		readErr    error
		offsite    bool
		wantVerify string
		wantAlert  string
	}{
		{"matches", "abc", "abc", nil, false, "ok", ""},
		{"bit-rot mismatch", "abc", "def", nil, false, "corrupt", "bitRot"},
		{"missing and not off-site", "abc", "", os.ErrNotExist, false, "corrupt", "corruptMissing"},
		{"missing but off-site by design", "abc", "", os.ErrNotExist, true, "remote", ""},
		{"unreadable (permission), off-site flag irrelevant", "abc", "", os.ErrPermission, true, "corrupt", "corruptMissing"},
	}
	for _, c := range cases {
		gotV, gotA := classifyIntegrity(c.stored, c.current, c.readErr, c.offsite)
		if gotV != c.wantVerify || gotA != c.wantAlert {
			t.Errorf("%s: classifyIntegrity = (%q,%q), want (%q,%q)", c.name, gotV, gotA, c.wantVerify, c.wantAlert)
		}
	}
}

// A non-regular file (a named pipe) where an archive belongs is refused rather
// than hashed, so a planted special file cannot masquerade as a valid backup.
func TestFileSHA256RefusesNonRegular(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	if _, err := fileSHA256(p); err == nil {
		t.Error("a named pipe was hashed as if it were a regular file")
	}
}
