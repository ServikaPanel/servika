package provisioner

import (
	"os"
	"path/filepath"
	"testing"
)

// writeDropIn writes an absent file, reports the write, and then leaves the file
// alone on a second call because the key is already present. The idempotency is
// what keeps EnsureOOMGuard from reloading systemd on every startup.
func TestWriteDropInIsIdempotentOnTheKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "drop-in.conf")
	content := "[Service]\nMemoryMax=384M\nTasksMax=128\n"

	if !writeDropIn(path, content, "MemoryMax=384M") {
		t.Fatal("the first write should report a change")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != content {
		t.Fatalf("content = %q, want %q", got, content)
	}

	if writeDropIn(path, "REWRITTEN", "MemoryMax=384M") {
		t.Error("a second write with the key already present should report no change")
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back after second call: %v", err)
	}
	if string(got) != content {
		t.Errorf("the file was rewritten to %q; it must be left alone when the key is present", got)
	}
}

// A file that exists but does NOT carry the expected key is rewritten, because
// an older or partial drop-in must be brought up to the current content.
func TestWriteDropInRewritesWhenTheKeyIsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drop-in.conf")
	if err := os.WriteFile(path, []byte("[Service]\nOLD=1\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !writeDropIn(path, "[Service]\nOOMScoreAdjust=-700\n", "OOMScoreAdjust=-700") {
		t.Fatal("a file missing the key should be rewritten")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "[Service]\nOOMScoreAdjust=-700\n" {
		t.Errorf("content = %q, want the new drop-in", got)
	}
}
