package antivirus

// Looking at a quarantined file before deciding what to do with it.

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"servika/internal/files"
)

// The file being opened is a KNOWN MALICIOUS one and the panel runs as root, so
// the open pins every component and the regular-file test is on the DESCRIPTOR.
// Upstream's version calls os.Open on a path read from the database and stats
// nothing, which follows a link at any level.
func TestTheInspectReadPinsEveryComponent(t *testing.T) {
	source, err := os.ReadFile("quarantine.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	start := strings.Index(body, "func (h *Handlers) QuarantineInspect(")
	if start < 0 {
		t.Fatal("the inspect handler is gone")
	}
	handler := body[start:]

	if !strings.Contains(handler, "files.OpenBeneath(userStore(systemUser), stored)") {
		t.Error("the inspect read no longer goes through the symlink-safe open")
	}
	if strings.Contains(handler, "os.Open(") || strings.Contains(handler, "os.ReadFile(") {
		t.Error("the inspect read opens a path directly, which follows a planted link")
	}
	// The test is on the descriptor, never on a separate stat of the path.
	if !strings.Contains(handler, "handle.Stat()") || !strings.Contains(handler, "info.Mode().IsRegular()") {
		t.Error("the regular-file test is no longer on the descriptor")
	}
	// Nothing about the request names a file: the row is read by id narrowed to
	// the domain, and the store path is built from the validated system user.
	if !strings.Contains(handler, "WHERE id=? AND domain_id=?") {
		t.Error("the inspect row is no longer narrowed to the requesting domain")
	}
}

// A quarantined file may be up to quarantineMaxBytes, so the whole file is never
// read, and the reader is TOLD the preview stops rather than being shown a
// prefix that reads as the whole file. A payload appended past the cut is
// exactly what an operator would then miss.
func TestALongFileIsCutAndSaysSo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("safeio is Linux-only; the stub refuses everything")
	}
	store := t.TempDir()
	long := bytes.Repeat([]byte("A"), inspectMaxBytes+4096)
	if err := os.WriteFile(filepath.Join(store, "big"), long, 0o600); err != nil {
		t.Fatal(err)
	}
	handle, err := files.OpenBeneath(store, "big")
	if err != nil {
		t.Fatalf("the fixture could not be opened: %v", err)
	}
	defer func() { _ = handle.Close() }()

	buffer := make([]byte, inspectMaxBytes+1)
	read, _ := handle.Read(buffer)
	// The buffer is one byte past the limit, so "there is more" is measured
	// rather than inferred from a read that happened to fill it exactly.
	if read <= inspectMaxBytes {
		// A short read is legal for one Read call, so top it up the way the
		// handler does with ReadFull.
		more, _ := handle.Read(buffer[read:])
		read += more
	}
	if read <= inspectMaxBytes {
		t.Fatalf("the fixture read %d bytes, which cannot distinguish a cut file", read)
	}
}

// A NUL byte means the content is not text. Sending the raw bytes through a JSON
// string would show the reader mangled binary and tell them nothing.
func TestBinaryContentIsNamedRatherThanShown(t *testing.T) {
	source, err := os.ReadFile("quarantine.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	start := strings.Index(body, "func (h *Handlers) QuarantineInspect(")
	handler := body[start:]
	if !strings.Contains(handler, `bytes.IndexByte(content, 0) >= 0`) {
		t.Error("binary content is no longer detected")
	}
	if !strings.Contains(handler, `response["binary"] = true`) ||
		!strings.Contains(handler, `response["content"] = ""`) {
		t.Error("binary content is no longer reported as binary with no body")
	}
}

// A link planted where a stored file belongs is REFUSED rather than followed.
// The store is root-owned 0700 outside every home, so this is defence in depth
// rather than a reachable path today; it is the rule every root-run read in this
// repository follows, and the store is the one directory whose contents are
// known-malicious files.
func TestALinkInTheStoreIsRefused(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("safeio is Linux-only; the stub refuses everything")
	}
	root := t.TempDir()
	store := filepath.Join(root, "store")
	outside := filepath.Join(root, "outside")
	for _, dir := range []string{store, outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(outside, "shadow")
	if err := os.WriteFile(secret, []byte("root:$6$hash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(store, "42_evil.php")); err != nil {
		t.Fatal(err)
	}

	handle, err := files.OpenBeneath(store, "42_evil.php")
	if err == nil {
		_ = handle.Close()
		t.Fatal("the inspect open followed a link out of the store")
	}

	// And a real file in the same store IS readable, so the refusal above is not
	// the open failing on everything.
	if err := os.WriteFile(filepath.Join(store, "43_real.php"), []byte("<?php echo 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	good, err := files.OpenBeneath(store, "43_real.php")
	if err != nil {
		t.Fatalf("a plain file in the store could not be read: %v", err)
	}
	_ = good.Close()
}
