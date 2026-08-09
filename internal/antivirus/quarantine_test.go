package antivirus

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"servika/internal/files"
)

// A finding's path is converted to a home-relative one, and anything that does
// not sit under the home is refused rather than repaired.
//
// This is the last point before a root-privileged file operation at which a path
// that escaped the home can be caught, so "outside" must be a refusal and not a
// best effort.
func TestOnlyAPathUnderTheHomeIsConverted(t *testing.T) {
	const home = "/home/c_site"

	for _, valid := range []struct{ absolute, want string }{
		{"/home/c_site/public_html/shell.php", "public_html/shell.php"},
		{"/home/c_site/public_html/a/b/c.php", "public_html/a/b/c.php"},
		{"/home/c_site/public_html/./x.php", "public_html/x.php"},
	} {
		got, ok := homeRelative(home, valid.absolute)
		if !ok || got != valid.want {
			t.Errorf("homeRelative(%q) = %q, %v; want %q, true", valid.absolute, got, ok, valid.want)
		}
	}

	for _, refused := range []string{
		"/etc/shadow",
		"/home/c_other/public_html/x.php",
		"/home/c_site",                         // the home itself is not a file
		"/home/c_site/public_html/../../etc/x", // climbs out once cleaned
		"/home/c_site_evil/public_html/x.php",  // prefix without the separator
		"",
	} {
		if got, ok := homeRelative(home, refused); ok {
			t.Errorf("homeRelative(%q) accepted it as %q", refused, got)
		}
	}
}

// The whole point of the change: a symlink planted at an INTERMEDIATE component
// must not let the panel reach a file outside the home.
//
// lstat and rename follow every component except the last, so the previous
// string-prefix check accepted such a path and moved the target as root. safeio
// resolves with RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS, so the open fails instead.
func TestASymlinkedComponentCannotReachOutsideTheHome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("safeio is Linux-only; the stub refuses everything")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(filepath.Join(home, "public_html"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "shadow")
	if err := os.WriteFile(secret, []byte("root:$6$hash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The tenant owns public_html and may create a link in it.
	if err := os.Symlink(outside, filepath.Join(home, "public_html", "pwn")); err != nil {
		t.Fatal(err)
	}

	// The path a finding would have to carry to exploit this.
	rel, ok := homeRelative(home, filepath.Join(home, "public_html", "pwn", "shadow"))
	if !ok {
		t.Fatal("the fixture path is not under the home; the test would prove nothing")
	}

	source, err := files.OpenBeneath(home, rel)
	if err == nil {
		_ = source.Close()
		t.Fatal("the open followed a symlinked component out of the home")
	}
	if _, err := os.Stat(secret); err != nil {
		t.Errorf("the file outside the home was disturbed: %v", err)
	}
}

// A regular file under the home is still readable through the same call, so the
// guard above is not simply refusing everything.
func TestAPlainFileUnderTheHomeIsStillReadable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("safeio is Linux-only; the stub refuses everything")
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "public_html"), 0o750); err != nil {
		t.Fatal(err)
	}
	want := "<?php eval($_GET['x']);"
	if err := os.WriteFile(filepath.Join(home, "public_html", "shell.php"), []byte(want), 0o644); err != nil {
		t.Fatal(err)
	}

	source, err := files.OpenBeneath(home, "public_html/shell.php")
	if err != nil {
		t.Fatalf("a plain file under the home was refused: %v", err)
	}
	defer func() { _ = source.Close() }()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("stat on the descriptor: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := source.Read(got); err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("read %q, want %q", got, want)
	}
}

// A fifo under the home opens successfully, so "is this a regular file" has to be
// asked of the DESCRIPTOR. Copying one would block the handler forever.
func TestANonRegularFileIsRefusedOnTheDescriptor(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("safeio is Linux-only; the stub refuses everything")
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "public_html"), 0o750); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(home, "public_html", "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo is unavailable here: %v", err)
	}

	source, err := files.OpenBeneath(home, "public_html/pipe")
	if err != nil {
		return // refused at the open, which is also correct
	}
	defer func() { _ = source.Close() }()
	info, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().IsRegular() {
		t.Error("a fifo was reported as a regular file")
	}
}

// The endpoint must never accept a path from the request again.
func TestTheEndpointTakesAFindingIDAndNotAPath(t *testing.T) {
	source, err := os.ReadFile("quarantine.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	if !strings.Contains(body, "func (h *Handlers) Quarantine(") {
		t.Fatal("Quarantine was renamed; this test has to follow it")
	}

	if !strings.Contains(body, `json:"finding_id"`) {
		t.Error("the request body no longer names finding_id")
	}
	if strings.Contains(body, `json:"file"`) {
		t.Error("the endpoint accepts a path from the request again")
	}
	// Anchored to the whole SELECT, not to a fragment: the UPDATE that marks a
	// finding quarantined carries the same words, so a fragment match stayed
	// green with the read's ownership narrowing removed.
	if !strings.Contains(body,
		"SELECT file, signature, engine, quarantined FROM av_findings WHERE id=? AND domain_id=?") {
		t.Error("the finding lookup is no longer narrowed by domain")
	}
	// Reads and removals inside a tenant tree go through the openat2 jail. The
	// store is outside every home and root-owned, so os.* there is correct; what
	// must never come back is a raw operation on a path under the home.
	for _, raw := range []string{"os.Rename(", "os.Lstat("} {
		if strings.Contains(body, raw) {
			t.Errorf("a tenant path reaches %s instead of going through safeio", raw)
		}
	}
	if !strings.Contains(body, "files.OpenBeneath(home, rel)") ||
		!strings.Contains(body, "files.RemoveAllBeneath(home, rel)") ||
		!strings.Contains(body, "files.StreamIntoBeneath(home, rel,") {
		t.Error("the tenant-side read, removal or restore no longer goes through safeio")
	}
}
