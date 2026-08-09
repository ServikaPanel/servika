package antivirus

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"servika/internal/files"
)

// withStore points the quarantine store at a temporary directory for one test.
func withStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SERVIKA_QUARANTINE_DIR", dir)
	return dir
}

// tenantHome builds a home with one file under public_html and returns both.
func tenantHome(t *testing.T, name, content string) (home, rel string) {
	t.Helper()
	home = t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "public_html"), 0o750); err != nil {
		t.Fatal(err)
	}
	rel = "public_html/" + name
	if err := os.WriteFile(filepath.Join(home, rel), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return home, rel
}

// The file leaves the tenant tree and lands in the store, which is outside every
// home so the account it came from cannot reach it.
func TestContainMovesTheFileOutOfTheTenantTree(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("safeio is Linux-only; the stub refuses everything")
	}
	store := withStore(t)
	home, rel := tenantHome(t, "shell.php", "<?php eval($_GET['x']);")

	size, err := contain(home, rel, "c_site", 42)
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len("<?php eval($_GET['x']);")) {
		t.Errorf("wrote %d bytes, want %d", size, len("<?php eval($_GET['x']);"))
	}
	if _, err := os.Stat(filepath.Join(home, rel)); !os.IsNotExist(err) {
		t.Error("the original is still in the tenant tree")
	}
	target := filepath.Join(store, "c_site", "42_shell.php")
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("the file is not in the store: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("stored mode is %o, want 600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Join(store, "c_site"))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("store directory mode is %o, want 700", dirInfo.Mode().Perm())
	}
}

// A file over the ceiling is refused and NOTHING is written to the store, which
// sits under /var and is shared with the panel's own state.
func TestAFileOverTheCeilingIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("safeio is Linux-only; the stub refuses everything")
	}
	store := withStore(t)
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "public_html"), 0o750); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(home, "public_html", "big.bin")
	// A sparse file: the size is what the ceiling reads, and no disk is spent.
	handle, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Truncate(quarantineMaxBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = handle.Close()

	if _, err := contain(home, "public_html/big.bin", "c_site", 7); err == nil {
		t.Fatal("a file over the ceiling was quarantined")
	}
	if _, err := os.Stat(filepath.Join(store, "c_site", "7_big.bin")); !os.IsNotExist(err) {
		t.Error("something was written to the store for a refused file")
	}
	if _, err := os.Stat(big); err != nil {
		t.Error("the refused file was removed from the tenant tree anyway")
	}
}

// A copy whose original survives is taken back. Reporting containment while the
// file still runs is worse than reporting a failure.
func TestACopyIsTakenBackWhenTheOriginalCannotBeRemoved(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("safeio is Linux-only; the stub refuses everything")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory permission this test relies on")
	}
	store := withStore(t)
	home, rel := tenantHome(t, "shell.php", "<?php eval($_GET['x']);")

	// A directory with no write permission makes the unlink fail while the read
	// still succeeds, which is exactly the half-done state the order guards.
	guarded := filepath.Join(home, "public_html")
	if err := os.Chmod(guarded, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(guarded, 0o750) })

	if _, err := contain(home, rel, "c_site", 9); err == nil {
		t.Fatal("containment was reported although the original could not be removed")
	}
	if _, err := os.Stat(filepath.Join(store, "c_site", "9_shell.php")); !os.IsNotExist(err) {
		t.Error("the copy was left in the store beside a live original")
	}
	if _, err := os.Stat(filepath.Join(home, rel)); err != nil {
		t.Error("the original went missing after a failed containment")
	}
}

// Restoring writes the file back into the tenant tree, and a path the tenant has
// since filled is refused rather than overwritten.
func TestRestoreRefusesToOverwriteWhatIsThereNow(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("safeio is Linux-only; the stub refuses everything")
	}
	home, rel := tenantHome(t, "shell.php", "original")
	source, err := os.Open(filepath.Join(home, rel))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()

	// The tenant's own file is already at the path a restore would take.
	if _, err := files.StreamIntoBeneath(home, rel, source, ""); err == nil {
		t.Fatal("a restore wrote over a file that was already there")
	}
}

// The store is named per system user, and a name that is not a tenant is refused
// so nothing can point the removal at another directory.
func TestOnlyATenantStoreCanBeRemoved(t *testing.T) {
	store := withStore(t)
	if err := os.MkdirAll(filepath.Join(store, "c_site"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, refused := range []string{"", "root", "..", "/etc"} {
		if err := RemoveStoreForUser(refused); err == nil {
			t.Errorf("RemoveStoreForUser(%q) was accepted", refused)
		}
	}
	if _, err := os.Stat(filepath.Join(store, "c_site")); err != nil {
		t.Fatalf("a refused removal disturbed the store: %v", err)
	}
	if err := RemoveStoreForUser("c_site"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store, "c_site")); !os.IsNotExist(err) {
		t.Error("the tenant store survived its own removal")
	}
}

// The store path is derived from config, never from anything a caller sends.
func TestTheStorePathComesFromConfig(t *testing.T) {
	store := withStore(t)
	if got := userStore("c_site"); got != filepath.Join(store, "c_site") {
		t.Errorf("userStore = %q, want %q", got, filepath.Join(store, "c_site"))
	}
	// The stored name carries the row id, so two files with one base name cannot
	// collide and an orphan cannot be taken for a live entry.
	if got := storedName(12, "public_html/a/shell.php"); got != "12_shell.php" {
		t.Errorf("storedName = %q, want 12_shell.php", got)
	}
	if strings.Contains(storedName(12, "public_html/a/shell.php"), "/") {
		t.Error("the stored name carries a path separator")
	}
}
