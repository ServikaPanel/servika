package antivirus

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"servika/internal/files"

	_ "github.com/go-sql-driver/mysql"
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

// unreachableDB is a handle that opens without connecting and fails on the first
// statement. restoreEntry and deleteEntry act on the FILE before they touch the
// database, so this lets the file half be measured on its own: the reason code
// that comes back names the database step, which is the proof the file step ran.
func unreachableDB(t *testing.T) *sql.DB {
	t.Helper()
	// Port 1 refuses immediately; sql.Open itself never dials.
	handle, err := sql.Open("mysql", "u:p@tcp(127.0.0.1:1)/none")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	return handle
}

// A stored name that no longer looks the way this code wrote it may not reach
// outside the store.
//
// `stored` is interpolated from av_quarantine.stored_name, a DATABASE ROW, and a
// row outlives the code that wrote it. filepath.Join CLEANS a leading "..", so a
// plain os.Open/os.Remove pair resolves such a name to a real file above the
// store and acts on it as root.
func TestAStoredNameCannotReachOutsideTheStore(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("safeio is Linux-only; the stub refuses everything")
	}
	store := withStore(t)
	if err := os.MkdirAll(filepath.Join(store, "c_site"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A file one level ABOVE the tenant's own store directory.
	outside := filepath.Join(store, "someone-elses-evidence")
	if err := os.WriteFile(outside, []byte("not this tenant's"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{DB: unreachableDB(t)}

	if _, reason := h.restoreEntry("c_site", "public_html/shell.php", "../someone-elses-evidence", 1); reason != reasonFileMissing {
		t.Errorf("a traversing stored name was opened for restore: reason %q", reason)
	}
	// Measured: RemoveAllBeneath answers nil for a traversing rel rather than an
	// error. The ".." is resolved inside the jail, so the leaf names nothing and
	// the removal is a no-op that reports success. What the caller must not do is
	// reach the file, so the assertion that carries the boundary is the one below,
	// not this reason code.
	if reason := h.deleteEntry("c_site", "../someone-elses-evidence", 1); reason != reasonDeleteRecordFail {
		t.Errorf("deleting a traversing stored name answered %q, want the database step to be the failure", reason)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("the file above the store was removed: %v", err)
	}
	// The read half is asserted through inspect, which reaches the same store
	// with the same primitive and, unlike restore, does not build a path under
	// /home that a test cannot create.
	if _, reason := inspectEntry("c_site", "public_html/shell.php", "../someone-elses-evidence"); reason != reasonFileMissing {
		t.Errorf("a traversing stored name was read: reason %q", reason)
	}
}

// A symlink standing where a stored file belongs is refused rather than followed.
//
// The store is root-owned 0700 so no tenant can plant one today, which is why
// this is hardening rather than a reachable bug. It is asserted anyway because
// the two paths that read this file must not use two strengths of primitive:
// inspectEntry already opens through openat2, and the weaker of the two is what
// decides what the pair is worth.
func TestASymlinkInTheStoreIsNotFollowed(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("safeio is Linux-only; the stub refuses everything")
	}
	store := withStore(t)
	userDir := filepath.Join(store, "c_site")
	if err := os.MkdirAll(userDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(secret, []byte("root:$6$hash"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(userDir, "1_shell.php")); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{DB: unreachableDB(t)}

	if _, reason := h.restoreEntry("c_site", "public_html/shell.php", "1_shell.php", 1); reason != reasonFileMissing {
		t.Errorf("the link was followed for restore: reason %q", reason)
	}
	if _, reason := inspectEntry("c_site", "public_html/shell.php", "1_shell.php"); reason != reasonFileMissing {
		t.Errorf("inspect followed the link: reason %q", reason)
	}

	// Deleting removes the LINK and leaves its target alone. unlink(2) never
	// follows a final component, so this half held before the change too; it is
	// asserted so a later rewrite cannot lose it.
	if reason := h.deleteEntry("c_site", "1_shell.php", 1); reason != reasonDeleteRecordFail {
		t.Errorf("removing the link answered %q, want the database step to be the failure", reason)
	}
	if _, err := os.Lstat(filepath.Join(userDir, "1_shell.php")); !os.IsNotExist(err) {
		t.Error("the link itself survived the deletion")
	}
	if _, err := os.Stat(secret); err != nil {
		t.Errorf("the link's target was deleted: %v", err)
	}
}

// The non-vacuity of the two above: an ORDINARY stored file is still opened and
// still removed. Without this both would pass on a pair of calls that refuse
// everything.
//
// restoreEntry builds the tenant home itself as "/home/<user>", so its success
// path cannot be exercised without writing under /home, which a test may not do.
// It does not need to be: reasonFileMissing is returned by the OPEN and nothing
// else, so a restore that reaches a LATER step is a restore whose open
// succeeded, and that open is the line this change touched.
func TestAnOrdinaryStoredFileIsStillOpenedAndRemoved(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("safeio is Linux-only; the stub refuses everything")
	}
	store := withStore(t)
	userDir := filepath.Join(store, "c_site")
	if err := os.MkdirAll(userDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stored := filepath.Join(userDir, "5_shell.php")
	body := "<?php eval($_GET['x']);"
	if err := os.WriteFile(stored, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{DB: unreachableDB(t)}

	if _, reason := h.restoreEntry("c_site", "public_html/back.php", "5_shell.php", 5); reason == reasonFileMissing {
		t.Error("an ordinary stored file could not be opened for restore")
	}
	// The same call inspect makes, on the same store and the same name, so the
	// bytes are proved to come back rather than only the absence of a refusal.
	response, reason := inspectEntry("c_site", "public_html/back.php", "5_shell.php")
	if reason != "" {
		t.Fatalf("an ordinary stored file could not be read: reason %q", reason)
	}
	if response["content"] != body {
		t.Errorf("read %q, want %q", response["content"], body)
	}

	if reason := h.deleteEntry("c_site", "5_shell.php", 5); reason != reasonDeleteRecordFail {
		t.Fatalf("an ordinary stored file did not delete: reason %q", reason)
	}
	if _, err := os.Stat(stored); !os.IsNotExist(err) {
		t.Error("the ordinary stored file survived its own deletion")
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
