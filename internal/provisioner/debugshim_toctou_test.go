package provisioner

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestInstallDebugShim_SymlinkAttackBlocked verifies that installDebugShim does
// NOT follow a symlink placed at the .servika path. A tenant can symlink
// /home/<su>/.servika to an arbitrary path before debug mode is enabled;
// the fix must replace the symlink with a real root:root 0755 directory
// without writing to or chown-ing the symlink target.
// Requires root (symlink/chown semantics).
func TestInstallDebugShim_SymlinkAttackBlocked(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required (symlink/chown semantics)")
	}
	base, home := debugShimHome(t)

	// Victim directory: the attacker's symlink target. Chown to nobody so
	// that any chown-to-root by a vulnerable code path is detected.
	victim, sentinel := nobodyOwnedVictimDirectory(t, base)

	// Attack: home/.servika -> victim symlink (tenant would do this before debug is enabled).
	servPath := filepath.Join(home, ".servika")
	if err := os.Symlink(victim, servPath); err != nil {
		t.Fatal(err)
	}

	// Trigger the actual FS core.
	installDebugShim(home, "c_toctou_attack", []byte("<?php /* shim */"))

	// (1) .servika is NO LONGER a symlink -- a real root:root directory.
	assertRootOwnedServikaDirectory(t, servPath)
	// (2) Victim is untouched: still nobody-owned, sentinel present, no shim leaked.
	assertVictimDirectoryUntouched(t, victim, sentinel)
	// (3) Shim was written to the REAL .servika directory, (4) by root.
	assertShimWrittenByRoot(t, servPath)
}

// debugShimHome creates a tenant home under a new temporary directory and
// returns the directory and the home.
func debugShimHome(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	home := filepath.Join(base, "home")
	if err := os.Mkdir(home, 0o710); err != nil {
		t.Fatal(err)
	}
	return base, home
}

// nobodyOwnedVictimDirectory creates a nobody-owned directory holding a sentinel
// file, and returns both paths.
func nobodyOwnedVictimDirectory(t *testing.T, base string) (string, string) {
	t.Helper()
	victim := filepath.Join(base, "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chown(victim, 65534, 65534); err != nil {
		t.Fatalf("victim chown nobody: %v", err)
	}
	sentinel := filepath.Join(victim, "keep.txt")
	if err := os.WriteFile(sentinel, []byte("UNTOUCHED"), 0o600); err != nil {
		t.Fatal(err)
	}
	return victim, sentinel
}

// assertRootOwnedServikaDirectory fails unless servPath is a real root:root
// directory.
func assertRootOwnedServikaDirectory(t *testing.T, servPath string) {
	t.Helper()
	var lst unix.Stat_t
	if err := unix.Lstat(servPath, &lst); err != nil {
		t.Fatalf(".servika lstat: %v", err)
	}
	if lst.Mode&unix.S_IFMT == unix.S_IFLNK {
		t.Fatal("FAIL: .servika is STILL a symlink -- symlink WAS followed")
	}
	if lst.Mode&unix.S_IFMT != unix.S_IFDIR {
		t.Fatal("FAIL: .servika is not a real directory")
	}
	if lst.Uid != 0 || lst.Gid != 0 {
		t.Fatalf("FAIL: .servika is not root:root (uid=%d gid=%d)", lst.Uid, lst.Gid)
	}
}

// assertVictimDirectoryUntouched fails when the victim lost its owner or its
// sentinel, or received the shim.
func assertVictimDirectoryUntouched(t *testing.T, victim, sentinel string) {
	t.Helper()
	var vst unix.Stat_t
	if err := unix.Lstat(victim, &vst); err != nil {
		t.Fatalf("victim lstat: %v", err)
	}
	if vst.Uid != 65534 || vst.Gid != 65534 {
		t.Fatalf("FAIL: victim was chown-ed -> cross-tenant DoS (uid=%d gid=%d)", vst.Uid, vst.Gid)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("FAIL: victim sentinel is missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(victim, "debug_prepend.php")); err == nil {
		t.Fatal("FAIL: debug_prepend.php was written to victim -> arbitrary root-write")
	}
}

// assertShimWrittenByRoot fails unless the log and the shim exist in servPath
// and root created the shim.
func assertShimWrittenByRoot(t *testing.T, servPath string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(servPath, "php_debug.log")); err != nil {
		t.Fatal("FAIL: php_debug.log not created in real .servika")
	}
	if _, err := os.Stat(filepath.Join(servPath, "debug_prepend.php")); err != nil {
		t.Fatal("FAIL: debug_prepend.php not created in real .servika")
	}
	var gst unix.Stat_t
	if err := unix.Lstat(filepath.Join(servPath, "debug_prepend.php"), &gst); err != nil {
		t.Fatal(err)
	}
	if gst.Uid != 0 {
		t.Fatalf("FAIL: debug_prepend.php owner is not root (uid=%d)", gst.Uid)
	}
}

// TestInstallDebugShim_LogSymlinkAttackBlocked verifies that the php_debug.log
// file is opened with O_NOFOLLOW. A tenant could place a symlink named
// php_debug.log pointing to a sensitive path before the shim creates it.
func TestInstallDebugShim_LogSymlinkAttackBlocked(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required (symlink/chown semantics)")
	}
	base, home := debugShimHome(t)
	// Create a valid .servika directory first (as ensureRootDirAt would).
	servPath := rootOwnedServikaDirectory(t, home)

	// Victim file: symlink target.
	victim := nobodyOwnedVictimFile(t, base)

	// Attack: php_debug.log -> victim symlink.
	if err := os.Symlink(victim, filepath.Join(servPath, "php_debug.log")); err != nil {
		t.Fatal(err)
	}

	installDebugShim(home, "c_toctou_attack", []byte("<?php /* shim */"))

	// php_debug.log is no longer a symlink.
	var lst unix.Stat_t
	logPath := filepath.Join(servPath, "php_debug.log")
	if err := unix.Lstat(logPath, &lst); err != nil {
		t.Fatal(err)
	}
	if lst.Mode&unix.S_IFMT == unix.S_IFLNK {
		t.Fatal("FAIL: php_debug.log is STILL a symlink")
	}
	// Victim is untouched.
	var vst unix.Stat_t
	if err := unix.Lstat(victim, &vst); err != nil {
		t.Fatal(err)
	}
	if vst.Uid != 65534 {
		t.Fatalf("FAIL: victim chown-ed to %d", vst.Uid)
	}
}

// rootOwnedServikaDirectory creates a root:root .servika directory in home and
// returns its path.
func rootOwnedServikaDirectory(t *testing.T, home string) string {
	t.Helper()
	servPath := filepath.Join(home, ".servika")
	if err := os.Mkdir(servPath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chown(servPath, 0, 0); err != nil {
		t.Fatal(err)
	}
	return servPath
}

// nobodyOwnedVictimFile creates an empty nobody-owned file and returns its path.
func nobodyOwnedVictimFile(t *testing.T, base string) string {
	t.Helper()
	victim := filepath.Join(base, "victim_log")
	if err := os.WriteFile(victim, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chown(victim, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	return victim
}

// TestInstallDebugShim_TenantOwnedDir verifies that ensureRootDirAt rejects
// a tenant-owned directory at .servika and replaces it with root:root.
func TestInstallDebugShim_TenantOwnedDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required")
	}
	_, home := debugShimHome(t)
	// Tenant-owned .servika (e.g., created manually).
	servPath := filepath.Join(home, ".servika")
	if err := os.Mkdir(servPath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chown(servPath, 65534, 65534); err != nil {
		t.Fatal(err)
	}

	installDebugShim(home, "c_toctou_attack", []byte("<?php /* shim */"))

	var lst unix.Stat_t
	if err := unix.Lstat(servPath, &lst); err != nil {
		t.Fatal(err)
	}
	if lst.Uid != 0 || lst.Gid != 0 {
		t.Fatalf("FAIL: .servika still tenant-owned (uid=%d gid=%d)", lst.Uid, lst.Gid)
	}
	if _, err := os.Stat(filepath.Join(servPath, "debug_prepend.php")); err != nil {
		t.Fatal("FAIL: shim not created in reclaimed directory")
	}
}

// TestInstallDebugShim_GeneratedPHPSyntax verifies the generated shim content
// passes php -l syntax validation and contains the expected function skeleton.
func TestInstallDebugShim_GeneratedPHPSyntax(t *testing.T) {
	if _, err := exec.LookPath("php"); err != nil {
		t.Skip("php binary not found")
	}
	base := t.TempDir()
	shimPath := filepath.Join(base, "debug_prepend.php")
	content := []byte(renderDebugPrependPHP("c_test", ""))
	if err := os.WriteFile(shimPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.Command("php", "-l", shimPath).CombinedOutput(); err != nil {
		t.Fatalf("php -l FAILED: %s: %v", string(out), err)
	}

	source := string(content)
	if !strings.Contains(source, "register_shutdown_function") {
		t.Error("shim missing register_shutdown_function")
	}
	if !strings.Contains(source, "error_get_last") {
		t.Error("shim missing error_get_last")
	}
}

// TestInstallDebugShim_ChainedPrependPreserved verifies that when an app has
// its own auto_prepend_file value, the shim chains it via require_once.
func TestInstallDebugShim_ChainedPrependPreserved(t *testing.T) {
	if _, err := exec.LookPath("php"); err != nil {
		t.Skip("php binary not found")
	}
	base := t.TempDir()
	shimPath := filepath.Join(base, "debug_prepend.php")
	content := []byte(renderDebugPrependPHP("c_test", "/home/c_test/my_prepend.php"))
	if err := os.WriteFile(shimPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.Command("php", "-l", shimPath).CombinedOutput(); err != nil {
		t.Fatalf("php -l FAILED: %s: %v", string(out), err)
	}

	source := string(content)
	if !strings.Contains(source, "require_once '/home/c_test/my_prepend.php'") {
		t.Error("shim does not chain the app's auto_prepend")
	}
}
