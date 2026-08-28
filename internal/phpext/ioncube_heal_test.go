package phpext

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIonCubeLoaderPresent reports the loader as present only when the version's
// 00-ioncube.ini exists, because that .ini is what the startup heal reads to skip
// a version and avoid downloading the archive on a healthy server.
func TestIonCubeLoaderPresent(t *testing.T) {
	dir := t.TempDir()
	s := Version{Version: "8.3", IniDir: dir}
	if ionCubeLoaderPresent(s) {
		t.Fatal("an empty ini directory must not report the loader as present")
	}
	if err := os.WriteFile(filepath.Join(dir, "00-ioncube.ini"), []byte("; loader\n"), 0o644); err != nil {
		t.Fatalf("write the ini: %v", err)
	}
	if !ionCubeLoaderPresent(s) {
		t.Error("a present 00-ioncube.ini must report the loader as present")
	}
}

// TestIonCubeInstallShellCarriesTheFlag proves the injected shell re-invokes this
// binary in its hardened -ioncube-install mode for the named version and falls
// back to a warning rather than failing the PHP install.
func TestIonCubeInstallShellCarriesTheFlag(t *testing.T) {
	got := IonCubeInstallShell("8.3")
	for _, fragment := range []string{
		"-" + ionCubeInstallFlag,
		"'8.3'",
		"|| echo",
		"WARNING",
	} {
		if !strings.Contains(got, fragment) {
			t.Errorf("the injected shell does not carry %q: %q", fragment, got)
		}
	}
}
