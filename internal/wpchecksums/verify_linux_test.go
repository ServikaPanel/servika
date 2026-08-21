package wpchecksums

// The comparison reads a tenant tree as root, so every read goes through
// files.OpenBeneath. That is Linux only (internal/files/safeio_stub.go answers an
// error to everything else), which is why these tests skip elsewhere and why the
// repository runs the suite in a Linux container.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func skipOffLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("safeio is Linux-only; the stub refuses everything")
	}
}

// plantTree writes a minimal installation and returns the home it sits under.
func plantTree(t *testing.T, files map[string]string) (home, relDir string) {
	t.Helper()
	home = t.TempDir()
	relDir = "public_html"
	for rel, body := range files {
		full := filepath.Join(home, relDir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return home, relDir
}

func TestTheVersionFileIsReadBeneathTheHome(t *testing.T) {
	skipOffLinux(t)
	home, relDir := plantTree(t, map[string]string{
		"wp-includes/version.php": realVersionPHP,
	})
	details, err := ReadDetails(home, relDir)
	if err != nil {
		t.Fatalf("ReadDetails: %v", err)
	}
	if details.Version != "7.1" || details.Locale != "tr_TR" {
		t.Fatalf("details = %+v, want 7.1/tr_TR", details)
	}
}

// This runs as root while the directory belongs to the tenant, so a symlink
// planted where version.php belongs would otherwise decide which table is
// fetched, from a file outside the tree entirely.
func TestASymlinkedVersionFileIsRefused(t *testing.T) {
	skipOffLinux(t)
	home, relDir := plantTree(t, map[string]string{"wp-admin/index.php": "x"})
	outside := filepath.Join(t.TempDir(), "elsewhere.php")
	if err := os.WriteFile(outside, []byte(realVersionPHP), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, relDir, "wp-includes", "version.php")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDetails(home, relDir); err == nil {
		t.Fatal("a symlinked version.php was followed")
	}
}

// The three verdicts are three different actions for the caller, so each has to
// come out under its own message rather than as one "dirty" flag.
func TestTheThreeVerdictsAreProducedSeparately(t *testing.T) {
	skipOffLinux(t)
	home, relDir := plantTree(t, map[string]string{
		"wp-includes/version.php":  realVersionPHP,
		"wp-admin/index.php":       "original",
		"wp-admin/edited.php":      "changed on disk",
		"wp-includes/planted.php":  "<?php system($_GET['c']);",
		"wp-content/plugins/x.php": "the site's own file",
		"wp-config.php":            "the site's own credentials",
	})
	table := map[string]string{
		// md5("original")
		"wp-admin/index.php": "919c8b643b7133116b02fc0d9bb7df3f",
		// deliberately wrong, so the file on disk does not match
		"wp-admin/edited.php": "00000000000000000000000000000000",
		// named by the table but absent from the tree
		"wp-includes/gone.php": "11111111111111111111111111111111",
		// skipped by the table pass because it is the site's own
		"wp-content/plugins/x.php": "22222222222222222222222222222222",
		// present so the version file is not itself reported
		"wp-includes/version.php": hashOf(t, home, relDir, "wp-includes/version.php"),
	}

	verdicts, err := Verify(home, relDir, table)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	got := map[string]string{}
	for _, v := range verdicts {
		got[v.Rel] = v.Message
	}
	want := map[string]string{
		"wp-admin/edited.php":     MessageModified,
		"wp-includes/gone.php":    MessageMissing,
		"wp-includes/planted.php": MessageExtra,
	}
	for rel, message := range want {
		if got[rel] != message {
			t.Errorf("%s = %q, want %q", rel, got[rel], message)
		}
	}
	// wp-config.php is the site's own file and the disk pass must never collect
	// it; wp-content is skipped by the table pass whatever its checksum says.
	for _, quiet := range []string{"wp-config.php", "wp-content/plugins/x.php", "wp-admin/index.php"} {
		if message, reported := got[quiet]; reported {
			t.Errorf("%s was reported as %q", quiet, message)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d verdicts, want %d: %v", len(got), len(want), got)
	}
}

// A symlink where a core file belongs is not that core file. wp-cli, running as
// the tenant, follows it and hashes the target; this refuses it, which is the
// deliberate difference that makes this the fallback rather than the engine.
func TestASymlinkedCoreFileIsNotVerified(t *testing.T) {
	skipOffLinux(t)
	home, relDir := plantTree(t, map[string]string{"wp-admin/other.php": "original"})
	outside := filepath.Join(t.TempDir(), "target.php")
	if err := os.WriteFile(outside, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, relDir, "wp-admin", "index.php")); err != nil {
		t.Fatal(err)
	}
	table := map[string]string{
		"wp-admin/index.php": "919c8b643b7133116b02fc0d9bb7df3f", // md5("original")
		"wp-admin/other.php": "919c8b643b7133116b02fc0d9bb7df3f",
	}
	verdicts, err := Verify(home, relDir, table)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(verdicts) != 1 || verdicts[0].Rel != "wp-admin/index.php" {
		t.Fatalf("verdicts = %+v, want one for the symlinked file", verdicts)
	}
	// The file whose content really does match is not reported, so the refusal
	// above is about the symlink and not about the comparison being broken.
	if verdicts[0].Message != MessageModified {
		t.Fatalf("message = %q, want %q", verdicts[0].Message, MessageModified)
	}
}

// A tenant can create directories under wp-includes, so the walk that collects
// extra files is driven by entries they control.
func TestTheDiskPassFindsAPlantedFileAtDepth(t *testing.T) {
	skipOffLinux(t)
	home, relDir := plantTree(t, map[string]string{
		"wp-includes/js/jquery/deep/shell.php": "<?php eval($_POST['x']);",
	})
	verdicts, err := Verify(home, relDir, map[string]string{"wp-admin/index.php": "x"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var found bool
	for _, v := range verdicts {
		if v.Rel == "wp-includes/js/jquery/deep/shell.php" && v.Message == MessageExtra {
			found = true
		}
	}
	if !found {
		t.Fatalf("the planted file was not reported: %+v", verdicts)
	}
}

func hashOf(t *testing.T, home, relDir, rel string) string {
	t.Helper()
	sum, err := hashBeneath(home, filepath.Join(relDir, rel))
	if err != nil {
		t.Fatalf("hashBeneath(%s): %v", rel, err)
	}
	return sum
}
