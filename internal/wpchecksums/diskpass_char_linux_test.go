package wpchecksums

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// The disk pass is what finds a file nobody published: a shell dropped into a
// core directory, or a `wp-` file left at the installation root. It walks a tree
// the tenant writes to, so its bounds are part of the behaviour.

// reportedExtras returns the relative paths the disk pass called extra.
func reportedExtras(t *testing.T, home, relDir string, table map[string]string) []string {
	t.Helper()
	verdicts, err := Verify(home, relDir, table)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var extras []string
	for _, verdict := range verdicts {
		if verdict.Message == MessageExtra {
			extras = append(extras, verdict.Rel)
		}
	}
	return extras
}

// A `wp-` file at the installation root is core's own territory, so one the
// table does not name is reported. wp-config.php is the site's own and is not.
func TestARootLevelFileTheTableDoesNotNameIsReported(t *testing.T) {
	skipOffLinux(t)
	home, relDir := plantTree(t, map[string]string{
		"wp-login.php":   "the file core ships",
		"wp-shell.php":   "<?php system($_GET['c']);",
		"wp-config.php":  "the site's own credentials",
		"index.php":      "the site's own front controller",
		"wp-admin/x.php": "core",
	})

	extras := reportedExtras(t, home, relDir, map[string]string{
		"wp-login.php":   "irrelevant, the name is what counts here",
		"wp-admin/x.php": "irrelevant too",
	})

	if strings.Join(extras, "|") != "wp-shell.php" {
		t.Errorf("extras = %v, want only the planted root file", extras)
	}
}

// The descent is bounded, because the directories it follows are created by the
// tenant. A tree deeper than the bound is walked to the bound and no further.
func TestTheWalkStopsAtItsDepthBound(t *testing.T) {
	skipOffLinux(t)
	deep := "wp-includes"
	for range walkDepth + 4 {
		deep = path.Join(deep, "d")
	}
	home, relDir := plantTree(t, map[string]string{
		path.Join(deep, "shell.php"):        "<?php eval($_POST['x']);",
		"wp-includes/d/d/d/shallow.php":     "<?php eval($_POST['x']);",
		"wp-includes/version.php":           realVersionPHP,
		"wp-admin/includes/plugin-list.php": "core",
	})

	extras := reportedExtras(t, home, relDir, map[string]string{"wp-admin/index.php": "x"})

	found := map[string]bool{}
	for _, rel := range extras {
		found[rel] = true
	}
	if !found["wp-includes/d/d/d/shallow.php"] {
		t.Errorf("the file inside the bound was not reported: %v", extras)
	}
	if found[path.Join(strings.TrimPrefix(deep, "wp-includes/"), "shell.php")] {
		t.Errorf("a file past the bound was reported: %v", extras)
	}
}

// A core directory that is not there at all is the table pass's finding, a long
// list of missing files, and the disk pass adds nothing of its own.
func TestAMissingCoreDirectoryIsNotADiskPassFinding(t *testing.T) {
	skipOffLinux(t)
	home, relDir := plantTree(t, map[string]string{"wp-admin/index.php": "core"})

	extras := reportedExtras(t, home, relDir, map[string]string{
		"wp-admin/index.php":      "irrelevant",
		"wp-includes/version.php": "irrelevant",
	})

	if len(extras) != 0 {
		t.Errorf("extras = %v, want none", extras)
	}
}

// A symlinked directory under a core directory is not descended, so a tenant
// cannot have the walk list a tree outside the home.
func TestASymlinkedCoreDirectoryIsNotDescended(t *testing.T) {
	skipOffLinux(t)
	home, relDir := plantTree(t, map[string]string{"wp-includes/version.php": realVersionPHP})
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "elsewhere.php"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, relDir, "wp-includes", "linked")); err != nil {
		t.Fatal(err)
	}

	extras := reportedExtras(t, home, relDir, map[string]string{"wp-admin/index.php": "x"})

	for _, rel := range extras {
		if strings.Contains(rel, "linked") {
			t.Errorf("the walk followed the symlink: %v", extras)
		}
	}
}
