package antivirus

import "testing"

// Moving a WordPress core file out of the tree turns a compromised site into a
// dead one, so the finding is reported and the file stays. The case is
// reachable: measured with a real backdoor appended to a real
// wp-includes/pluggable.php from WordPress 7.1, the shipped rule set scores it
// critical 100 through PHP.Webshell.EvalSuperglobal, and automatic containment
// takes every critical finding.
func TestACoreFileIsProtectedFromContainment(t *testing.T) {
	protected := []string{
		"/home/c_site/public_html/wp-includes/pluggable.php",
		"/home/c_site/public_html/wp-admin/includes/file.php",
		"/home/c_site/public_html/blog/wp-includes/load.php",
	}
	for _, path := range protected {
		if !CoreFileProtected(path, "PHP.Webshell.EvalSuperglobal") {
			t.Errorf("%s was not protected", path)
		}
	}
}

// The exception must not swallow the files this scanner exists to take away.
// Without this half the change would be a way to make every finding
// uncontainable by putting it in the right directory name.
func TestEverythingElseIsStillContained(t *testing.T) {
	contained := []string{
		"/home/c_site/public_html/wp-content/uploads/shell.php",
		"/home/c_site/public_html/wp-content/plugins/x/evil.php",
		"/home/c_site/public_html/shell.php",
		"/home/c_site/public_html/wp-login.php",
		// A tenant directory whose NAME contains a core directory name is not
		// core. A substring test would make every file under it uncontainable,
		// which is a place to hide a webshell.
		"/home/c_site/public_html/my-wp-includes-backup/shell.php",
		"/home/c_site/public_html/wp-includes-old/shell.php",
		// A FILE called wp-admin names no tree.
		"/home/c_site/public_html/wp-admin",
	}
	for _, path := range contained {
		if CoreFileProtected(path, "PHP.Webshell.EvalSuperglobal") {
			t.Errorf("%s was protected and should not be", path)
		}
	}
}

// The checksum engine already proved its extra-file findings belong to no
// release, so those stay containable even inside a core directory: that is
// exactly the webshell case and removing one breaks nothing.
func TestAnExtraFileInsideCoreIsStillContained(t *testing.T) {
	path := "/home/c_site/public_html/wp-includes/js/jquery/jquery.min.php"
	if CoreFileProtected(path, SignatureExtraFile) {
		t.Error("a checksum extra-file finding inside wp-includes was protected")
	}
	// The same path found by a content rule IS protected, because nothing there
	// proved the file is not part of the release.
	if !CoreFileProtected(path, "PHP.Webshell.EvalSuperglobal") {
		t.Error("the same path found by a content rule was not protected")
	}
}

// IsWordPressCoreFile is the path half on its own, so a caller that reaches for
// it directly gets the same segment rule.
func TestTheCoreTreeTestIsOnWholeSegments(t *testing.T) {
	cases := map[string]bool{
		"/x/wp-includes/a.php":         true,
		"/x/wp-admin/a.php":            true,
		"/x/wp-includes":               false,
		"/x/notwp-includes/a.php":      false,
		"/x/wp-includes-backup/a.php":  false,
		"/x/wp-content/wp-admin/a.php": true,
		"wp-includes/a.php":            true,
		"a.php":                        false,
	}
	for path, want := range cases {
		if got := IsWordPressCoreFile(path); got != want {
			t.Errorf("IsWordPressCoreFile(%q) = %v, want %v", path, got, want)
		}
	}
}
