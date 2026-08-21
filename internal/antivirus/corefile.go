package antivirus

// A WordPress core file is REPORTED, never taken away.
//
// Containment moves a file out of the tree, and for everything this scanner
// normally finds that is the right answer: a webshell under uploads has no
// business existing and the site does not miss it. A core file is the opposite.
// WordPress cannot load without wp-includes/pluggable.php, so containing an
// infected one turns a compromised site into a dead one, and the customer sees a
// fatal error on every request instead of a working site with a backdoor.
//
// The case is reachable rather than theoretical. Measured with a real backdoor
// appended to a real wp-includes/pluggable.php from WordPress 7.1:
//
//	critical 100  wp-includes/pluggable.php  [PHP.Webshell.EvalSuperglobal(100)]
//
// Automatic containment takes every critical finding, so with the switch on the
// panel would have moved that file itself.
//
// The repair already exists and is the correct one: `wp core download --force
// --skip-content` puts the official file back with the site still running, which
// internal/wordpress.Repair does. So the finding is worth reporting and worth
// nothing to contain.
//
// The test is on the core TREE, because at containment time nothing here knows
// which files a release owns: that answer lives in the checksum table, which is
// keyed by version and locale and may not be reachable at all. The one case
// where it IS known is a finding the checksum engine itself produced, since
// SignatureExtraFile means "wordpress.org's table does not name this path". That
// signature is exempt and nothing else is.
//
// So a webshell planted at wp-admin/evil.php is contained when the checksum
// engine found it and only reported when a content rule found it. That asymmetry
// is deliberate: the file stays on disk and on the screen either way, and the
// operator removes it from the file manager, while the alternative risks moving
// a file the site cannot start without.

import (
	"path/filepath"
	"slices"
	"strings"
)

// SignatureExtraFile marks a file that WordPress.org's own checksum table does
// not name, so it is certainly not part of the release.
//
// The string is spelled here rather than imported because internal/wordpress
// imports this package, so the dependency can only run one way.
// internal/wordpress holds the same constant and a test there asserts the two
// still agree.
const SignatureExtraFile = "WP.Core.ExtraFile"

// CoreFileProtected reports whether a finding must be left where it is.
//
// It takes the signature as well as the path, because the checksum engine
// already proved that its extra-file findings belong to no release.
func CoreFileProtected(path, signature string) bool {
	if signature == SignatureExtraFile {
		return false
	}
	return IsWordPressCoreFile(path)
}

// coreDirectories are the two trees a WordPress release owns outright. Anything
// else, including wp-content and the root-level wp-*.php files, is either the
// site's own or is replaced wholesale by a core download.
var coreDirectories = []string{"wp-admin", "wp-includes"}

// IsWordPressCoreFile reports whether a path sits inside a WordPress core
// directory.
//
// The test is on whole path SEGMENTS, never a substring: a tenant directory
// really named `my-wp-includes-backup` contains the string and is not core, and
// treating it as core would quietly make every file under it uncontainable,
// which is a place to hide a webshell.
func IsWordPressCoreFile(path string) bool {
	parts := strings.Split(filepath.ToSlash(path), "/")
	// The last element is the file itself. A file called `wp-admin` is not a
	// directory and names no tree.
	for _, part := range parts[:max(len(parts)-1, 0)] {
		if slices.Contains(coreDirectories, part) {
			return true
		}
	}
	return false
}
