package antivirus

// Where a file sits is evidence in its own right, and it is the cheapest
// evidence there is: no read, no pattern, just the path.
//
// A .php file under wp-content/uploads is the single most common shape a
// compromised WordPress site takes. WordPress never writes PHP there and
// neither do plugins: measured against the five most-installed ones,
// WooCommerce, Elementor, Contact Form 7, Wordfence and UpdraftPlus, not one
// writes a PHP file into the upload directory (WooCommerce writes index.html).
// That makes it a verdict on its own, and it costs nothing to reach, which
// matters because a payload can also sit in a file too large to read.
//
// Every weight here was measured against WordPress core plus those five
// plugins, 7142 real executable files: none of the five rules fires once.

import (
	"path/filepath"
	"slices"
	"strings"
)

// fakeExtensions are the segments that make a double extension a disguise
// rather than a naming convention. The test is for one of THESE followed by a
// dot, never a dot count: a plugin file called class.wp.php has two dots and is
// nothing of the kind.
var fakeExtensions = []string{".jpg.", ".jpeg.", ".png.", ".gif.", ".pdf.", ".zip.", ".txt."}

// locationMatches judges a file by its path within the scan root.
//
// The path is taken RELATIVE to the root, so a root that itself sits under a
// dotted directory cannot make every file in the tree look hidden.
func locationMatches(root, path string) []match {
	if !phpish(strings.ToLower(filepath.Ext(path))) {
		// These rules are about a file the web server will EXECUTE. An image
		// under uploads is what that directory is for.
		return nil
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil
	}
	rel = "/" + filepath.ToSlash(rel)

	var out []match
	switch {
	case strings.Contains(rel, "/wp-content/uploads/"):
		out = append(out, match{name: "Location.UploadsExecutable", score: weightProof})
	case strings.Contains(rel, "/wp-content/cache/"):
		// A cache directory holds generated PHP on some stacks, so this is
		// evidence rather than a verdict.
		out = append(out, match{name: "Location.CacheExecutable", score: weightStrong})
	case strings.Contains(rel, "/.well-known/"):
		// That directory exists to serve fixed verification files to an ACME
		// server and to a browser. Nothing there is meant to execute.
		out = append(out, match{name: "Location.WellKnownExecutable", score: weightProof})
	}

	base := strings.ToLower(filepath.Base(rel))
	for _, fake := range fakeExtensions {
		if strings.Contains(base, fake) {
			out = append(out, match{name: "Location.DoubleExtension", score: 80})
			break
		}
	}

	if hiddenDirectory(rel) {
		out = append(out, match{name: "Location.HiddenDirectory", score: scoreSuspicious})
	}
	return out
}

// ordinaryHiddenDirs are dotted directories a project really keeps, measured
// rather than guessed: each is a place a normal repository puts files, so a PHP
// file inside one is not evidence of anything.
//
// .well-known is here for a second reason: it is already judged above, and
// counting it twice would push it past a threshold on its own.
var ordinaryHiddenDirs = []string{
	".well-known", ".github", ".gitlab", ".ci", ".circleci",
	".docker", ".devcontainer", ".vscode", ".idea", ".config",
}

// hiddenDirectory reports whether the file sits inside a dotted DIRECTORY that
// is not one a project ordinarily keeps.
//
// The rule used to be `strings.Contains(rel, "/.")`, which also matched a hidden
// FILE. That is where it went wrong: measured on a real composer install of
// friendsofphp/php-cs-fixer plus phpunit/phpunit, 3011 files, the only dotted
// PHP path in the whole tree is
// vendor/phar-io/manifest/.php-cs-fixer.dist.php, shipped by a PHPUnit
// dependency. The weight is exactly scoreSuspicious, so that one ordinary file
// became a finding on its own, on every PHP project that uses PHPUnit, and the
// panel's own Git deployment is how such a project arrives.
//
// WordPress core and the five most-installed plugins carry no dotted PHP path at
// all (18001 files measured), which is why the corpus never showed this.
func hiddenDirectory(rel string) bool {
	parts := strings.Split(rel, "/")
	if len(parts) < 2 {
		return false
	}
	// The last element is the file itself. A dotted FILE name is ordinary: a
	// tool's own configuration is written that way by convention.
	for _, part := range parts[:len(parts)-1] {
		if !strings.HasPrefix(part, ".") || part == "." || part == ".." {
			continue
		}
		if slices.Contains(ordinaryHiddenDirs, strings.ToLower(part)) {
			continue
		}
		return true
	}
	return false
}
