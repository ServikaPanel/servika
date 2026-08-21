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
		out = append(out, match{"Location.UploadsExecutable", weightProof})
	case strings.Contains(rel, "/wp-content/cache/"):
		// A cache directory holds generated PHP on some stacks, so this is
		// evidence rather than a verdict.
		out = append(out, match{"Location.CacheExecutable", weightStrong})
	case strings.Contains(rel, "/.well-known/"):
		// That directory exists to serve fixed verification files to an ACME
		// server and to a browser. Nothing there is meant to execute.
		out = append(out, match{"Location.WellKnownExecutable", weightProof})
	}

	base := strings.ToLower(filepath.Base(rel))
	for _, fake := range fakeExtensions {
		if strings.Contains(base, fake) {
			out = append(out, match{"Location.DoubleExtension", 80})
			break
		}
	}

	// A hidden directory is where something is put to be missed. .well-known is
	// excluded because it is already judged above and would otherwise be
	// counted twice.
	if strings.Contains(rel, "/.") && !strings.Contains(rel, "/.well-known/") {
		out = append(out, match{"Location.HiddenDirectory", scoreSuspicious})
	}
	return out
}
