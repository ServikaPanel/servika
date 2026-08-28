package antivirus

import (
	"strings"
	"testing"
)

const scanRoot = "/home/c_tenant/public_html"

// Both directions, because a location rule scores high enough to report on its
// own and it never reads the file: if it is wrong about a path, nothing
// downstream can correct it.
func TestALocationIsEvidenceOnlyWhereItShouldBe(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		level string
		rule  string
	}{
		// Uploads location alone is corroborating evidence, below suspicious, so
		// a contentless legitimate plugin file there is NOT a finding; the
		// dedicated test below proves location + webshell content is critical.
		{"executable under uploads alone is not a verdict", scanRoot + "/wp-content/uploads/2026/08/shell.php", "", ""},
		{"executable under cache", scanRoot + "/wp-content/cache/x.php", LevelSuspicious, "Location.CacheExecutable"},
		{"executable under .well-known", scanRoot + "/.well-known/x.php", LevelCritical, "Location.WellKnownExecutable"},
		{"image extension before php", scanRoot + "/photo.jpg.php", LevelSuspicious, "Location.DoubleExtension"},
		{"executable in a hidden directory", scanRoot + "/.cache/s.php", LevelSuspicious, "Location.HiddenDirectory"},

		// An image under uploads is what that directory is for.
		{"an image under uploads", scanRoot + "/wp-content/uploads/2026/08/photo.jpg", "", ""},
		// The ACME token is a fixed file the validator reads, not code.
		{"an acme token", scanRoot + "/.well-known/acme-challenge/tok3n", "", ""},
		// Two dots is a naming convention, not a disguise. This one is real:
		// WordPress core and plugins are full of class.name.php.
		{"a dotted class file name", scanRoot + "/wp-content/plugins/x/class.wp.hooks.php", "", ""},
		{"an ordinary front controller", scanRoot + "/index.php", "", ""},
		{"an ordinary plugin file", scanRoot + "/wp-content/plugins/x/x.php", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			score, signature, names, level := verdict(locationMatches(scanRoot, c.path), 0)
			if level != c.level {
				t.Fatalf("level %q, want %q (score %d, rules %v)", level, c.level, score, names)
			}
			if c.rule != "" && !strings.Contains(strings.Join(names, ","), c.rule) {
				t.Errorf("rules %v, want %s among them", names, c.rule)
			}
			if c.rule != "" && signature == "" {
				t.Error("a finding was produced with no signature to group by")
			}
		})
	}
}

// The path is judged relative to the scan root. A root that itself sits under a
// dotted directory must not make every file in the tree look hidden, which is
// what matching the absolute path would do.
func TestTheRootItselfIsNotJudged(t *testing.T) {
	root := "/home/c_tenant/.local/public_html"
	if score, _, names, level := verdict(locationMatches(root, root+"/index.php"), 0); level != "" {
		t.Errorf("the scan root's own path produced %q at score %d: %v", level, score, names)
	}
	// A hidden directory INSIDE that root is still a finding.
	if _, _, _, level := verdict(locationMatches(root, root+"/.hidden/s.php"), 0); level == "" {
		t.Error("a hidden directory inside the root was not judged")
	}
}

// Location evidence adds to content evidence rather than replacing it. A cache
// directory holds generated PHP on some stacks, so it is strong evidence, and
// one more signal is what makes it a verdict.
func TestLocationAndContentEvidenceCombine(t *testing.T) {
	path := scanRoot + "/wp-content/cache/x.php"
	body := []byte(`<?php ini_set('disable_functions', '');`)

	if _, _, _, level := verdict(locationMatches(scanRoot, path), 0); level != LevelSuspicious {
		t.Fatalf("the cache location alone should be suspicious, got %q", level)
	}
	if _, _, _, level := verdict(evaluate(".php", body), 0); level != LevelSuspicious {
		t.Fatalf("the content alone should be suspicious, got %q", level)
	}
	combined := append(locationMatches(scanRoot, path), evaluate(".php", body)...)
	score, _, names, level := verdict(combined, 0)
	if level != LevelCritical {
		t.Errorf("together they should be critical, got %q at score %d: %v", level, score, names)
	}
}

// A .php under uploads is corroborating evidence, not a verdict: real plugins
// write legitimate PHP there, so a contentless file must not be quarantined,
// while a real webshell there is critical on its content plus the location.
func TestUploadsExecutableIsCorroborating(t *testing.T) {
	path := scanRoot + "/wp-content/uploads/2026/08/x.php"

	// Location alone stays below the suspicious threshold, but the rule still
	// fires so it can corroborate content evidence.
	score, _, names, level := verdict(locationMatches(scanRoot, path), 0)
	if level != "" {
		t.Fatalf("uploads location alone produced %q at score %d, want no finding", level, score)
	}
	if !strings.Contains(strings.Join(names, ","), "Location.UploadsExecutable") {
		t.Fatalf("the uploads rule did not fire: %v", names)
	}

	// A real webshell under uploads is critical: content plus the location.
	body := []byte(`<?php eval(base64_decode($_POST['c']));`)
	combined := append(locationMatches(scanRoot, path), evaluate(".php", body)...)
	if _, _, n, lvl := verdict(combined, 0); lvl != LevelCritical {
		t.Fatalf("a webshell under uploads was %q, want critical: %v", lvl, n)
	}

	// A contentless "Silence is golden" guard file is not a finding at all.
	guard := []byte("<?php // Silence is golden")
	quiet := append(locationMatches(scanRoot, path), evaluate(".php", guard)...)
	if _, _, n, lvl := verdict(quiet, 0); lvl != "" {
		t.Fatalf("a contentless uploads guard file was %q, want no finding: %v", lvl, n)
	}
}

// .well-known is judged once. It is excluded from the hidden-directory rule
// deliberately, because counting the same directory twice would turn a single
// piece of evidence into a verdict by arithmetic.
func TestWellKnownIsNotCountedTwice(t *testing.T) {
	_, _, names, _ := verdict(locationMatches(scanRoot, scanRoot+"/.well-known/x.php"), 0)
	joined := strings.Join(names, ",")
	if strings.Contains(joined, "Location.HiddenDirectory") {
		t.Errorf("counted twice: %v", names)
	}
	if !strings.Contains(joined, "Location.WellKnownExecutable") {
		t.Errorf("rules %v, want the .well-known rule", names)
	}
}

// The rule used to be strings.Contains(rel, "/."), which matched a hidden FILE
// as well as a hidden directory, and the weight is exactly scoreSuspicious so
// one ordinary file convicted on its own. Measured on a real composer install of
// friendsofphp/php-cs-fixer plus phpunit/phpunit, 3011 files: the only dotted
// PHP path in the whole tree is vendor/phar-io/manifest/.php-cs-fixer.dist.php,
// shipped by a PHPUnit dependency, so every PHP project that uses PHPUnit
// carried one false finding.
func TestAnOrdinaryDottedFileIsNotAFinding(t *testing.T) {
	root := "/home/c_site/public_html"
	quiet := []string{
		root + "/.php-cs-fixer.dist.php",
		root + "/vendor/phar-io/manifest/.php-cs-fixer.dist.php",
		root + "/.php_cs.php",
		// Ordinary dotted DIRECTORIES a project really keeps.
		root + "/.github/workflows/build.php",
		root + "/.docker/entrypoint.php",
		root + "/.vscode/x.php",
	}
	for _, path := range quiet {
		for _, m := range locationMatches(root, path) {
			if m.name == "Location.HiddenDirectory" {
				t.Errorf("%s was reported as hidden", path)
			}
		}
	}
}

// The other direction: a dotted directory nothing ordinarily keeps is still
// where a payload goes to be missed, so the rule must not have been turned off.
func TestAPaylodInAHiddenDirectoryIsStillFound(t *testing.T) {
	root := "/home/c_site/public_html"
	loud := []string{
		root + "/.hidden/shell.php",
		root + "/assets/.cache2/shell.php",
		root + "/.tmp/deep/shell.php",
	}
	for _, path := range loud {
		var found bool
		for _, m := range locationMatches(root, path) {
			if m.name == "Location.HiddenDirectory" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was not reported as hidden", path)
		}
	}
}
