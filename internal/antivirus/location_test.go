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
		{"executable under uploads", scanRoot + "/wp-content/uploads/2026/08/shell.php", LevelCritical, "Location.UploadsExecutable"},
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
			score, signature, names, level := verdict(locationMatches(scanRoot, c.path))
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
	if score, _, names, level := verdict(locationMatches(root, root+"/index.php")); level != "" {
		t.Errorf("the scan root's own path produced %q at score %d: %v", level, score, names)
	}
	// A hidden directory INSIDE that root is still a finding.
	if _, _, _, level := verdict(locationMatches(root, root+"/.hidden/s.php")); level == "" {
		t.Error("a hidden directory inside the root was not judged")
	}
}

// Location evidence adds to content evidence rather than replacing it. A cache
// directory holds generated PHP on some stacks, so it is strong evidence, and
// one more signal is what makes it a verdict.
func TestLocationAndContentEvidenceCombine(t *testing.T) {
	path := scanRoot + "/wp-content/cache/x.php"
	body := []byte(`<?php ini_set('disable_functions', '');`)

	if _, _, _, level := verdict(locationMatches(scanRoot, path)); level != LevelSuspicious {
		t.Fatalf("the cache location alone should be suspicious, got %q", level)
	}
	if _, _, _, level := verdict(evaluate(".php", body)); level != LevelSuspicious {
		t.Fatalf("the content alone should be suspicious, got %q", level)
	}
	combined := append(locationMatches(scanRoot, path), evaluate(".php", body)...)
	score, _, names, level := verdict(combined)
	if level != LevelCritical {
		t.Errorf("together they should be critical, got %q at score %d: %v", level, score, names)
	}
}

// .well-known is judged once. It is excluded from the hidden-directory rule
// deliberately, because counting the same directory twice would turn a single
// piece of evidence into a verdict by arithmetic.
func TestWellKnownIsNotCountedTwice(t *testing.T) {
	_, _, names, _ := verdict(locationMatches(scanRoot, scanRoot+"/.well-known/x.php"))
	joined := strings.Join(names, ",")
	if strings.Contains(joined, "Location.HiddenDirectory") {
		t.Errorf("counted twice: %v", names)
	}
	if !strings.Contains(joined, "Location.WellKnownExecutable") {
		t.Errorf("rules %v, want the .well-known rule", names)
	}
}
