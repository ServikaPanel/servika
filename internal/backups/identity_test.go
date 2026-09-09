package backups

import (
	"strings"
	"testing"
)

// A real wp-config.php carries the three defines among a lot of other text, in
// either quote style, and the file is the tenant's so its formatting varies.
func TestParseWPConfigReadsTheThreeValues(t *testing.T) {
	src := `<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'c_acme_wp' );
define( "DB_USER",   "c_acme_wpuser" );
define('DB_PASSWORD','s3cr3t');
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	name, user, password := parseWPConfig(src)
	if name != "c_acme_wp" || user != "c_acme_wpuser" || password != "s3cr3t" {
		t.Fatalf("got (%q, %q, %q)", name, user, password)
	}
}

// The value alternatives in the pattern are what make this work. With a single
// ['"] class the double quote inside the password would close the value early,
// the account would be created with the truncated password, and the site would
// still fail to connect: a wrong password is worse than no recovery, because it
// looks like it worked.
func TestParseWPConfigKeepsAPasswordContainingTheOtherQuote(t *testing.T) {
	cases := map[string]string{
		`define('DB_PASSWORD', 'p@ss"word');`:   `p@ss"word`,
		`define("DB_PASSWORD", "p@ss'word");`:   `p@ss'word`,
		`define('DB_PASSWORD', 'it\'s here');`:  `it's here`,
		`define("DB_PASSWORD", "back\\slash");`: `back\slash`,
	}
	for src, want := range cases {
		full := "<?php\ndefine('DB_NAME','d');\ndefine('DB_USER','u');\n" + src + "\n"
		_, _, got := parseWPConfig(full)
		if got != want {
			t.Errorf("%s\n got %q, want %q", src, got, want)
		}
	}
}

// A file that names no database yields nothing, so appIdentity moves on to the
// next candidate rather than creating an account from a partial read.
func TestParseWPConfigOnAFileWithoutTheDefines(t *testing.T) {
	name, user, password := parseWPConfig("<?php\n// nothing to see\n")
	if name != "" || user != "" || password != "" {
		t.Fatalf("got (%q, %q, %q), want all empty", name, user, password)
	}
}

func TestParseDotEnvReadsTheThreeValues(t *testing.T) {
	src := `APP_ENV=production
DB_CONNECTION=mysql
DB_DATABASE=c_acme_app
DB_USERNAME = c_acme_user
DB_PASSWORD="quoted secret"
`
	name, user, password := parseDotEnv(src)
	if name != "c_acme_app" || user != "c_acme_user" || password != "quoted secret" {
		t.Fatalf("got (%q, %q, %q)", name, user, password)
	}
}

// A # is a comment only when a space precedes it. A password is allowed to
// contain one, and cutting there would again produce a wrong password.
func TestParseDotEnvCutsACommentButNotAHashInsideTheValue(t *testing.T) {
	_, _, password := parseDotEnv("DB_PASSWORD=s3cr3t # the database password\n")
	if password != "s3cr3t" {
		t.Errorf("trailing comment not removed: %q", password)
	}
	_, _, password = parseDotEnv("DB_PASSWORD=pa#ss\n")
	if password != "pa#ss" {
		t.Errorf("a hash inside the value was cut: %q", password)
	}
}

// candidateConfigs must look at the document root and one level below it, and
// must not walk deeper: the cost of a restore cannot follow the size of the
// tenant's tree.
func TestCandidateConfigsCoverTheRootAndOneLevel(t *testing.T) {
	got := candidateConfigs(t.TempDir())
	if len(got) != 2 {
		t.Fatalf("an empty document root should yield the two root candidates, got %v", got)
	}
	for _, want := range []string{"public_html/wp-config.php", "public_html/.env"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not among the candidates: %v", want, got)
		}
	}
	for _, g := range got {
		if strings.Count(g, "/") > 2 {
			t.Errorf("candidate %q is deeper than one level below the document root", g)
		}
	}
}
