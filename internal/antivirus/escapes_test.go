package antivirus

import (
	"os"
	"path/filepath"
	"testing"
)

// Ten shapes that escaped this rule set entirely, each scoring zero. Every one
// is a complete webshell or a step that only a webshell takes.
//
// They come from an adversarial audit of the upstream this package is derived
// from; each was checked against THIS rule set before it was ported, and only
// the ones that really escaped here are listed.
func TestTheKnownEscapesAreClosed(t *testing.T) {
	cases := []struct {
		name, body string
		want       string
	}{
		// Request data reaching execution through an intermediate variable.
		// Every adjacency rule in the set is defeated by one assignment.
		{"decoupled variable function", `<?php $d=$_POST['x']; $c=$_GET['f']; $c($d);`, LevelCritical},
		{"decoupled eval", `<?php $p=$_POST['x']; eval($p);`, LevelCritical},
		{"decoupled system", `<?php $q=$_REQUEST['c']; system($q);`, LevelCritical},

		// call_user_func is a variable function with another spelling.
		{"call_user_func", `<?php call_user_func($_GET['f'], $_GET['a']);`, LevelCritical},
		{"call_user_func_array", `<?php call_user_func_array($_POST['f'], $_POST['a']);`, LevelCritical},

		// Decoders other than base64 fed to eval.
		{"eval hex2bin", `<?php eval(hex2bin('6576616c'));`, LevelCritical},
		{"eval gzdecode", `<?php eval(gzdecode($x));`, LevelCritical},
		{"eval pack", `<?php eval(pack('H*', $x));`, LevelCritical},

		// A dangerous function named as a string callback, the modern
		// replacement for preg_replace's /e modifier.
		{"preg_replace_callback assert", `<?php preg_replace_callback('/(.+)/', 'assert', [$_POST['x']]);`, LevelCritical},

		// Stream wrappers that fetch code without touching http.
		{"php:// include", `<?php include('php://input');`, LevelCritical},
		{"data:// require", `<?php require('data://text/plain;base64,PD9waHA=');`, LevelCritical},
	}
	dir := t.TempDir()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(dir, "x.php")
			if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, names, level := verdict(evaluate(".php", []byte(c.body)), scoreCritical)
			if level != c.want {
				t.Errorf("reported %q, want %q (rules %v) for: %s", level, c.want, names, c.body)
			}
		})
	}
}

// The new rules must not report code that is merely doing its job. Each of
// these is the legitimate counterpart of a rule above.
func TestTheNewRulesReportNothingOnLegitimateCode(t *testing.T) {
	cases := []struct{ name, body string }{
		// call_user_func with a constant function name.
		{"call_user_func constant", `<?php call_user_func('sanitize_text_field', $input);`},
		// A closure callback rather than a string one.
		{"array_map closure", `<?php $r = array_map(function($x){ return trim($x); }, $list);`},
		{"preg_replace_callback closure", `<?php preg_replace_callback('/\d+/', function($m){ return $m[0]*2; }, $s);`},
		// An ARRAY callback naming a method on an object. A Redis client's
		// `eval` is a Lua eval on the server, not PHP's eval, and this exact
		// line ships in a widely-installed cache plugin.
		{"array callback on an object", `<?php call_user_func_array([$this->redis, 'eval'], $args);`},
		// The same array-callback shape reaching a function the string-callback
		// rule DOES name. This is what the `[^;\[]` in that pattern exists for:
		// `[$obj, 'eval']` is a method on an object, not PHP's eval.
		{"array callback through array_map", `<?php $out = array_map([$this->redis, 'eval'], $rows);`},
		{"array callback through usort", `<?php usort($rows, [$this->cmp, 'exec']);`},
		// Request data read into a variable and then ESCAPED, which is what
		// every form handler does.
		{"request into a variable, escaped", `<?php $name=$_POST['name']; echo htmlspecialchars($name);`},
		// Request data read into a variable and passed to an ordinary function.
		{"request into a variable, used", `<?php $id=$_GET['id']; $post=get_post($id); echo $post->title;`},
		// A constant include.
		{"constant include", `<?php require_once __DIR__.'/config.php';`},
		// A phar stub requiring its own archive, which is what a phar stub is.
		{"phar stub", `<?php require_once 'phar://guzzle.phar/vendor/autoload.php';`},
		// Prose about a variable in a comment, which is not a call.
		{"a variable named in a comment", "<?php\n$doing_wp_cron = $_GET['doing_wp_cron'];\n// must match $doing_wp_cron (the \"key\").\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, names, level := verdict(evaluate(".php", []byte(c.body)), scoreCritical)
			if level != "" {
				t.Errorf("reported %q on legitimate code (rules %v): %s", level, names, c.body)
			}
		})
	}
}
