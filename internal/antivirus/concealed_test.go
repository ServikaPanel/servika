package antivirus

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// Every way of splitting a name has to be seen, because an attacker picks the
// split point and there are as many as the name has characters.
func TestAConcealedNameIsFoundHoweverItIsSplit(t *testing.T) {
	cases := []struct{ name, body string }{
		{"two-part split", `<?php $g = 'ev'.'al'; $g($x);`},
		{"per-character split", `<?php $g = 'e'.'v'.'a'.'l'; $g($x);`},
		{"double-quoted split", `<?php $f = "base"."64_decode"; $f($d);`},
		{"spaced split", `<?php $f = 'sys' . 'tem'; $f($c);`},
		{"split across a line break", "<?php $f = 'sys' .\n  'tem'; $f($c);"},
		{"inline split call", `<?php ('sys'.'tem')($_GET['c']);`},
		{"concealed decoder", `<?php $f = 'gzin'.'flate'; echo $f($d);`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if len(concealedMatches(".php", []byte(c.body))) == 0 {
				t.Error("a concealed name was not found")
			}
		})
	}
}

// The rule is about CONCEALMENT, not about the call, so a plain call and
// ordinary string building must both stay silent. The plain call is owned by
// the ordinary rules and counting it here would report it twice.
func TestAPlainCallAndOrdinaryConcatenationStaySilent(t *testing.T) {
	cases := []struct{ name, body string }{
		{"a plain eval", `<?php eval($_POST['c']);`},
		{"a plain system call", `<?php system('/usr/bin/convert in.png out.jpg');`},
		{"ordinary string building", `<?php $msg = 'Hello ' . 'world'; $sql = 'SELECT ' . '*';`},
		{"path building", `<?php $p = ABSPATH . 'wp-admin' . '/includes/file.php';`},
		{"a concatenation with no dangerous result", `<?php $k = 'wc_' . 'session_' . 'id';`},
		{"no concatenation at all", `<?php add_action('init', 'my_plugin_boot');`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if m := concealedMatches(".php", []byte(c.body)); len(m) != 0 {
				t.Errorf("false alarm: %v", m)
			}
		})
	}
}

// The whole point of the rule: this file is a working webshell that every
// pattern in the set walks past, because the blob is only weak evidence and the
// execution never spells its own name.
func TestTheSplitNameWebshellIsReported(t *testing.T) {
	blob := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("<?php system($_GET['c']); ", 70)))
	body := []byte("<?php\n$d = <<<EOT\n" + blob + "\nEOT;\n" +
		"$f = 'base'.'64_decode';\n$g = 'ev'.'al';\n$g($f($d));\n")

	score, _, names, level := verdict(evaluate(".php", body), 0)
	if level != LevelCritical {
		t.Fatalf("level %q at score %d, want %q (matched %v)", level, score, LevelCritical, names)
	}
	if !strings.Contains(strings.Join(names, ","), "PHP.Obf.ConcealedFunctionName") {
		t.Errorf("matched %v, want the concealed-name rule among them", names)
	}
	// Without the concealed execution the same file is not CRITICAL, which is
	// what made the concealment worth a rule of its own. The decode layer
	// (decoded.go) does see the staged `system($_GET)` payload inside the blob
	// and reports it as suspicious, but a decoded match is capped there and
	// cannot drive containment on its own; it is the concealed execution that
	// makes the full file critical.
	withoutExecution := []byte("<?php\n$d = <<<EOT\n" + blob + "\nEOT;\n")
	if _, _, _, level := verdict(evaluate(".php", withoutExecution), 0); level == LevelCritical {
		t.Errorf("the blob alone produced %q; without the execution it must not be critical", level)
	}
}

// A JavaScript bundle is full of concatenated strings and none of it runs
// through PHP, so the strip never happens there.
func TestTheStripIsNotAppliedToOtherFileKinds(t *testing.T) {
	body := []byte(`var g = 'ev' + 'al';`)
	for _, ext := range append(append([]string{}, jsExts...), extHTAccess) {
		if m := concealedMatches(ext, body); len(m) != 0 {
			t.Errorf("%s: %v", ext, m)
		}
	}
}

// The cheap pre-test must not change the answer, only the cost.
func TestTheJoinPreTestDoesNotChangeTheAnswer(t *testing.T) {
	r := make([]byte, 2000)
	if _, err := rand.Read(r); err != nil {
		t.Fatal(err)
	}
	noJoin := []byte(`<?php $x = base64_decode('` + base64.StdEncoding.EncodeToString(r) + `');`)
	if m := concealedMatches(".php", noJoin); len(m) != 0 {
		t.Errorf("a file with no concatenation produced %v", m)
	}
}
