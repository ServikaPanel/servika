package antivirus

// Request data reaching execution through an intermediate VARIABLE.
//
// Every pattern rule requires the superglobal to sit beside the sink, and one
// assignment defeats all of them at once:
//
//	$d = $_POST['x']; $c = $_GET['f']; $c($d);
//
// That is a complete webshell in which no dangerous name appears next to any
// request data. Upstream closed it with two independent weak patterns, one for
// the assignment and one for the dynamic call, scoring them so a file carrying
// both was reported. Measured against WordPress core plus the five
// most-installed plugins, that pair fired together on SIX clean files,
// `wp-includes/functions.php` and PHPMailer among them: reading a request into
// a variable is what every form handler does, and calling something with a
// variable argument is most of PHP. Two shapes that common are not evidence.
//
// This requires the SAME variable instead. A regular expression cannot follow a
// value from one statement to the next, so the assignment names are collected
// first and the sinks are then looked for by name. It is still not taint
// tracking: no scope, no reassignment, no function boundary. What it is, is a
// claim that this file assigns request data to a name and then executes
// something through that exact name, which is a far narrower thing to say.

import (
	"regexp"
	"strings"
)

var (
	// taintedAssign captures the name a superglobal is read into.
	taintedAssign = regexp.MustCompile(`(?i)\$([a-z_]\w*)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[`)

	// taintedVarCall is a VARIABLE FUNCTION whose name came from the request:
	// `$c(...)` where $c holds request data. The callee is the tainted part.
	//
	// No whitespace is allowed before the parenthesis, and that is a measured
	// decision rather than a stylistic one. PHP accepts `$c (...)`, but with
	// `\s*` in the gap this matched wp-cron.php's own comment, `must match
	// $doing_wp_cron (the "key")`, and reported WordPress core as a webshell.
	// Prose about a variable is common; a space before the call parenthesis in
	// real code is not. This is the same trade PHP.Webshell.BacktickInput
	// already makes against WordPress PHPDoc.
	taintedVarCall = regexp.MustCompile(`\$([a-z_]\w*)\(`)

	// taintedSinkArg is a dangerous function given a tainted variable as its
	// first argument. `include` and `require` are deliberately absent: a
	// template loader that includes a variable path is a different bug class
	// and one ordinary code really does contain.
	taintedSinkArg = regexp.MustCompile(`(?i)\b(?:system|exec|shell_exec|passthru|assert|eval|popen|proc_open|create_function)\s*\(\s*\$([a-z_]\w*)`)
)

// taintMatches reports a superglobal read into a variable that is then executed
// through that same name.
//
// The weight is the critical one because the shape has no legitimate
// counterpart: a file that reads request data into a name and then calls that
// name, or hands it to a shell, is doing the one thing this scanner exists to
// find. It was measured to zero on the clean corpus before it was given that
// weight.
func taintMatches(ext string, content []byte) []match {
	if !phpish(ext) {
		return nil
	}
	body := string(content)
	assigned := map[string]bool{}
	for _, m := range taintedAssign.FindAllStringSubmatch(body, -1) {
		assigned[strings.ToLower(m[1])] = true
	}
	if len(assigned) == 0 {
		return nil
	}
	for _, m := range taintedVarCall.FindAllStringSubmatch(body, -1) {
		if assigned[strings.ToLower(m[1])] {
			return []match{{"PHP.Taint.RequestNameExecuted", weightProof}}
		}
	}
	for _, m := range taintedSinkArg.FindAllStringSubmatch(body, -1) {
		if assigned[strings.ToLower(m[1])] {
			return []match{{"PHP.Taint.RequestValueToSink", weightProof}}
		}
	}
	return nil
}
