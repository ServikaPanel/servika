package antivirus

// The heuristic rule set and the weighing that turns matches into one verdict
// per file.
//
// Every rule used to write its own finding the moment it matched, which is why
// the set could only ever hold patterns that are damning on their own. A
// legitimate plugin calls base64_decode, calls system(), and disables an ini
// guard; naming any of those a finding by itself reports a working site as
// infected, and the cost of a false positive here is a customer's live site.
// Carrying a WEIGHT instead lets evidence be evidence: a chr() chain or a
// suppressed exec is real signal, but only a second independent signal turns it
// into a verdict.
//
// The thresholds and the weights were chosen together, so they are not
// independently adjustable: no single rule below scoreCritical may ever produce
// a critical verdict, and no single rule below scoreSuspicious may produce a
// finding at all.

import (
	"regexp"
	"slices"
)

// The two verdicts a finding can carry. They are the API contract the screen
// renders, so they are stable strings.
const (
	LevelSuspicious = "suspicious"
	LevelCritical   = "critical"
)

// Score thresholds. A file below scoreSuspicious produces NO finding.
const (
	scoreSuspicious = 50
	scoreCritical   = 100
)

// extHTAccess is what filepath.Ext reports for an Apache override file:
// measured, ".htaccess" has its final dot at index 0, so Ext returns the whole
// name and one extension key covers dotfiles and ordinary files alike. A
// renamed copy is NOT covered, because Ext(".htaccess.bak") is ".bak", which is
// right: no web server reads that file as configuration.
const extHTAccess = ".htaccess"

// jsExts are the JavaScript forms a site actually serves.
var jsExts = []string{".js", ".mjs", ".cjs"}

// phpExts are the extensions a PHP-FPM pool will execute. This is the ONE list:
// phpish reads it, the read limits read it, and every PHP rule is scoped to it,
// so a new extension cannot be honoured in one place and missed in another.
var phpExts = []string{
	".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".phar", ".inc", ".pht",
}

// Weight tiers, named so a rule's score reads as a claim about evidence rather
// than as a number somebody picked.
const (
	// weightProof: no realistic legitimate counterpart. One is enough.
	weightProof = 100
	// weightStrong: strong evidence; a second signal makes it critical.
	weightStrong = 60
	// weightModerate: two of these clear the suspicious threshold.
	weightModerate = 40
	// weightWeak: never sufficient alone, and never sufficient with one other
	// weak signal either.
	weightWeak = 20
)

// rule is one heuristic pattern and what a match is worth.
type rule struct {
	name  string
	score int
	re    *regexp.Regexp
	// exts limits the rule to these lowercase extensions. Empty means every
	// file the walk opens. A PHP pattern tried against every JavaScript bundle
	// on a site is cost with no possible finding, and an .htaccess pattern
	// tried against PHP is the same in reverse.
	exts []string
}

// heuristics are the PHP webshell, obfuscation and evasion patterns.
//
// The first seven predate the weighing and each one already wrote a finding on
// its own, so all seven keep a weight at the critical threshold: giving any of
// them less would quietly stop reporting an infection the panel has been
// reporting, and nothing else in the tree would notice.
//
// Every weight below was measured against WordPress core plus the five
// most-installed plugins, 8536 real PHP files. The whole set reports NOTHING on
// that corpus, which is the property that makes the evidence tiers usable at
// all.
var heuristics = buildHeuristics()

// buildHeuristics scopes every PHP pattern to the PHP extensions and appends
// the rules that name their own kind.
//
// The scoping is not an optimisation. A PHP pattern tried against JavaScript
// can match: a bundle carrying the string $_POST[ inside a template reaches
// PHP.Webshell.VariableFunction, and the finding would name a file PHP never
// executes. Writing phpExts into 22 literals by hand is how one of them ends up
// missing it.
func buildHeuristics() []rule {
	out := make([]rule, 0, len(phpHeuristics)+len(otherHeuristics))
	for _, r := range phpHeuristics {
		r.exts = phpExts
		out = append(out, r)
	}
	return append(out, otherHeuristics...)
}

var phpHeuristics = []rule{
	{"PHP.Webshell.EvalBase64", weightProof, regexp.MustCompile(`(?i)eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode)\s*\(`), nil},
	{"PHP.Webshell.PregReplaceE", weightProof, regexp.MustCompile(`(?i)preg_replace\s*\(\s*['"][^'"]{0,200}/e['"]`), nil},
	{"PHP.Webshell.AssertInput", weightProof, regexp.MustCompile(`(?i)assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`), nil},
	{"PHP.Webshell.SystemInput", weightProof, regexp.MustCompile(`(?i)(shell_exec|passthru|system|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)`), nil},
	{"PHP.Webshell.KnownMarker", weightProof, regexp.MustCompile(`(?i)(c99shell|r57shell|b374k|wso[_ ]?shell|filesman|indoxploit|angelshell|priv8|mini\s*shell)`), nil},
	{"PHP.Obf.CreateFunc", weightProof, regexp.MustCompile(`(?i)create_function\s*\([^)]*base64_decode`), nil},
	{"PHP.Obf.CharObfEval", weightProof, regexp.MustCompile(`(?i)\$\{?['"]?\w+['"]?\}?\s*\(\s*\$\{?['"]?\w+['"]?\}?\s*\)\s*;.*base64`), nil},

	// Request data reaching execution directly. Nothing legitimate hands a
	// superglobal to eval, to a variable function, or to a remote include.
	{"PHP.Webshell.EvalSuperglobal", weightProof, regexp.MustCompile(`(?i)eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[`), nil},
	{"PHP.Webshell.VariableFunction", weightProof, regexp.MustCompile(`\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[`), nil},
	{"PHP.Webshell.RemoteInclude", weightProof, regexp.MustCompile(`(?i)(include|require)(_once)?\s*\(?\s*['"]https?://`), nil},
	{"PHP.Webshell.RemoteFetchEval", weightProof, regexp.MustCompile(`(?i)eval\s*\(\s*(file_get_contents|curl_exec)\s*\(`), nil},
	{"PHP.Webshell.MoveUploadedPHP", weightProof, regexp.MustCompile(`(?i)move_uploaded_file\s*\([^)]*\.ph(p|tml|ar)`), nil},
	{"PHP.Webshell.PasswordGate", weightProof, regexp.MustCompile(`(?i)\$(pass|password|pwd)\s*=\s*['"][0-9a-f]{32}['"]\s*;.{0,200}(md5|hash)\s*\(\s*\$_`), nil},

	// The backtick operator with request data. The pattern requires the
	// expression to be USED, because a bare backtick statement inside a PHPDoc
	// line is how WordPress core documents its own superglobals: measured
	// against core plus the five most-installed plugins, matching a same-line
	// backtick pair alone reported 11 clean files and matching across lines
	// reported 184, wp-admin/admin.php among them. Requiring an assignment or
	// an output keyword reports none of them and still catches every shape an
	// attacker can use, since a webshell has to READ the command's output.
	{"PHP.Webshell.BacktickInput", weightProof, regexp.MustCompile("(?i)(=|\\(|,|\\breturn\\b|\\becho\\b|\\bprint\\b)\\s*`[^`\\r\\n]*\\$_(GET|POST|REQUEST|COOKIE)\\s*\\[[^`\\r\\n]*`"), nil},

	// Obfuscation and evasion. None of these is a verdict on its own: a real
	// plugin builds a string from chr(), suppresses an error and reads a user
	// agent, so each is evidence that needs a second signal.
	{"PHP.Obf.ChrChain", weightStrong, regexp.MustCompile(`(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}`), nil},
	{"PHP.Obf.GzinflateBase64", weightStrong, regexp.MustCompile(`(?i)gzinflate\s*\(\s*base64_decode\s*\(`), nil},
	{"PHP.Evasion.CreateFunction", weightStrong, regexp.MustCompile(`(?i)create_function\s*\(\s*['"]`), nil},
	{"PHP.Evasion.DisableIniGuard", weightStrong, regexp.MustCompile(`(?i)ini_set\s*\(\s*['"](disable_functions|open_basedir|safe_mode)['"]`), nil},
	{"PHP.Evasion.ErrorSuppressedExec", weightModerate, regexp.MustCompile(`@\s*(eval|system|shell_exec|assert)\s*\(`), nil},
	{"PHP.Evasion.BotCloaking", weightModerate, regexp.MustCompile(`(?i)\$_SERVER\s*\[\s*['"]HTTP_USER_AGENT['"]\s*\][^;]{0,80}(googlebot|bingbot|yandex)`), nil},

	// A long escaped or encoded blob. Weak on purpose: a cipher implementation
	// is a table of \x bytes and an embedded icon is a base64 block, so both
	// shapes occur in code nobody should be told about. Measured, the escaped
	// form matches 27 of 8536 clean files (phpseclib's DES tables among them),
	// which is why upstream's weight of 60, enough to report on its own, is not
	// carried over.
	{"PHP.Obf.HexEscapedName", weightWeak, regexp.MustCompile(`["'](?:\\x[0-9a-fA-F]{2}){5,}["']`), nil},
	{"PHP.Obf.LongBase64Block", weightWeak, regexp.MustCompile(`["'][A-Za-z0-9+/]{500,}={0,2}["']`), nil},
}

// otherHeuristics name the file kind they apply to, because it is not PHP.
var otherHeuristics = []rule{
	// Persistence through the web server's own configuration. Telling Apache to
	// run .jpg through the PHP handler turns an image upload into code
	// execution, and nothing legitimate asks for it.
	{"HTAccess.PHPHandlerInjection", weightProof,
		regexp.MustCompile(`(?i)(AddType|AddHandler)\s+[^\s]*php[^\s]*\s+\.(jpg|jpeg|png|gif|txt|ico|pdf|zip)`),
		[]string{extHTAccess}},

	// Injected JavaScript. These reach a visitor's browser rather than the
	// server, so they are how a defaced or ad-injecting site is found.
	{"JS.EvalFromCharCode", weightProof,
		regexp.MustCompile(`(?i)eval\s*\(\s*String\.fromCharCode\s*\(`), jsExts},
	{"JS.DocumentWriteUnescape", weightStrong,
		regexp.MustCompile(`(?i)document\.write\s*\(\s*unescape\s*\(`), jsExts},
}

// appliesTo says whether a rule is tried against a file of this extension.
func appliesTo(h rule, ext string) bool {
	if len(h.exts) == 0 {
		return true
	}
	return slices.Contains(h.exts, ext)
}

// levelFor maps a total score to a verdict. An empty level means the score did
// not reach the reporting threshold and no finding is written.
func levelFor(score int) string {
	switch {
	case score >= scoreCritical:
		return LevelCritical
	case score >= scoreSuspicious:
		return LevelSuspicious
	default:
		return ""
	}
}

// match is one rule that fired, whether it read the file or only its path.
type match struct {
	name  string
	score int
}

// evaluate weighs one file's content against the rule set and the signals that
// are not patterns.
func evaluate(ext string, content []byte) []match {
	return append(evaluateWith(heuristics, ext, content), entropyMatches(ext, content)...)
}

// evaluateWith is the same weighing against an explicit set, so a test can
// exercise the thresholds with rules at every tier. The shipped set carries no
// rule below the critical weight that also matches a one-line sample, which
// cannot demonstrate that a moderate rule alone produces nothing.
func evaluateWith(rules []rule, ext string, content []byte) []match {
	var out []match
	for _, h := range rules {
		if !appliesTo(h, ext) {
			continue
		}
		if h.re.Match(content) {
			out = append(out, match{h.name, h.score})
		}
	}
	return out
}

// verdict folds every match into one result.
//
// The signature is the name of the HIGHEST-scoring match, because the screen
// groups by it and a joined list groups by nothing. Ties keep the earlier
// match, which is stable because both sources iterate fixed slices. The full
// list travels beside it so an operator can see every reason. An empty level
// means the total did not reach the reporting threshold and no row is written.
func verdict(matches []match) (score int, signature string, names []string, level string) {
	best := 0
	for _, m := range matches {
		score += m.score
		names = append(names, m.name)
		if m.score > best {
			best, signature = m.score, m.name
		}
	}
	return score, signature, names, levelFor(score)
}
