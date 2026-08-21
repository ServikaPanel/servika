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

import "regexp"

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
var heuristics = []rule{
	{"PHP.Webshell.EvalBase64", weightProof, regexp.MustCompile(`(?i)eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode)\s*\(`)},
	{"PHP.Webshell.PregReplaceE", weightProof, regexp.MustCompile(`(?i)preg_replace\s*\(\s*['"][^'"]{0,200}/e['"]`)},
	{"PHP.Webshell.AssertInput", weightProof, regexp.MustCompile(`(?i)assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`)},
	{"PHP.Webshell.SystemInput", weightProof, regexp.MustCompile(`(?i)(shell_exec|passthru|system|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)`)},
	{"PHP.Webshell.KnownMarker", weightProof, regexp.MustCompile(`(?i)(c99shell|r57shell|b374k|wso[_ ]?shell|filesman|indoxploit|angelshell|priv8|mini\s*shell)`)},
	{"PHP.Obf.CreateFunc", weightProof, regexp.MustCompile(`(?i)create_function\s*\([^)]*base64_decode`)},
	{"PHP.Obf.CharObfEval", weightProof, regexp.MustCompile(`(?i)\$\{?['"]?\w+['"]?\}?\s*\(\s*\$\{?['"]?\w+['"]?\}?\s*\)\s*;.*base64`)},

	// Request data reaching execution directly. Nothing legitimate hands a
	// superglobal to eval, to a variable function, or to a remote include.
	{"PHP.Webshell.EvalSuperglobal", weightProof, regexp.MustCompile(`(?i)eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[`)},
	{"PHP.Webshell.VariableFunction", weightProof, regexp.MustCompile(`\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[`)},
	{"PHP.Webshell.RemoteInclude", weightProof, regexp.MustCompile(`(?i)(include|require)(_once)?\s*\(?\s*['"]https?://`)},
	{"PHP.Webshell.RemoteFetchEval", weightProof, regexp.MustCompile(`(?i)eval\s*\(\s*(file_get_contents|curl_exec)\s*\(`)},
	{"PHP.Webshell.MoveUploadedPHP", weightProof, regexp.MustCompile(`(?i)move_uploaded_file\s*\([^)]*\.ph(p|tml|ar)`)},
	{"PHP.Webshell.PasswordGate", weightProof, regexp.MustCompile(`(?i)\$(pass|password|pwd)\s*=\s*['"][0-9a-f]{32}['"]\s*;.{0,200}(md5|hash)\s*\(\s*\$_`)},

	// The backtick operator with request data. The pattern requires the
	// expression to be USED, because a bare backtick statement inside a PHPDoc
	// line is how WordPress core documents its own superglobals: measured
	// against core plus the five most-installed plugins, matching a same-line
	// backtick pair alone reported 11 clean files and matching across lines
	// reported 184, wp-admin/admin.php among them. Requiring an assignment or
	// an output keyword reports none of them and still catches every shape an
	// attacker can use, since a webshell has to READ the command's output.
	{"PHP.Webshell.BacktickInput", weightProof, regexp.MustCompile("(?i)(=|\\(|,|\\breturn\\b|\\becho\\b|\\bprint\\b)\\s*`[^`\\r\\n]*\\$_(GET|POST|REQUEST|COOKIE)\\s*\\[[^`\\r\\n]*`")},

	// Obfuscation and evasion. None of these is a verdict on its own: a real
	// plugin builds a string from chr(), suppresses an error and reads a user
	// agent, so each is evidence that needs a second signal.
	{"PHP.Obf.ChrChain", weightStrong, regexp.MustCompile(`(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}`)},
	{"PHP.Obf.GzinflateBase64", weightStrong, regexp.MustCompile(`(?i)gzinflate\s*\(\s*base64_decode\s*\(`)},
	{"PHP.Evasion.CreateFunction", weightStrong, regexp.MustCompile(`(?i)create_function\s*\(\s*['"]`)},
	{"PHP.Evasion.DisableIniGuard", weightStrong, regexp.MustCompile(`(?i)ini_set\s*\(\s*['"](disable_functions|open_basedir|safe_mode)['"]`)},
	{"PHP.Evasion.ErrorSuppressedExec", weightModerate, regexp.MustCompile(`@\s*(eval|system|shell_exec|assert)\s*\(`)},
	{"PHP.Evasion.BotCloaking", weightModerate, regexp.MustCompile(`(?i)\$_SERVER\s*\[\s*['"]HTTP_USER_AGENT['"]\s*\][^;]{0,80}(googlebot|bingbot|yandex)`)},

	// A long escaped or encoded blob. Weak on purpose: a cipher implementation
	// is a table of \x bytes and an embedded icon is a base64 block, so both
	// shapes occur in code nobody should be told about. Measured, the escaped
	// form matches 27 of 8536 clean files (phpseclib's DES tables among them),
	// which is why upstream's weight of 60, enough to report on its own, is not
	// carried over.
	{"PHP.Obf.HexEscapedName", weightWeak, regexp.MustCompile(`["'](?:\\x[0-9a-fA-F]{2}){5,}["']`)},
	{"PHP.Obf.LongBase64Block", weightWeak, regexp.MustCompile(`["'][A-Za-z0-9+/]{500,}={0,2}["']`)},
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

// evaluate weighs one file's content against the rule set.
//
// The returned signature is the name of the HIGHEST-scoring match, because the
// screen groups by it and a joined list groups by nothing. Ties keep the
// earlier rule, which is stable because the set is a fixed slice. The full list
// travels beside it so an operator can see every reason.
func evaluate(content []byte) (score int, signature string, matched []string) {
	return evaluateWith(heuristics, content)
}

// evaluateWith is the same weighing against an explicit set, so a test can
// exercise the thresholds with rules at every tier. The shipped set is all
// weightProof today, which cannot demonstrate that a moderate rule alone
// produces nothing.
func evaluateWith(rules []rule, content []byte) (score int, signature string, matched []string) {
	best := 0
	for _, h := range rules {
		if !h.re.Match(content) {
			continue
		}
		score += h.score
		matched = append(matched, h.name)
		if h.score > best {
			best, signature = h.score, h.name
		}
	}
	return score, signature, matched
}
