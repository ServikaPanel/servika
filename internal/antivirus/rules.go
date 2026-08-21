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

// heuristics are low false-positive PHP webshell and obfuscation patterns.
//
// Every entry here carries weightProof, because these are the rules that
// predate the weighing and each one already wrote a finding on its own. Giving
// them anything less would quietly downgrade findings the panel has been
// reporting as infections.
var heuristics = []rule{
	{"PHP.Webshell.EvalBase64", weightProof, regexp.MustCompile(`(?i)eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode)\s*\(`)},
	{"PHP.Webshell.PregReplaceE", weightProof, regexp.MustCompile(`(?i)preg_replace\s*\(\s*['"][^'"]{0,200}/e['"]`)},
	{"PHP.Webshell.AssertInput", weightProof, regexp.MustCompile(`(?i)assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`)},
	{"PHP.Webshell.SystemInput", weightProof, regexp.MustCompile(`(?i)(shell_exec|passthru|system|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)`)},
	{"PHP.Webshell.KnownMarker", weightProof, regexp.MustCompile(`(?i)(c99shell|r57shell|b374k|wso[_ ]?shell|filesman|indoxploit|angelshell|priv8|mini\s*shell)`)},
	{"PHP.Obf.CreateFunc", weightProof, regexp.MustCompile(`(?i)create_function\s*\([^)]*base64_decode`)},
	{"PHP.Obf.CharObfEval", weightProof, regexp.MustCompile(`(?i)\$\{?['"]?\w+['"]?\}?\s*\(\s*\$\{?['"]?\w+['"]?\}?\s*\)\s*;.*base64`)},
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
