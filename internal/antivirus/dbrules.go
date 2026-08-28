package antivirus

// What counts as malware inside a WordPress database value.
//
// These are a SEPARATE set from the file heuristics, weighed by the same
// thresholds. The file rules were measured against 8536 real PHP source files;
// a WordPress option value is not PHP source, so a rule calibrated on one is
// not evidence about the other. Two consequences follow, and both are
// deliberate.
//
// The entropy, taint and concealed-name passes are NOT run here. Every one of
// them was calibrated on PHP source: the entropy threshold of 5.9 sits above a
// measured clean maximum of 5.776 across PHP FILES, and a serialized option
// value is a different distribution entirely. Running them unmeasured would
// invent findings on working sites, which is the failure the weighing model
// exists to avoid.
//
// The bar is set so that a single moderate signal never convicts. A page
// builder legitimately stores PHP snippets, a theme legitimately stores an
// analytics script, and an SEO plugin legitimately stores base64 in an option.
// Each of those is one moderate signal, 40, below scoreSuspicious. It takes two
// independent signals, or one with no legitimate counterpart, to be reported.

import "regexp"

// extDatabase and extPost are the pseudo-extensions these rules are scoped to.
// Neither can collide with a real file: the walk lowercases a real extension and
// every real one begins with a dot.
//
// A POST value is a third distribution again, and the same argument that
// separates this file from the source rules separates the two of these. An
// option value is serialized configuration that WordPress loads on every
// request; post content is HTML rendered in a browser, and the PHP function
// names in it are the subject somebody is writing ABOUT. Measured against seven
// realistic post bodies, all of which pass postPrefilter and are therefore read:
// four produced findings and two were critical, including a post explaining that
// backdoors hide a payload with base64_decode() and run it with eval(). A
// WordPress blog about PHP security is exactly the site a hosting customer runs.
const (
	extDatabase = "<database>"
	extPost     = "<database-post>"
)

// postApplicable names the rules that also judge post content.
//
// Each of these requires a CONSTRUCT with no prose counterpart: request data
// adjacent to a sink, a decoder adjacent to eval, or a <script> carrying a
// decoder. Everything else in the set below is a bare PHP function NAME, and a
// name in prose is what a blog about PHP is made of. Measured on the same
// corpora, this scoping reports none of the seven prose bodies and still reports
// all five real injections as critical.
//
// The dividing line is NOT the weight. DB.Webshell.FilesMan and
// DB.Webshell.PregReplaceE are weightProof and still bare-name shaped: the
// second convicted a post explaining that PHP 7 removed the /e modifier.
var postApplicable = map[string]bool{
	"DB.Webshell.EvalDecoder":      true,
	"DB.Webshell.AssertInput":      true,
	"DB.Webshell.SystemInput":      true,
	"DB.Injected.ObfuscatedScript": true,
}

// dbHeuristics is the weighed rule set for a value read out of a tenant's
// WordPress tables.
var dbHeuristics = buildDatabaseHeuristics()

func buildDatabaseHeuristics() []rule {
	out := make([]rule, 0, len(databaseRules))
	for _, r := range databaseRules {
		r.exts = []string{extDatabase}
		if postApplicable[r.name] {
			r.exts = append(r.exts, extPost)
		}
		out = append(out, r)
	}
	return out
}

var databaseRules = []rule{
	// Proof. A stored value that executes a decoded payload has no legitimate
	// counterpart: WordPress never evaluates an option value, so anything that
	// arranges for one to be evaluated was put there to be run.
	{"DB.Webshell.EvalDecoder", weightProof,
		regexp.MustCompile(`(?i)eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|convert_uudecode|pack)\s*\(`), nil},
	{"DB.Webshell.AssertInput", weightProof,
		regexp.MustCompile(`(?i)assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`), nil},
	{"DB.Webshell.SystemInput", weightProof,
		regexp.MustCompile(`(?i)(shell_exec|passthru|system|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)`), nil},
	{"DB.Webshell.PregReplaceE", weightProof,
		regexp.MustCompile(`(?i)preg_replace\s*\(\s*['"][^'"]{0,200}/e['"]`), nil},
	// An injected script that decodes its own body. A plain <script> is not
	// enough and never will be: a theme option holding an analytics snippet is
	// the ordinary case, and reporting it would report every configured site.
	// What makes this one evidence is the decoder INSIDE the script.
	{"DB.Injected.ObfuscatedScript", weightProof,
		regexp.MustCompile(`(?i)<script[^>]*>[^<]{0,400}?(eval|unescape|fromCharCode|atob)\s*\(`), nil},
	// FilesMan is the banner of a widely distributed PHP file manager shell. It
	// is a name, not a technique, so nothing legitimate carries it.
	{"DB.Webshell.FilesMan", weightProof,
		regexp.MustCompile(`FilesMan`), nil},

	// Strong. Execution with no visible decoder: one more signal convicts.
	{"DB.Exec.Eval", weightStrong,
		regexp.MustCompile(`(?i)\beval\s*\(`), nil},
	{"DB.Exec.CreateFunction", weightStrong,
		regexp.MustCompile(`(?i)\bcreate_function\s*\(`), nil},

	// Moderate. Each has a legitimate counterpart in a stored value, so none
	// convicts alone; two of them do.
	{"DB.Obf.Decoder", weightModerate,
		regexp.MustCompile(`(?i)\b(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode)\s*\(`), nil},
	{"DB.Exec.Shell", weightModerate,
		regexp.MustCompile(`(?i)\b(shell_exec|passthru|proc_open|popen)\s*\(`), nil},
	{"DB.Exec.FileWrite", weightModerate,
		regexp.MustCompile(`(?i)\b(move_uploaded_file|file_put_contents)\s*\(`), nil},
	// A remote include reached from a stored value. http:// alone is every
	// option that holds a URL, so the include is what carries the signal. The
	// trailing [^'"\s] requires a real host, so a post that merely writes about
	// includes ("do not include \"http://\" links") is not a match.
	{"DB.Include.Remote", weightModerate,
		regexp.MustCompile(`(?i)\b(include|require)(_once)?\s*\(?\s*['"]https?://[^'"\s]`), nil},
}

// evaluateDatabaseValue weighs one stored value.
//
// It runs the pattern pass ALONE, for the reason in this file's header. Remote
// packaged rules are not applied either: every one of them was written against
// file content and declares a file kind, so a package cannot reach this set.
func evaluateDatabaseValue(value string) []match {
	return evaluateWith(dbHeuristics, extDatabase, []byte(value))
}

// evaluateDatabasePost weighs one post body, which is the narrower set.
//
// It is a separate function rather than a parameter so the two callers in
// dbscan.go say which distribution they are judging at the call site: a rule set
// applied to the wrong kind of content is the defect this exists to prevent, and
// it is silent in both directions.
func evaluateDatabasePost(value string) []match {
	return evaluateWith(dbHeuristics, extPost, []byte(value))
}

// dbValueLimit bounds how much of one value is weighed.
//
// A WordPress option can hold a serialized array of any size, and a rule
// applied to a megabyte of it costs the scan for no gain: an injected payload
// sits at the head or the tail of a value exactly as it does in a file. The
// same head-and-tail reading the file scan uses would need its own seam rule,
// so this takes the head only and the value's SIZE is not a gate: a value past
// the limit is still weighed on its first 256 KiB rather than skipped.
const dbValueLimit = 256 << 10

// clampValue returns at most dbValueLimit bytes of a stored value.
func clampValue(value string) string {
	if len(value) > dbValueLimit {
		return value[:dbValueLimit]
	}
	return value
}
