package antivirus

// A dangerous function name split across string concatenation is invisible to
// every pattern in the set, because the name never appears in the file:
//
//	$d = <<<EOT
//	<base64 payload>
//	EOT;
//	$f = 'base'.'64_decode';
//	$g = 'ev'.'al';
//	$g($f($d));
//
// That is a complete, working webshell. `PHP.Obf.LongBase64Block` sees the blob
// and weighs it as the weak evidence it is, but nothing sees the execution, so
// the file scores 20 and is never reported. Removing the concatenation and
// reading the result again is the only thing that sees it.
//
// The rule fires only on a name that appears AFTER stripping and NOT before, so
// it is about the CONCEALMENT rather than the call. A file that plainly calls
// `eval` is judged by the ordinary rules and is not counted twice here.
//
// It carries the full weight because there is no legitimate reason to rebuild
// `eval` or `system` from pieces. Measured across WordPress core plus the five
// most-installed plugins, 8536 real PHP files, NOT ONE contains a concealed
// name, while every split form measured fires: two-part, per-character,
// double-quoted, spaced, and an inline `('sys'.'tem')(...)` call.

import (
	"bytes"
	"regexp"
)

// concatJoin matches the seam between two quoted literals. The whitespace is
// permissive on purpose: `'ev' . 'al'` split across a line break is still one
// name to PHP.
var concatJoin = regexp.MustCompile(`['"]\s*\.\s*['"]`)

// dangerousNames are the functions worth concealing. Names a normal file uses
// constantly, such as `preg_replace` or `file_put_contents`, are deliberately
// absent: the rule already requires concealment, and a wider list only widens
// what an accidental join can produce.
var dangerousNames = regexp.MustCompile(`(?i)\b(eval|assert|system|shell_exec|passthru|proc_open|popen|base64_decode|gzinflate|gzuncompress|str_rot13|create_function|move_uploaded_file)\b`)

// concealedMatches reports a dangerous name rebuilt from string concatenation.
func concealedMatches(ext string, content []byte) []match {
	if !phpish(ext) {
		return nil
	}
	// Most files never join two literals, and the strip below copies the whole
	// file, so this cheap test comes first.
	if !concatJoin.Match(content) {
		return nil
	}
	joined := concatJoin.ReplaceAll(content, nil)
	found := dangerousNames.FindAll(joined, -1)
	if len(found) == 0 {
		return nil
	}
	lowerRaw := bytes.ToLower(content)
	for _, name := range found {
		if !bytes.Contains(lowerRaw, bytes.ToLower(name)) {
			return []match{{"PHP.Obf.ConcealedFunctionName", weightProof}}
		}
	}
	return nil
}
