package antivirus

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// semScore runs the semantic layer over a PHP snippet and returns the total
// score and the match names. clearNames is empty: these tests exercise the layer
// in isolation, not the full evaluate() pipeline.
func semScore(src string) (int, []string) {
	matches := semanticMatches(".php", []byte(src), map[string]bool{})
	total := 0
	var names []string
	for _, m := range matches {
		total += m.score
		names = append(names, m.name)
	}
	return total, names
}

func nameContains(names []string, sub string) bool {
	for _, n := range names {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// The evasions the layer must catch. Each names a shape a regular expression
// cannot express: a concatenated sink name, a variable function, a callable
// superglobal, or reconstructed eval'd code.
func TestSemanticCatchesObfuscatedSinks(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"concat-sink-assign", `<?php $f = 'sy'.'st'.'em'; $f('id');`, "ConcatenatedSink"},
		{"paren-concat-call", `<?php ('sy'.'stem')('whoami');`, "ConcatenatedSink"},
		{"varfunc-sink", `<?php $x = 'system'; $x($_GET['c']);`, "VariableSinkCall"},
		{"superglobal-call", `<?php $_GET['f']($_GET['a']);`, "SuperglobalCall"},
		{"taint-call", `<?php $cb = $_POST['x']; $cb('arg');`, "TaintedNameCall"},
		{"eval-concat-var", `<?php $c = 'ph'.'pinfo()'; eval($c);`, "EvalConcat"},
		{"eval-direct-concat", `<?php eval('sys'.'tem'.'("x")');`, "EvalConcat"},
		{"assert-direct-concat", `<?php assert('sys'.'tem'.'("x")');`, "EvalConcat"},
		// A structural call wrapped in an assignment does not escape: the
		// right-hand side is re-walked by the main loop.
		{"assign-wrapped-superglobal", `<?php $x = $_GET['f']($_GET['a']);`, "SuperglobalCall"},
		{"assign-wrapped-varfunc", `<?php $g='system'; $x = $g($_GET['a']);`, "VariableSinkCall"},
		// Transitive concatenation across several assignments (concealed.go, which
		// only folds inline literal concat, cannot cross the variable boundary).
		{"transitive-concat", `<?php $a='sy'; $b='stem'; $c=$a.$b; $c('x');`, "ConcatenatedSink"},
		// Compound concatenation `$c .= ...`.
		{"compound-concat", `<?php $c='sy'; $c.='stem'; $c($_GET['x']);`, "ConcatenatedSink"},
		// A hex-hidden sink name resolved through double-quote escapes.
		{"hex-escape-sink", `<?php $f = "\x73\x79\x73\x74\x65\x6d"; $f($_GET['c']);`, "VariableSinkCall"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			score, names := semScore(c.src)
			if score <= 0 || !nameContains(names, c.want) {
				t.Errorf("score=%d names=%v, want a %q match", score, names, c.want)
			}
		})
	}
}

// The concat rescan runs the shipped heuristics against reconstructed eval'd
// code. A payload assembled from pieces so the literal file never carries the
// contiguous marker fires only after folding, and the rescan names the shipped
// rule it reconstructed.
func TestSemanticRescanReconstructsAShippedRule(t *testing.T) {
	// The literal bytes hold `'c99'.'shell'`, which KnownMarker does not match;
	// the folded eval'd code is `c99shell`, which it does.
	score, names := semScore(`<?php $c = 'c99'.'shell'; eval($c);`)
	if !nameContains(names, semanticRescanPrefix) {
		t.Fatalf("the rescan did not reconstruct the marker: names=%v", names)
	}
	if score < weightProof {
		t.Fatalf("score=%d, want the EvalConcat proof beside the rescan", score)
	}
}

// The rescan can never convict on its own: its combined contribution is capped
// below the critical threshold, so a rescan match beside the EvalConcat proof
// never inflates the file past a single measured signal's worth.
func TestSemanticRescanIsCapped(t *testing.T) {
	_, names := semScore(`<?php $c = 'c99'.'shell'; eval($c);`)
	rescanScore := 0
	for _, m := range semanticMatches(".php", []byte(`<?php $c = 'c99'.'shell'; eval($c);`), map[string]bool{}) {
		if strings.HasPrefix(m.name, semanticRescanPrefix) {
			rescanScore += m.score
		}
	}
	if rescanScore > semRescanCap {
		t.Fatalf("rescan contributed %d, want <= %d (cap)", rescanScore, semRescanCap)
	}
	if rescanScore >= scoreCritical {
		t.Fatalf("a rescan match reached %d, the critical threshold; it must not convict alone", rescanScore)
	}
	_ = names
}

// The clean shapes the layer must NOT report. Benign concatenation, a benign
// variable function, WordPress hook registration, SQL building, and dynamic
// METHOD dispatch (`$this->$action()`) are all legitimate.
func TestSemanticNoFalsePositives(t *testing.T) {
	clean := []struct{ name, src string }{
		{"harmless-concat", `<?php $msg = 'Hello ' . $name . ', welcome';`},
		{"benign-varfunc", `<?php $cb = 'strtolower'; echo $cb($x);`},
		{"wp-hook", `<?php $f = 'esc_html'; add_filter('t', $f);`},
		{"double-quote-interpolation", `<?php $q = "SELECT $a FROM t"; $r = $q;`},
		{"sql-concat", `<?php $sql = "SELECT * " . "FROM users " . "WHERE id=1";`},
		{"dot-outside-php", `<html><body>a.b.c 'quote' system( ) not php</body></html>`},
		{"benign-constant-fn", `<?php echo strtoupper('sys' . 'tem');`},
		{"array-map-callback", `<?php $r = array_map('trim', $arr);`},
		// The critical false positive class: dynamic method dispatch. A member
		// access (`->`/`?->`/`::`) is a method call, not arbitrary code.
		{"dynamic-method-taint", `<?php $action = $_REQUEST['action']; $this->$action();`},
		{"rest-method-dispatch", `<?php $m = $_SERVER['REQUEST_METHOD']; $this->$m();`},
		{"pdo-exec-method", `<?php $method = 'exec'; $db->$method($sql);`},
		{"static-method-dispatch", `<?php $cb = $_GET['x']; Foo::$cb();`},
		{"xml-declaration", `<?xml version="1.0"?><root>system('x')</root>`},
	}
	for _, c := range clean {
		t.Run(c.name, func(t *testing.T) {
			if score, names := semScore(c.src); score > 0 {
				t.Errorf("false positive: score=%d names=%v (want 0)", score, names)
			}
		})
	}
}

// Reassigning a sink variable to a safe name clears the earlier value, so the
// variable function does not fire.
func TestSemanticReassignmentClears(t *testing.T) {
	if score, names := semScore(`<?php $f='system'; $f='strtolower'; $f($x);`); score > 0 {
		t.Errorf("reassign: score=%d names=%v (want 0)", score, names)
	}
}

// A non-PHP extension is not scanned.
func TestSemanticPHPOnly(t *testing.T) {
	if len(semanticMatches(".txt", []byte(`<?php $f='sy'.'stem'; $f('x');`), map[string]bool{})) != 0 {
		t.Error("a non-PHP extension was scanned")
	}
}

// doublingChain builds `$a='xxxxxxxx'; $b=$a.$a; $c=$b.$b; ...`, whose folded
// value doubles with every statement. With n doublings the last value is
// 8 * 2^n bytes if nothing bounds the fold.
func doublingChain(n int) (source string, unboundedBytes int) {
	var b strings.Builder
	b.WriteString("<?php $a='xxxxxxxx';")
	vars := "abcdefghijklmnopqrstuvwxyz"
	for k := 1; k <= n; k++ {
		b.WriteByte('$')
		b.WriteByte(vars[k])
		b.WriteString("=$")
		b.WriteByte(vars[k-1])
		b.WriteString(".$")
		b.WriteByte(vars[k-1])
		b.WriteByte(';')
	}
	return b.String(), 8 << n
}

// allocatedBy reports how many bytes the call allocated in total.
func allocatedBy(call func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	call()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// An exponential variable-doubling concatenation must be bounded. semMaxFoldBytes
// is what makes it finite: the scan runs on attacker-authored PHP from a tenant's
// document root, so a file that folds to gigabytes takes the scan's whole memory
// budget with it.
//
// The chain is measured rather than merely run. Twenty-two doublings allocate
// about 0.5 MB with the ceiling in place and about 115 MB with it removed from
// both enforcement points (foldExpr and applyAssign), so the budget below
// separates the two by two orders of magnitude.
func TestSemanticBillionLaughs(t *testing.T) {
	source, unbounded := doublingChain(22)
	if unbounded <= semMaxFoldBytes {
		t.Fatalf("the chain folds to %d bytes, which the %d byte ceiling would not bound anyway",
			unbounded, semMaxFoldBytes)
	}

	var score int
	allocated := allocatedBy(func() { score, _ = semScore(source) })

	const budget = 16 << 20
	if allocated > budget {
		t.Errorf("the doubling chain allocated %d bytes, want at most %d: the fold ceiling did not bound it",
			allocated, budget)
	}
	if score != 0 {
		t.Errorf("a chain of harmless letters scored %d, want 0", score)
	}
}

// A very long concatenation must stay within the token budget. semMaxToken is
// what bounds the work: the tokenizer stops there, so a file made of nothing but
// concatenation terms cannot make the scan grow with the file.
func TestSemanticDoSBudget(t *testing.T) {
	const terms = 150000
	var b strings.Builder
	b.WriteString("<?php $x = ")
	for range terms {
		b.WriteString("'a'.")
	}
	b.WriteString("'b';")
	source := b.String()

	// Each term is a string token plus a dot, so the file carries far more
	// tokens than the cap. Without the cap this assertion is vacuous.
	if terms*2 <= semMaxToken {
		t.Fatalf("%d terms produce fewer tokens than the %d cap; the input no longer tests it",
			terms, semMaxToken)
	}
	if got := len(phpTokenize([]byte(source))); got > semMaxToken {
		t.Errorf("the tokenizer produced %d tokens, want at most %d", got, semMaxToken)
	}

	started := time.Now()
	score, names := semScore(source)
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Errorf("scanning %d terms took %s, which is not a bounded amount of work", terms, elapsed)
	}
	if score != 0 {
		t.Errorf("a concatenation of harmless letters scored %d (%v), want 0", score, names)
	}
}
