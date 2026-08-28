package antivirus

import (
	"strings"
	"testing"
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

// An exponential variable-doubling concatenation must be bounded, not blow
// memory or hang. The fold ceiling makes it finite.
func TestSemanticBillionLaughs(t *testing.T) {
	var b strings.Builder
	b.WriteString("<?php $a='xxxxxxxx';")
	vars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"
	for k := 1; k < len(vars); k++ {
		b.WriteByte('$')
		b.WriteByte(vars[k])
		b.WriteString("=$")
		b.WriteByte(vars[k-1])
		b.WriteString(".$")
		b.WriteByte(vars[k-1])
		b.WriteByte(';')
	}
	semScore(b.String()) // must return in reasonable time without OOM or panic
}

// A very long concatenation must stay within the token budget.
func TestSemanticDoSBudget(t *testing.T) {
	var b strings.Builder
	b.WriteString("<?php $x = ")
	for range 50000 {
		b.WriteString("'a'.")
	}
	b.WriteString("'b';")
	semScore(b.String())
}
