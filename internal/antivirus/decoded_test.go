package antivirus

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"strings"
	"testing"
)

// A webshell hidden behind a decoder is invisible to the pattern set until the
// decode layer reads it. Each case below wraps a real payload in one of the
// encodings decoded.go follows, and asserts the inner rule fires as a Decoded:
// finding.

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// rawDeflate compresses s with raw DEFLATE, which is what PHP's gzinflate reads.
func rawDeflate(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

// hasDecoded reports whether the matches carry a decoded finding for the named
// rule (without the Decoded: prefix), and that it is flagged decoded.
func hasDecoded(matches []match, ruleName string) bool {
	for _, m := range matches {
		if m.name == decodedPrefix+ruleName && m.decoded {
			return true
		}
	}
	return false
}

func TestABase64WebshellIsSeenThroughTheDecodeLayer(t *testing.T) {
	payload := `<?php eval($_POST['x']); ?>`
	file := []byte(`<?php $c = base64_decode('` + b64(payload) + `'); eval($c); ?>`)
	got := decodedMatches(".php", file)
	if !hasDecoded(got, "PHP.Webshell.EvalSuperglobal") {
		t.Fatalf("base64 payload not caught through decode: %+v", got)
	}
}

func TestAGzinflateBase64WebshellIsSeenThroughTheDecodeLayer(t *testing.T) {
	payload := `<?php system($_GET['cmd']); ?>`
	blob := base64.StdEncoding.EncodeToString(rawDeflate(t, payload))
	file := []byte(`<?php eval(gzinflate(base64_decode('` + blob + `'))); ?>`)
	got := decodedMatches(".php", file)
	if !hasDecoded(got, "PHP.Webshell.SystemInput") {
		t.Fatalf("gzinflate+base64 payload not caught through decode: %+v", got)
	}
}

func TestARot13WebshellIsSeenThroughTheDecodeLayer(t *testing.T) {
	payload := `eval($_REQUEST['x']);`
	// str_rot13 of the payload; decoded.go rot13s the whole file back to clear.
	file := []byte(`<?php $c = str_rot13('` + rot13Str(payload) + `'); ?>`)
	got := decodedMatches(".php", file)
	if !hasDecoded(got, "PHP.Webshell.EvalSuperglobal") {
		t.Fatalf("rot13 payload not caught through decode: %+v", got)
	}
}

// rot13Str is the test's own encoder, independent of the package's rot13 which
// works on bytes and returns nil for letter-free input.
func rot13Str(s string) string {
	out := []byte(s)
	for i, c := range out {
		switch {
		case c >= 'a' && c <= 'z':
			out[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			out[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(out)
}

func TestACleanFileWithABase64AssetProducesNoDecodedFinding(t *testing.T) {
	// A base64 blob that decodes to ordinary text, the shape of a legitimate
	// embedded asset. Nothing dangerous is inside, so nothing fires.
	asset := b64(strings.Repeat("the quick brown fox jumps over the lazy dog. ", 20))
	file := []byte(`<?php $logo = '` + asset + `'; echo base64_decode($logo); ?>`)
	if got := decodedMatches(".php", file); len(got) != 0 {
		t.Fatalf("clean base64 asset produced a decoded finding: %+v", got)
	}
}

func TestNormalCodeWithNoEncodedBlobProducesNoDecodedFinding(t *testing.T) {
	file := []byte("<?php\nfunction add($a, $b) { return $a + $b; }\necho add(1, 2);\n")
	if got := decodedMatches(".php", file); len(got) != 0 {
		t.Fatalf("normal code produced a decoded finding: %+v", got)
	}
}

func TestADecodedFileKindThatIsNotPHPIsNotDecoded(t *testing.T) {
	payload := `<?php eval($_POST['x']); ?>`
	file := []byte(`var c = atob('` + b64(payload) + `');`)
	if got := decodedMatches(".js", file); len(got) != 0 {
		t.Fatalf("a non-PHP file was decoded: %+v", got)
	}
}

// A decoded webshell match, on its own, must NOT reach the critical verdict that
// drives automatic containment: decoding produces bytes the rule set has never
// been measured against, so it is capped exactly like a remote rule.
func TestADecodedMatchAloneCannotConvictCritically(t *testing.T) {
	payload := `<?php eval($_POST['x']); ?>` // EvalSuperglobal, weightProof in clear
	file := []byte(`<?php $c = base64_decode('` + b64(payload) + `'); eval($c); ?>`)
	// Weigh ONLY the decoded matches, as if the outer eval() had not also fired.
	decoded := decodedMatches(".php", file)
	if len(decoded) == 0 {
		t.Fatalf("expected a decoded match to weigh")
	}
	_, _, _, level := verdict(decoded, scoreCritical)
	if level == LevelCritical {
		t.Fatalf("a decoded match alone reached critical: %+v", decoded)
	}
	if level != LevelSuspicious {
		t.Fatalf("expected suspicious from a decoded proof match, got %q", level)
	}
	// A WEAK in-clear shape rule beside it is NOT enough: LongBase64Block sees
	// the same blob the decode layer is built on, so it is the same evidence,
	// not corroboration.
	withWeakShape := append(decoded, match{name: "PHP.Obf.LongBase64Block", score: weightWeak})
	if _, _, _, l := verdict(withWeakShape, scoreCritical); l == LevelCritical {
		t.Fatalf("a decoded match plus a weak shape rule reached critical: %q", l)
	}
	// An in-clear BEHAVIOURAL match (weightModerate+) does convict.
	withBehavioural := append(decoded, match{name: "PHP.Webshell.EvalSuperglobal", score: weightProof})
	if _, _, _, l := verdict(withBehavioural, scoreCritical); l != LevelCritical {
		t.Fatalf("an in-clear behavioural match should convict, got %q", l)
	}
}

// A decode bomb must be bounded: a large, deeply nestable input returns within
// the budget rather than looping or exhausting memory. The assertion is that the
// call terminates at all; the test hangs the suite if the budget does not hold.
func TestTheDecodeBudgetBoundsTheWork(t *testing.T) {
	inner := strings.Repeat("QUFB", 4000) // valid base64 that decodes to more text
	file := []byte(`<?php $x = '` + inner + `'; ?>`)
	if got := decodedMatches(".php", file); len(got) != 0 {
		t.Fatalf("a benign blob produced a decoded finding: %+v", got)
	}
}
