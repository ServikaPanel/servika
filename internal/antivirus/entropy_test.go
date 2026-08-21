package antivirus

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// payload builds an encoded blob of the shape a packed webshell carries.
func payload(t *testing.T, bytes int) string {
	t.Helper()
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// payloadOf encodes a known string, which is the shape a webshell carrying its
// own uncompressed source has.
func payloadOf(t *testing.T, body string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString([]byte(body))
}

// The alphabet rule and this one cover different halves of the same problem, so
// a change that makes one redundant should show up here. Every shape must be
// seen by at least one of them, and the last column asserts that.
func TestEveryBlobShapeIsSeenBySomething(t *testing.T) {
	blob := payload(t, 3000)
	plain := payloadOf(t, strings.Repeat("<?php function h($q){ return $q->all(); } ", 70))
	cases := []struct {
		name        string
		body        string
		wantEntropy bool
		wantPattern bool
	}{
		{"quoted, compressed", `<?php $d = '` + blob + `';`, true, true},
		{"quoted, plain source", `<?php $d = '` + plain + `';`, false, true},
		// A delimiter is not what makes a blob suspicious, so the heredoc and
		// nowdoc forms reach the alphabet rule exactly as the quoted one does.
		{"heredoc, compressed", "<?php $d = <<<EOT\n" + blob + "\nEOT;", true, true},
		{"heredoc, plain source", "<?php $d = <<<EOT\n" + plain + "\nEOT;", false, true},
		{"nowdoc, plain source", "<?php $d = <<<'EOT'\n" + plain + "\nEOT;", false, true},
		// Broken into pieces too short to be a run, so only density sees it.
		{"concatenated", `<?php $d = '` + blob[:400] + `' . '` + blob[400:800] + `' . '` + blob[800:1200] + `';`, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotEntropy := len(entropyMatches(".php", []byte(c.body))) > 0
			_, _, names, _ := verdict(evaluateWith(heuristics, ".php", []byte(c.body)), 0)
			gotPattern := strings.Contains(strings.Join(names, ","), "PHP.Obf.LongBase64Block")
			if gotEntropy != c.wantEntropy || gotPattern != c.wantPattern {
				t.Errorf("entropy=%v (want %v) pattern=%v (want %v), line entropy %.3f",
					gotEntropy, c.wantEntropy, gotPattern, c.wantPattern,
					highestLineEntropy([]byte(c.body)))
			}
			if !gotEntropy && !gotPattern {
				t.Error("no signal at all sees this shape")
			}
		})
	}
}

// The threshold has to sit above every clean file and below every payload, and
// both halves are held here. Without the second half the rule is dead weight;
// without the first it reports working sites.
func TestTheEntropyThresholdSeparatesPayloadsFromDenseCode(t *testing.T) {
	blob := payload(t, 3000)
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"base64 payload", `<?php eval(base64_decode('` + blob + `'));`, true},
		{"gzinflate payload", `<?php eval(gzinflate(base64_decode('` + blob[:2000] + `')));`, true},

		// The two shapes the quoted-run rule cannot see, which are the reason
		// this signal exists beside it.
		{"a payload in a heredoc", "<?php $d = <<<EOT\n" + blob + "\nEOT;", true},
		{"a payload split across concatenation", `<?php $d = '` + blob[:400] + `' . '` + blob[400:800] + `' . '` + blob[800:1200] + `';`, true},

		// The measured shapes of dense CLEAN PHP. A localisation table and a
		// long array literal are the two that came closest in the real corpus,
		// where the highest of 1307 files was 5.776.
		{"a long array of words", `<?php $m = array(` + strings.Repeat(`'monday'=>'Monday',`, 40) + `);`, false},
		{"a long line of ordinary code", `<?php ` + strings.Repeat(`$total = $total + $price * $quantity; `, 12), false},
		{"a hex byte table", `<?php $sbox = "` + strings.Repeat(`\x41\x42\x43\x44`, 60) + `";`, false},
		{"nothing long enough to judge", `<?php eval(base64_decode('` + blob[:100] + `'));`, false},
	}
	// What this signal does NOT reach, stated rather than hidden: base64 of
	// plain uncompressed source measures inside the range clean code occupies,
	// so no threshold gets to it. PHP.Obf.LongBase64Block covers that shape by
	// alphabet instead, whatever delimiter it carries.
	plainSource := payloadOf(t, strings.Repeat("<?php function h($q){ return $q->all(); } ", 70))
	cases = append(cases, struct {
		name string
		body string
		want bool
	}{"base64 of plain php source", `<?php $d = '` + plainSource + `';`, false})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := len(entropyMatches(".php", []byte(c.body))) > 0
			if got != c.want {
				t.Errorf("fired=%v want=%v (entropy %.3f, threshold %.1f)",
					got, c.want, highestLineEntropy([]byte(c.body)), entropyThreshold)
			}
		})
	}
}

// The signal does not exist for JavaScript, and that is a measurement rather
// than a scoping preference: in 1354 real files the highest entropy is 6.145, a
// generated parser table, while a base64 payload reaches 6.007. Clean code
// scores higher than the payload, so applying the rule there would report
// libraries and still miss what it was looking for.
func TestEntropyIsNotAppliedToJavaScript(t *testing.T) {
	blob := payload(t, 3000)
	body := []byte(`var x = "` + blob + `";`)
	if highestLineEntropy(body) <= entropyThreshold {
		t.Fatal("the sample is not dense enough to make this test mean anything")
	}
	for _, ext := range append(append([]string{}, jsExts...), extHTAccess) {
		if m := entropyMatches(ext, body); len(m) != 0 {
			t.Errorf("%s: entropy fired on a kind where clean code outscores payloads: %v", ext, m)
		}
	}
}

// A dense line is not a verdict. It says a line is packed, which a legitimate
// build artefact can also be, so it can only ever add to something else.
func TestADenseLineAloneIsNotAFinding(t *testing.T) {
	body := []byte(`<?php $data = '` + payload(t, 3000) + `';`)
	score, _, names, level := verdict(evaluate(".php", body), 0)
	if level != "" {
		t.Fatalf("a packed literal alone produced %q at score %d: %v", level, score, names)
	}
	if len(names) == 0 {
		t.Fatal("the entropy signal did not fire at all, so this proves nothing")
	}

	// With one more independent signal it becomes a verdict.
	withExec := []byte(`<?php @system($cmd); $data = '` + payload(t, 3000) + `';`)
	if _, _, names, level := verdict(evaluate(".php", withExec), 0); level == "" {
		t.Errorf("a packed literal beside a suppressed exec produced nothing: %v", names)
	}
}
