package antivirus

import (
	"bytes"
	"strings"
	"testing"
)

// ionCubeFile builds a file shaped like a commercially encoded one: the ionCube
// stamp, the loader-missing fallback prose every encoded file carries, then a
// long base64 body. The prose is full of spaces and punctuation, so the
// base64-density heuristic locates the body rather than mistaking the preamble
// for it, which is how a real file looks. The body carries the argument
// verbatim, so a test can plant a signature word inside the encrypted region.
func ionCubeFile(inBody string) []byte {
	preamble := "<?php //ICB0 82:0 83:e7bc\n" +
		"if(!extension_loaded('ionCube Loader')){$__oc=strtolower(substr(php_uname(),0,3));" +
		"$__ln='ioncube_loader_'.$__oc.'_'.substr(phpversion(),0,3).'.so';" +
		"die('The file '.__FILE__.' requires the ionCube PHP Loader '.$__ln.' to be installed.');}\n"
	body := strings.Repeat("A", 400) + inBody + strings.Repeat("B", 400)
	return []byte(preamble + body)
}

// TestAnEncodedBodyDoesNotConvictOnARandomSignature is the core false positive.
// A signature word (filesman) sits inside the encrypted body, exactly as it did
// in the WHMCS case that ate 347 files. The body is opaque, so it is removed
// from what the rules see and the file stays clean.
func TestAnEncodedBodyDoesNotConvictOnARandomSignature(t *testing.T) {
	file := ionCubeFile("filesman")
	if !bytes.Contains(file, []byte("filesman")) {
		t.Fatal("the fixture must actually carry the signature word in its body")
	}

	stripped, name, ok := commercialEncoderExtract(".php", file)
	if !ok || name != "ionCube" {
		t.Fatalf("extract = (ok=%v name=%q), want the ionCube body recognised", ok, name)
	}
	if bytes.Contains(stripped, []byte("filesman")) {
		t.Error("the signature word survived into the scanned bytes; the body was not treated as opaque")
	}

	if _, _, _, level := verdict(evaluate(".php", file), scoreCritical); level == LevelCritical {
		t.Errorf("a legitimately encoded file was reported critical (level=%q)", level)
	}
}

// TestInjectedCodeAfterTheStampIsStillCaught is the escape guard. An attacker
// prepends a fake stamp plus a base64 body and then writes a real webshell; the
// injected plaintext code is kept and scanned at full strength.
func TestInjectedCodeAfterTheStampIsStillCaught(t *testing.T) {
	file := append(ionCubeFile("padding"), []byte("\n<?php eval($_POST['x']);")...)

	if _, _, _, level := verdict(evaluate(".php", file), scoreCritical); level != LevelCritical {
		t.Errorf("a webshell injected after an encoder stamp was not caught (level=%q)", level)
	}
}

// TestAStampWithoutAnEncodedBodyIsScannedInFull covers a webshell that merely
// imitates a stamp: there is no encoded body, so nothing is treated as opaque
// and the whole file is scanned.
func TestAStampWithoutAnEncodedBodyIsScannedInFull(t *testing.T) {
	file := []byte("<?php //ICB0 fake header\neval($_POST['cmd']);")

	if _, _, ok := commercialEncoderExtract(".php", file); ok {
		t.Fatal("a file with a stamp but no encoded body must not be treated as packed")
	}
	if _, _, _, level := verdict(evaluate(".php", file), scoreCritical); level != LevelCritical {
		t.Errorf("a webshell hiding behind a fake stamp was not caught (level=%q)", level)
	}
}

// TestAPackedFindingNamesTheEncoder checks the informational tag: a finding on a
// packed file carries the encoder name, so an operator sees the body was skipped
// rather than that the file is clean, and the tag never becomes the signature or
// the reason for conviction.
func TestAPackedFindingNamesTheEncoder(t *testing.T) {
	file := append(ionCubeFile("padding"), []byte("\n<?php eval($_POST['x']);")...)

	_, signature, names, level := verdict(evaluate(".php", file), scoreCritical)
	if level != LevelCritical {
		t.Fatalf("the injected webshell was not caught (level=%q)", level)
	}
	found := false
	for _, n := range names {
		if n == "PHP.Encoder.ionCube" {
			found = true
		}
	}
	if !found {
		t.Errorf("the finding does not name the encoder: %v", names)
	}
	if signature == "PHP.Encoder.ionCube" {
		t.Error("the informational tag became the signature; it carries no weight")
	}

	// A clean packed file writes no row, so the tag stays invisible.
	if _, _, _, l := verdict(evaluate(".php", ionCubeFile("filesman")), scoreCritical); l != "" {
		t.Errorf("a clean encoded file produced a finding (level=%q)", l)
	}
}

// TestASameContextSinkAfterTheBlobIsCaught is the escape-guard bypass. A
// webshell reads the base64 body into a variable and evaluates it in the SAME
// PHP context, opening no new <?php tag: `$c='<base64>'; eval(base64_decode($c));`.
// The eval sits right after the base64 body ends, so the tail after the blob
// must be scanned or the file scores zero.
func TestASameContextSinkAfterTheBlobIsCaught(t *testing.T) {
	blob := strings.Repeat("QUJD", 200) // 800 base64 characters
	file := []byte("<?php //ICB0 82:0 83:e7bc\n$c='" + blob + "'; eval(base64_decode($c));")

	if _, _, _, level := verdict(evaluate(".php", file), scoreCritical); level != LevelCritical {
		t.Errorf("a same-context eval after the encoded body was not caught (level=%q)", level)
	}
}

// TestARealEncodedFileWithABenignTailStaysClean protects the false-positive
// side: a genuine encoded file whose base64 body is followed by a harmless tag
// must not be reported.
func TestARealEncodedFileWithABenignTailStaysClean(t *testing.T) {
	blob := strings.Repeat("QUJD", 200)
	file := []byte("<?php //ICB0 82:0 83:e7bc\n$data='" + blob + "';\n?>\n")

	if _, _, _, level := verdict(evaluate(".php", file), scoreCritical); level == LevelCritical {
		t.Errorf("a genuinely encoded file with a benign tail was reported critical (level=%q)", level)
	}
}

// TestAPlainFileIsNotTreatedAsEncoded is the regression: an ordinary PHP file
// carries no stamp, so the extract leaves it untouched.
func TestAPlainFileIsNotTreatedAsEncoded(t *testing.T) {
	file := []byte("<?php\nfunction total($a, $b) { return $a + $b; }\n")
	if _, _, ok := commercialEncoderExtract(".php", file); ok {
		t.Error("a plain PHP file was mistaken for an encoded one")
	}
}
