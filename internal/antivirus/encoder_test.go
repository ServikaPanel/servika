package antivirus

import (
	"bytes"
	"strings"
	"testing"
)

// ionCubeFile builds a file shaped like a commercially encoded one: an ionCube
// stamp, then a long base64 body. The body carries the argument verbatim, so a
// test can plant a signature word inside the encrypted region.
func ionCubeFile(inBody string) []byte {
	preamble := "<?php //ICB0 82:0 83:e7bc\n"
	body := strings.Repeat("A", 250) + inBody + strings.Repeat("B", 250)
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

// TestAPlainFileIsNotTreatedAsEncoded is the regression: an ordinary PHP file
// carries no stamp, so the extract leaves it untouched.
func TestAPlainFileIsNotTreatedAsEncoded(t *testing.T) {
	file := []byte("<?php\nfunction total($a, $b) { return $a + $b; }\n")
	if _, _, ok := commercialEncoderExtract(".php", file); ok {
		t.Error("a plain PHP file was mistaken for an encoded one")
	}
}
