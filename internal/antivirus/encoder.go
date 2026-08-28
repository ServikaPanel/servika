package antivirus

// Commercial PHP encoders (ionCube, SourceGuardian, Zend Guard) ship a small
// plaintext preamble followed by a large ENCRYPTED body, and searching that body
// for a signature only produces false positives.
//
// An encrypted or compressed body is ~random bytes. A short signature word made
// only of base64-alphabet characters (c99shell, filesman, b374k, priv8) has a
// non-zero chance of appearing by accident somewhere in a 100 KB body, and
// PHP.Webshell.KnownMarker is weightProof, so one accidental hit is a critical
// verdict on its own and drives automatic containment. The body also cannot be
// decoded here (that needs the vendor's licensed loader), so searching it has no
// detection value either: counting what cannot be measured as dirty is as wrong
// as counting it clean.
//
// So a file that carries an encoder STAMP has its plaintext preamble scanned at
// full strength and its encrypted body treated as OPAQUE (removed from the bytes
// the rules see). The escape guard is injectedCodeAfterBlob: an attacker who
// prepends a fake stamp plus binary padding and then writes a webshell is still
// caught, because real injected PHP is long plaintext that random body bytes are
// not.

import "bytes"

// encoderStamps are the vendor markers looked for at the START of the file. Only
// the first encoderHeadWindow bytes are searched: a genuine stamp is at the very
// top, while the word "ionCube" appearing in a blog post further down must not
// weaken the scan of that file.
var encoderStamps = []struct {
	stamp []byte
	name  string
}{
	{[]byte("//ICB0"), "ionCube"},         // ionCube header comment: `<?php //ICB0 82:0 83:e7bc`
	{[]byte("ionCube Loader"), "ionCube"}, // loader-missing fallback text (in every encoded file)
	{[]byte("SourceGuardian"), "SourceGuardian"},
	{[]byte("sg_load"), "SourceGuardian"},
	{[]byte("@Zend;"), "ZendGuard"},
}

const (
	encoderHeadWindow = 1024 // the stamp is searched only in these first bytes
	encoderBinaryRun  = 48   // this many consecutive "binary" bytes → the encrypted body began
	encoderB64Window  = 256  // the base64-density measurement window
	encoderB64Ratio   = 96   // this percent of base64 characters in a window → encoded body
	encoderInjectHint = 5    // PHP-syntax characters required in an injected-code window
	encoderInjectSpan = 160  // bytes examined after a sink pattern in the body
)

// encoderSinks are patterns that occur in REAL PHP but CANNOT occur inside a
// base64 or ionCube body. The key insight: each carries a byte absent from the
// base64 alphabet (`<`, `(`, `$`, `[`), and a base64 body can produce none of
// them, so a sink appearing inside the body is real code, not encrypted noise.
// This replaces the "scan the base64 tail" approach, which produced 259/3316
// false positives on real ionCube bodies (the body is not pure base64, so the
// tail scan cut early and scanned the remainder as if it were plain code). The
// opaque body is now never scanned; only the plain-code region AROUND one of
// these impossible patterns is extracted and scanned.
var encoderSinks = [][]byte{
	[]byte("<?php"), []byte("<?="),
	[]byte("eval("), []byte("assert("), []byte("system("), []byte("passthru("),
	[]byte("shell_exec("), []byte("exec("), []byte("proc_open("), []byte("popen("),
	[]byte("base64_decode("), []byte("gzinflate("), []byte("gzuncompress("),
	[]byte("str_rot13("), []byte("create_function("), []byte("call_user_func("),
	[]byte("preg_replace("), []byte("$_GET["), []byte("$_POST["), []byte("$_REQUEST["),
	[]byte("$_COOKIE["), []byte("$_SERVER["), []byte("file_put_contents("),
}

// nonTextByte reports whether a byte is "not text". Printable ASCII and ordinary
// whitespace count as text; the rest is binary.
func nonTextByte(c byte) bool {
	if c == '\t' || c == '\n' || c == '\r' {
		return false
	}
	return c < 32 || c > 126
}

// base64Byte reports whether a byte is in the base64 alphabet (line-wrapping
// whitespace is deliberately excluded).
func base64Byte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '='
}

// phpSyntaxBytes are characters common in real PHP source and ABSENT from the
// base64 alphabet (space $ ( ) ; ' " NL TAB [ ] { } < > . , ! -). They are the
// key to telling a real injected `<?php` from one that appears by chance inside
// an encoded body, because base64 can produce NONE of them.
var phpSyntaxBytes = []byte{0x20, 0x24, 0x28, 0x29, 0x3b, 0x27, 0x22, 0x0a, 0x09, 0x5b, 0x5d, 0x7b, 0x7d, 0x3c, 0x3e, 0x2e, 0x2c, 0x21, 0x2d}

func phpSyntaxByte(c byte) bool { return bytes.IndexByte(phpSyntaxBytes, c) >= 0 }

// encoderBlobStart returns the offset at which the encrypted body begins when the
// file is packed by a commercial encoder: (name, offset, true), else ("", 0, false).
// The body start is the first run of encoderBinaryRun binary bytes, or the first
// window whose base64 density crosses encoderB64Ratio (ionCube's own form, where
// the body is fully printable). The plaintext preamble before that point stays
// inside the scan; the body itself is opaque and never scanned.
func encoderBlobStart(content []byte) (name string, offset int, ok bool) {
	head := content
	if len(head) > encoderHeadWindow {
		head = head[:encoderHeadWindow]
	}
	for _, s := range encoderStamps {
		if bytes.Contains(head, s.stamp) {
			name = s.name
			break
		}
	}
	if name == "" {
		return "", 0, false
	}
	// (a) A binary body (some packers write raw binary).
	run := 0
	for i := range content {
		if nonTextByte(content[i]) {
			run++
			if run >= encoderBinaryRun {
				return name, i - run + 1, true
			}
			continue
		}
		run = 0
	}
	// (b) A base64 body (ionCube's actual form: fully printable, so the binary
	// heuristic never sees it). The tell is base64-alphabet density, which real
	// PHP source cannot sustain because space, $, (, ; are not base64.
	for i := 0; i+encoderB64Window <= len(content); i += encoderB64Window {
		window := content[i : i+encoderB64Window]
		count := 0
		for _, c := range window {
			if base64Byte(c) {
				count++
			}
		}
		if count*100/len(window) >= encoderB64Ratio {
			start := i
			for start > 0 && base64Byte(content[start-1]) {
				start--
			}
			return name, start, true
		}
	}
	// A stamp but no encoded body → not actually packed (a plain PHP file that
	// MENTIONS ionCube, or a webshell imitating a stamp). Scan it in full.
	return "", 0, false
}

// blobEndBase64 returns the offset at which a base64 body ends, i.e. where plain
// code begins. It is called only for a base64 body: a raw-binary body has no
// readable tail, and scanning random binary would produce the signature-collision
// injectedCodeAfterBlob is the escape guard. It returns real PHP code injected
// into or after the encrypted body, or nil. A tail-scan of the base64 body was
// tried and abandoned: a real ionCube body is not pure base64, so cutting it at
// the first non-base64 run exposed the remainder and produced 259/3316 false
// positives. Instead it searches for the encoderSinks patterns, which base64
// CANNOT produce (each carries a `<`, `(`, `$` or `[`). Around a match it requires
// enough PHP-syntax density (encoderInjectHint) to reject a chance short match in
// a raw-binary body, then returns from the EARLIEST accepted match. A genuine
// ionCube body contains none of these patterns, so there is no false positive; a
// same-context `$c='<base64>'; eval(base64_decode($c));` webshell is still caught,
// because eval( sits in plain code after the body.
func injectedCodeAfterBlob(body []byte) []byte {
	best := -1
	for _, sink := range encoderSinks {
		offset := 0
		for {
			i := bytes.Index(body[offset:], sink)
			if i < 0 {
				break
			}
			at := offset + i
			end := min(at+len(sink)+encoderInjectSpan, len(body))
			hint := 0
			for _, c := range body[at:end] {
				if phpSyntaxByte(c) {
					hint++
				}
			}
			if hint >= encoderInjectHint {
				if best < 0 || at < best {
					best = at
				}
				break // the earliest accepted match for this sink is enough
			}
			offset = at + len(sink)
		}
	}
	if best < 0 {
		return nil
	}
	return body[best:]
}

// commercialEncoderExtract returns the bytes worth scanning when the file is
// packed by a commercial encoder: the plaintext preamble plus any real code
// injected into or after the body. The OPAQUE body (base64 or binary, the source
// of the false positives) is NEVER scanned; only the plain-code region around an
// encoderSinks pattern is extracted. It returns ok=false for anything not packed,
// so the caller scans the file unchanged. It is limited to PHP because the stamps
// are PHP encoders and a non-PHP file must not have its bytes rewritten here.
func commercialEncoderExtract(ext string, content []byte) (scanned []byte, name string, ok bool) {
	if !phpish(ext) {
		return nil, "", false
	}
	name, blobStart, packed := encoderBlobStart(content)
	if !packed {
		return nil, "", false
	}
	out := make([]byte, 0, blobStart+64)
	out = append(out, content[:blobStart]...) // the plaintext preamble
	// Real code injected into or after the opaque body, found by a pattern base64
	// cannot produce. A genuine encoded file has none, so this returns nil.
	if injected := injectedCodeAfterBlob(content[blobStart:]); injected != nil {
		out = append(out, '\n')
		out = append(out, injected...)
	}
	return out, name, true
}
