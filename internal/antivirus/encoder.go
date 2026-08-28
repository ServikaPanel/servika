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
	encoderInjectSpan = 160  // bytes examined after a `<?php` in the body
)

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
// file is packed by a commercial encoder: (name, offset, true), else ("", 0,
// false). The body start is the first run of encoderBinaryRun binary bytes, or
// the first window whose base64 density crosses encoderB64Ratio (ionCube's own
// form, where the body is fully printable). The plaintext preamble before that
// point stays inside the scan.
func encoderBlobStart(content []byte) (string, int, bool) {
	head := content
	if len(head) > encoderHeadWindow {
		head = head[:encoderHeadWindow]
	}
	name := ""
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

// injectedCodeAfterBlob is the escape guard. It returns real PHP code appended
// to the encrypted body, or nil. A `<?php` can appear in random body bytes by
// chance, but a following span of PHP-syntax characters cannot: base64 produces
// none of them. Real injected code is long plaintext by nature.
func injectedCodeAfterBlob(body []byte) []byte {
	for _, open := range [][]byte{[]byte("<?php"), []byte("<?=")} {
		offset := 0
		for {
			i := bytes.Index(body[offset:], open)
			if i < 0 {
				break
			}
			at := offset + i
			end := min(at+len(open)+encoderInjectSpan, len(body))
			hint := 0
			for _, c := range body[at+len(open) : end] {
				if phpSyntaxByte(c) {
					hint++
				}
			}
			if hint >= encoderInjectHint {
				return body[at:]
			}
			offset = at + len(open)
		}
	}
	return nil
}

// commercialEncoderExtract returns the bytes worth scanning when the file is
// packed by a commercial encoder: the plaintext preamble plus any real code
// injected after the body. It returns ok=false for anything not packed, so the
// caller scans the file unchanged. It is limited to PHP because the stamps are
// PHP encoders and a non-PHP file must not have its bytes rewritten here.
func commercialEncoderExtract(ext string, content []byte) (scanned []byte, name string, ok bool) {
	if !phpish(ext) {
		return nil, "", false
	}
	name, blobStart, packed := encoderBlobStart(content)
	if !packed {
		return nil, "", false
	}
	out := content[:blobStart]
	if injected := injectedCodeAfterBlob(content[blobStart:]); injected != nil {
		merged := make([]byte, 0, len(out)+len(injected)+1)
		merged = append(merged, out...)
		merged = append(merged, '\n')
		merged = append(merged, injected...)
		out = merged
	}
	return out, name, true
}
