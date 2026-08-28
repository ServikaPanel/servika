package antivirus

// A payload that is executed through a decoder is invisible to every pattern in
// the set, because the dangerous text is not in the file: it is inside a base64
// string, a `\x` escape run, a rot13 block, or a compressed blob, and only
// appears once the interpreter decodes it at runtime.
//
//	eval(gzinflate(base64_decode('7b0Ha...')))   // decoded payload reads $_POST
//
// The OUTER shapes of this are already caught in clear: `eval(base64_decode(`
// and `eval(gzinflate(base64_decode(` are weightProof/weightStrong rules, and a
// blob split across concatenation is caught by concealed.go. What this layer
// adds is the INNER content: it decodes the blob at bounded depth and runs the
// behavioural rules against each layer, so a webshell hidden one or more decodes
// down is seen for what it is.
//
// Four things bound it, and each closes a hole that is invisible from the code.
//
// A DECODED match is capped exactly like a remote rule (match.decoded): it can
// raise a file to suspicious but not, on its own, drive the containment that
// MOVES a customer's file. Decoding turns an arbitrary blob into bytes this set
// has never been measured against, and a legitimate base64 asset (a serialized
// config, an embedded font) is decoded here too. A real webshell payload is
// almost always ALSO caught in clear by its outer decoder call, which is a
// shipped rule and does convict; the decoded layer is corroboration and reach.
//
// Only a NEW signal is rewarded: a rule that already fired against the file's
// literal bytes is skipped in the decode pass, because re-adding it under the
// Decoded: name double-counts one behaviour a legitimate packer or license stub
// exhibits in clear, which is how upstream's version raised a clean file to a
// verdict with nothing malicious inside.
//
// The decode is fingerprinted by the WHOLE blob (fnv64a), not a prefix: a prefix
// key is craftable, and two blobs made to share it let an attacker suppress the
// real payload as "already seen".
//
// The whole decode runs under a STRICT budget (depth, total bytes, blobs per
// layer, and a decompression ratio), because unbounded recursive decompression
// is a denial-of-service vector: a small gzip blob can inflate to gigabytes, and
// the decompression is charged to the budget EVEN WHEN its output is rejected,
// so a bomb that inflates to non-text cannot be retried for free.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"hash/fnv"
	"io"
	"regexp"
)

const (
	// decodeMaxDepth bounds how many nested decode layers are followed.
	decodeMaxDepth = 4
	// decodeMaxBytes is the ceiling on total decoded output across all layers,
	// the guard against a decompression bomb.
	decodeMaxBytes = 3 << 20
	// decodeMaxBlobs bounds how many encoded blobs one layer contributes.
	decodeMaxBlobs = 12
	// decodeMaxMatches bounds how many decoded findings one file contributes,
	// so a blob that matches many rules cannot flood the finding list.
	decodeMaxMatches = 8
	// decodeBombRatio rejects a decompression whose output is more than this
	// many times its input, the shape of a decompression bomb.
	decodeBombRatio = 200
	// decodeMinWeight is the floor for a rule to fire against a DECODED layer.
	// The weak rules (LongBase64Block, HexEscapedName) detect the ENCODING form
	// itself, and a decoded layer that still looks encoded is expected in a
	// multi-layer payload, not new evidence: re-flagging the shape on the
	// decoded view only double-counts and fires on a decoded-then-still-base64
	// asset. Only BEHAVIOURAL rules (a dangerous call, a superglobal sink),
	// which are all weightModerate and above, say something the clear-text pass
	// did not already weigh.
	decodeMinWeight = weightModerate
	// decodedPrefix marks a finding as coming from a decoded layer, so the
	// operator sees it was obfuscated and the signature stays distinct from the
	// same rule firing in clear.
	decodedPrefix = "Decoded:"
)

var (
	// reBase64Blob matches a base64 run long enough to be a payload rather than
	// an ordinary token. 24 characters is 18 decoded bytes, below which there is
	// nothing worth decoding.
	//
	// The class is the STANDARD alphabet only (`+/`), never URL-safe (`-_`).
	// Measured on WordPress core, widening it to `-_` makes the pre-gate below
	// fire on 82.3% of clean PHP files instead of 33.7%, because it then matches
	// any long snake_case identifier (`wp_get_attachment_image_src`), so the
	// decode pass runs on 2.4x more clean files every sweep. URL-safe base64 is
	// a niche vector here (`base64_decode` reads the standard alphabet), not
	// worth that cost.
	reBase64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)
	// reHexEscapes matches a `\x41\x42...` escape run, PHP's other common inline
	// encoding.
	reHexEscapes = regexp.MustCompile(`(?:\\x[0-9A-Fa-f]{2}){16,}`)
	// encodedIndicator is the pre-gate: a file with no base64 run, no hex run and
	// no str_rot13 call carries nothing to decode, so the whole pass (and its
	// full-file rot13 copy) is skipped.
	encodedIndicator = regexp.MustCompile(`[A-Za-z0-9+/]{24,}|(?:\\x[0-9A-Fa-f]{2}){16,}|str_rot13`)
)

// decodedMatches decodes the encoded blobs in a PHP file at bounded depth and
// runs the behavioural rules against each decoded layer.
//
// clearNames are the rules that already fired against the file's literal bytes;
// they are not rewarded again here. It is PHP only: encoded-then-executed
// payloads are a PHP shape, and gating on the file kind keeps the decode work
// off every asset the scan reads.
func decodedMatches(ext string, content []byte, clearNames map[string]bool) []match {
	if !phpish(ext) || !encodedIndicator.Match(content) {
		return nil
	}
	budget := decodeMaxBytes
	seen := map[uint64]bool{}
	// Seed the ORIGINAL content, because rot13 is its own inverse: applying it
	// twice reproduces the file exactly, which would otherwise re-fire every
	// clear-text rule as a decoded double of itself one layer down.
	seen[blobKey(content)] = true
	var out []match

	var walk func(data []byte, depth int)
	walk = func(data []byte, depth int) {
		if depth > decodeMaxDepth || budget <= 0 || len(out) >= decodeMaxMatches {
			return
		}
		for _, blob := range decodeLayer(data, &budget) {
			if len(blob) < 8 || looksLikeAsset(blob) {
				continue
			}
			key := blobKey(blob)
			if seen[key] {
				continue
			}
			seen[key] = true
			for _, h := range heuristics {
				if h.score < decodeMinWeight || clearNames[h.name] || !appliesTo(h, ext) {
					continue
				}
				if h.re.Match(blob) {
					out = append(out, match{name: decodedPrefix + h.name, score: h.score, decoded: true})
					if len(out) >= decodeMaxMatches {
						return
					}
				}
			}
			walk(blob, depth+1)
		}
	}
	walk(content, 1)
	return dedupeMatches(out)
}

// blobKey fingerprints a decoded payload for the seen set with a full-content
// hash. A prefix key would be craftable: two blobs made to share it let an
// attacker suppress the real payload as already-seen.
func blobKey(b []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(b)
	return h.Sum64()
}

// decodeLayer decodes the encoded blobs in data ONE level (base64, with any
// inner compression; `\x` hex, likewise; rot13 when the file calls it),
// charging every decoded byte to budget.
func decodeLayer(data []byte, budget *int) [][]byte {
	var out [][]byte
	add := func(b []byte) {
		if len(b) == 0 || *budget <= 0 {
			return
		}
		if len(b) > *budget {
			b = b[:*budget]
		}
		*budget -= len(b)
		out = append(out, b)
	}

	for _, blob := range reBase64Blob.FindAll(data, decodeMaxBlobs) {
		dec := decodeBase64(blob)
		if len(dec) == 0 {
			continue
		}
		add(dec)
		if inf := inflate(dec, budget); inf != nil {
			out = append(out, inf) // inflate charged the budget itself
		}
	}
	for _, run := range reHexEscapes.FindAll(data, decodeMaxBlobs) {
		clean := bytes.ReplaceAll(run, []byte(`\x`), nil)
		dec, err := hex.DecodeString(string(clean))
		if err != nil {
			continue
		}
		add(dec)
		// hex is the other input to gzinflate: gzinflate(hex2bin('...')) hides a
		// compressed payload behind hex rather than base64.
		if inf := inflate(dec, budget); inf != nil {
			out = append(out, inf)
		}
	}
	// rot13 only when the file actually calls str_rot13: applying it to every
	// file is a full-copy cost and turns arbitrary code into noise.
	if bytes.Contains(data, []byte("str_rot13")) {
		if r := rot13(data); r != nil {
			add(r)
		}
	}
	return out
}

// decodeBase64 tries the standard alphabet, padded and raw. URL-safe is not
// tried, because reBase64Blob does not match its alphabet (see the note there).
func decodeBase64(blob []byte) []byte {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if dec, err := enc.DecodeString(string(blob)); err == nil && len(dec) > 0 {
			return dec
		}
	}
	return nil
}

// inflate tries to decompress b as gzip, zlib or raw DEFLATE, matching PHP's
// gzdecode, gzuncompress and gzinflate. It reads no more than the remaining
// budget, CHARGES the budget for what it produced even when the result is
// rejected (so a bomb inflating to non-text cannot be retried for free), and
// rejects output that exceeds decodeBombRatio times its input.
func inflate(b []byte, budget *int) []byte {
	if len(b) < 4 || *budget <= 0 {
		return nil
	}
	limit := int64(*budget)
	read := func(r io.Reader) []byte {
		o, err := io.ReadAll(io.LimitReader(r, limit))
		if err != nil || len(o) == 0 {
			return nil
		}
		*budget -= len(o)
		if len(o) > len(b)*decodeBombRatio {
			return nil
		}
		return o
	}

	if b[0] == 0x1f && b[1] == 0x8b {
		if r, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
			if o := read(r); o != nil {
				return o
			}
		}
	}
	if r, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
		if o := read(r); o != nil {
			return o
		}
	}
	// Raw DEFLATE accepts any input, so its output is kept only when it reads as
	// text; the header formats above already refuse non-matching input.
	if o := read(flate.NewReader(bytes.NewReader(b))); o != nil && printableText(o) {
		return o
	}
	return nil
}

// rot13 applies the ROT13 cipher, returning nil when the input has no letter to
// move (so a purely non-alphabetic blob is not re-queued as itself).
func rot13(b []byte) []byte {
	out := make([]byte, len(b))
	moved := false
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			out[i] = 'a' + (c-'a'+13)%26
			moved = true
		case c >= 'A' && c <= 'Z':
			out[i] = 'A' + (c-'A'+13)%26
			moved = true
		default:
			out[i] = c
		}
	}
	if !moved {
		return nil
	}
	return out
}

// looksLikeAsset reports whether a decoded blob is a known media file by its
// magic bytes. A legitimate PHP file embedding an image, font or PDF as base64
// decodes to one of these, and scanning or recursing into its binary is wasted
// work that only widens the surface for a coincidental match.
func looksLikeAsset(b []byte) bool {
	magics := [][]byte{
		[]byte("\x89PNG"), []byte("\xff\xd8\xff"), []byte("GIF8"), []byte("%PDF"),
		[]byte("wOFF"), []byte("wOF2"), []byte("RIFF"), []byte("BM"),
		[]byte("\x00\x00\x01\x00"),                                // ICO
		[]byte("OggS"), []byte("ID3"), []byte("\x1a\x45\xdf\xa3"), // Ogg, MP3, Matroska
	}
	for _, m := range magics {
		if bytes.HasPrefix(b, m) {
			return true
		}
	}
	return false
}

// printableText reports whether the head of b is mostly printable, which
// separates a text payload from the binary noise raw DEFLATE produces for input
// that was never DEFLATE to begin with.
func printableText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	n := min(len(b), 512)
	printable := 0
	for _, c := range b[:n] {
		if c == 0 {
			return false
		}
		if (c >= 32 && c < 127) || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(n) > 0.75
}

// dedupeMatches removes repeated (name) matches, so one rule that fires on
// several decoded layers contributes a single finding.
func dedupeMatches(in []match) []match {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, m := range in {
		if seen[m.name] {
			continue
		}
		seen[m.name] = true
		out = append(out, m)
	}
	return out
}

// clearRuleNames is the set of shipped rule names that fired against the file's
// literal bytes, so the decode pass can reward only a NEW signal.
func clearRuleNames(matches []match) map[string]bool {
	names := make(map[string]bool, len(matches))
	for _, m := range matches {
		if !m.remote && !m.decoded && !m.informational {
			names[m.name] = true
		}
	}
	return names
}
