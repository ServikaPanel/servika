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
// same rule set against each layer, so a webshell hidden one or more decodes
// down is seen for what it is.
//
// Two things bound it, and both are essential.
//
// A DECODED match is capped exactly like a remote rule (match.decoded): it can
// raise a file to suspicious but not, on its own, drive the containment that
// MOVES a customer's file. Decoding turns an arbitrary blob into bytes this set
// has never been measured against, and a legitimate base64 asset (a serialized
// config, an embedded font) is decoded here too. A real webshell payload is
// almost always ALSO caught in clear by its outer decoder call, which is a
// shipped rule and does convict; the decoded layer is corroboration and reach,
// not the sole basis for moving a file.
//
// The whole decode runs under a STRICT budget (depth, total bytes, blobs per
// layer), because unbounded recursive decompression is a denial-of-service
// vector: a small gzip blob can inflate to gigabytes, and a rot13 of a rot13 is
// a loop. The budget is what makes this cheaper-layer-first design safe to run
// on every PHP file.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
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
	reBase64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)
	// reHexEscapes matches a `\x41\x42...` escape run, PHP's other common inline
	// encoding.
	reHexEscapes = regexp.MustCompile(`(?:\\x[0-9A-Fa-f]{2}){16,}`)
)

// decodedMatches decodes the encoded blobs in a PHP file at bounded depth and
// runs the shipped rule set against each decoded layer.
//
// It is PHP only: encoded-then-executed payloads are a PHP shape, and gating on
// the file kind keeps the decode work off every asset the scan reads.
func decodedMatches(ext string, content []byte) []match {
	if !phpish(ext) {
		return nil
	}
	budget := decodeMaxBytes
	seen := map[string]bool{}
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
			if len(blob) < 8 {
				continue
			}
			key := blobKey(blob)
			if seen[key] {
				continue
			}
			seen[key] = true
			for _, h := range heuristics {
				if h.score < decodeMinWeight || !appliesTo(h, ext) {
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

// blobKey identifies a decoded payload for the seen set: a bounded prefix plus
// the length. Two blobs that share both are treated as the same, which is what
// stops a payload being decoded and rescanned twice.
func blobKey(b []byte) string {
	head := b
	if len(head) > 24 {
		head = head[:24]
	}
	return string(head) + string(rune(len(b)%251))
}

// decodeLayer decodes the encoded blobs in data ONE level (base64, with any
// inner compression; `\x` hex; rot13), charging every decoded byte to budget.
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
		dec, err := base64.StdEncoding.DecodeString(string(blob))
		if err != nil {
			dec, err = base64.RawStdEncoding.DecodeString(string(blob))
		}
		if err != nil || len(dec) == 0 {
			continue
		}
		add(dec)
		if inflated := inflate(dec); inflated != nil {
			add(inflated)
		}
	}
	for _, run := range reHexEscapes.FindAll(data, decodeMaxBlobs) {
		clean := bytes.ReplaceAll(run, []byte(`\x`), nil)
		if dec, err := hex.DecodeString(string(clean)); err == nil {
			add(dec)
		}
	}
	if r := rot13(data); r != nil {
		add(r)
	}
	return out
}

// inflate tries to decompress b as gzip, zlib or raw DEFLATE, matching PHP's
// gzdecode, gzuncompress and gzinflate. Raw DEFLATE accepts any input, so its
// output is kept only when it reads as text; the other two carry a header that
// already refuses non-matching input.
func inflate(b []byte) []byte {
	if len(b) < 4 {
		return nil
	}
	if b[0] == 0x1f && b[1] == 0x8b {
		if r, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
			if o, e := io.ReadAll(io.LimitReader(r, decodeMaxBytes)); e == nil && len(o) > 0 {
				return o
			}
		}
	}
	if r, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
		if o, e := io.ReadAll(io.LimitReader(r, decodeMaxBytes)); e == nil && len(o) > 0 {
			return o
		}
	}
	fr := flate.NewReader(bytes.NewReader(b))
	if o, e := io.ReadAll(io.LimitReader(fr, decodeMaxBytes)); e == nil && len(o) > 0 && printableText(o) {
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
