package antivirus

// A long, high-entropy line is what an encoded payload looks like when no
// pattern matches it. It is the only signal here that is not a pattern, and it
// is the one that needed the most measuring, because the obvious version of it
// does not work.
//
// Upstream applies it to every file at a threshold of 5.2. Measured, neither
// half of that survives:
//
//   - Across JavaScript, the ranges OVERLAP THE WRONG WAY. In 1354 real files
//     with a line of 200 characters or more, the highest entropy is 6.145, a
//     generated parser table in @lezer/html, while a 3000-byte base64 payload
//     reaches 6.007. Clean code scores HIGHER than the payload, so no threshold
//     separates them and the signal does not exist for that file kind at all.
//
//   - Across PHP the ranges are clean, but 5.2 is far inside the clean one. In
//     1307 real plugin files the distribution is p50 4.792, p95 5.197, p99
//     5.390, max 5.776. At 5.2 that is 65 files carrying the signal; at 5.5 it
//     is 7; at 5.8 it is none, while both measured payload shapes still reach
//     6.008.
//
// So the rule is PHP only and its threshold is 5.8. Upstream's own test never
// exercised any of this: its minified-JavaScript sample is 101 characters and
// the rule needs 200, so the entropy layer never ran.
//
// What it adds over PHP.Obf.LongBase64Block, which looks for the same payloads
// by their ALPHABET, is a real question and the answer is two shapes. That rule
// needs the blob inside one pair of quotes, so measured:
//
//	shape                      entropy  quoted-run rule
//	quoted blob, compressed      fires   fires
//	quoted blob, plain source      no    fires
//	HEREDOC blob, compressed     fires     no
//	concatenated blob            fires     no
//	heredoc blob, plain source     no      no
//
// The two rules cover different halves and the last row is covered by neither,
// which is stated rather than hidden: base64 of plain PHP source measures 5.030
// to 5.633, inside the range clean code occupies, so no threshold reaches it.
//
// The threshold sits at 5.9 rather than at the midpoint because the two sides
// are not alike. A base64 alphabet has 64 symbols, so an encoded blob of
// compressed or random bytes is PINNED near log2(64) = 6.0 and measured 5.993
// to 6.038 across every shape above. The clean side is the variable one, and
// its maximum is a sample: 5.776 over 1654 files here, and some other plugin
// may sit higher. So the margin is spent on the clean side, where the cost of
// being wrong is a working site reported as infected.
//
// It carries the lightest weight regardless, because it says only that a line
// is dense. Hex encoding measures 4.027 and rot13 4.485, both below ordinary
// code, so this can never be the only thing looking for a hidden payload.

import (
	"bufio"
	"bytes"
	"math"
)

const (
	// entropyThreshold sits above every clean file measured (max 5.776) and
	// below every compressed payload measured (min 5.993).
	entropyThreshold = 5.9
	// entropyMinLine is how long a line must be before its entropy means
	// anything. A short line's character distribution is noise.
	entropyMinLine = 200
	// entropyMaxLine bounds one line, because the whole file may be one line
	// and the scanner would otherwise refuse to advance.
	entropyMaxLine = 4 << 20
)

// entropyMatches reports the dense-line signal for a PHP file.
func entropyMatches(ext string, content []byte) []match {
	if !phpish(ext) {
		return nil
	}
	if highestLineEntropy(content) <= entropyThreshold {
		return nil
	}
	return []match{{"PHP.Obf.HighEntropyLine", weightWeak}}
}

// highestLineEntropy returns the Shannon entropy of the densest long line, or 0
// when the file has no line long enough to judge.
func highestLineEntropy(content []byte) float64 {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), entropyMaxLine)
	best := 0.0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) < entropyMinLine {
			continue
		}
		var count [256]int
		for _, b := range line {
			count[b]++
		}
		total := float64(len(line))
		entropy := 0.0
		for _, n := range count {
			if n == 0 {
				continue
			}
			p := float64(n) / total
			entropy -= p * math.Log2(p)
		}
		if entropy > best {
			best = entropy
		}
	}
	return best
}
