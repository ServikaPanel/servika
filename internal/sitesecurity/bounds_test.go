package sitesecurity

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Everything on a finding row comes from a third-party JSON document. Two of
// the bounds did not hold: truncate cut at a byte offset, so a multi-byte
// character straddling the limit was split and MariaDB refused the parameter as
// invalid utf8mb4 (error 1366), and cvss was passed through unchecked against a
// DECIMAL(3,1) that stops at 99.9 (error 1264). Either failure loses the
// finding AND sets firstErr for the pass, which suppresses the stale-row prune
// for the whole domain: the screen then omits a vulnerable package and keeps
// rows for installations that are gone.

// A cut never leaves half a character behind.
func TestATruncatedValueIsStillValidUTF8(t *testing.T) {
	// "ş" is two bytes, so a 511 byte prefix of these lands inside one.
	value := strings.Repeat("ş", 400)
	for _, limit := range []int{1, 15, 63, 511, 512} {
		got := truncate(value, limit)
		if !utf8.ValidString(got) {
			t.Errorf("limit %d produced invalid UTF-8: %q", limit, got)
		}
		if len(got) > limit {
			t.Errorf("limit %d produced %d bytes", limit, len(got))
		}
	}
}

// The cut is as long as it can be: an even limit on two-byte characters keeps
// every byte, so the fix does not quietly shorten a title by a character.
func TestATruncatedValueKeepsEveryWholeCharacterThatFits(t *testing.T) {
	value := strings.Repeat("ş", 400)
	if got := truncate(value, 512); len(got) != 512 {
		t.Errorf("an even limit kept %d bytes, want 512", len(got))
	}
	if got := truncate(value, 511); len(got) != 510 {
		t.Errorf("an odd limit kept %d bytes, want 510, one whole character short", len(got))
	}
}

// An ASCII value shorter than its column is returned untouched.
func TestAValueInsideItsColumnIsNotTouched(t *testing.T) {
	if got := truncate("CVE-2026-1234", 64); got != "CVE-2026-1234" {
		t.Errorf("truncate = %q", got)
	}
}

// A score the column cannot hold is dropped rather than sent, because losing
// the number costs less than losing the finding.
func TestAScoreOutsideTheColumnIsNotWritten(t *testing.T) {
	for _, score := range []float64{-1, 0, 10.1, 99.9, 100, 1e9} {
		if got := storedCVSS(score); got != nil {
			t.Errorf("storedCVSS(%v) = %v, want nil", score, got)
		}
	}
	for _, score := range []float64{0.1, 5.5, 9.8, 10} {
		if got := storedCVSS(score); got != score {
			t.Errorf("storedCVSS(%v) = %v, want the score", score, got)
		}
	}
}
