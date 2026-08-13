package credentials

import (
	"strings"
	"testing"
)

// The alphabet has 56 characters and 256 % 56 = 32, so reducing a raw byte with
// `% 56` hands the first 32 characters five of the 256 byte values and the
// remaining 24 only four. Measured over the whole byte space that is a 1.2500
// ratio between the most and least likely character.
//
// The bound sits between the two: at this sample size each character is drawn
// about 35700 times with a standard deviation near 190, so the extreme of 56
// unbiased samples stays under 1.04, while the biased implementation is pinned
// at 1.2500 by arithmetic and cannot come down with more draws.
func TestNoCharacterIsFavouredOverAnother(t *testing.T) {
	const draws = 2_000_000

	counts := map[rune]int{}
	for len(counts) == 0 || totalOf(counts) < draws {
		for _, c := range RandomPassword(64) {
			counts[c]++
		}
	}

	if len(counts) != len(PasswordAlphabet) {
		t.Fatalf("saw %d distinct characters, want all %d of the alphabet",
			len(counts), len(PasswordAlphabet))
	}

	first := rune(PasswordAlphabet[0])
	least, most := counts[first], counts[first]
	leastCh, mostCh := first, first
	for _, c := range PasswordAlphabet {
		n := counts[c]
		if n < least {
			least, leastCh = n, c
		}
		if n > most {
			most, mostCh = n, c
		}
	}
	ratio := float64(most) / float64(least)

	const bound = 1.06
	if ratio > bound {
		t.Fatalf("character frequency ratio %.4f exceeds %.2f: %q appeared %d times, %q %d times",
			ratio, bound, mostCh, most, leastCh, least)
	}
	t.Logf("ratio %.4f over %d draws", ratio, totalOf(counts))
}

func totalOf(counts map[rune]int) int {
	n := 0
	for _, c := range counts {
		n += c
	}
	return n
}

func TestEveryCharacterComesFromTheAlphabet(t *testing.T) {
	for range 200 {
		got := RandomPassword(32)
		if len(got) != 32 {
			t.Fatalf("length %d, want 32", len(got))
		}
		for _, c := range got {
			if !strings.ContainsRune(PasswordAlphabet, c) {
				t.Fatalf("character %q is not in the alphabet", c)
			}
		}
	}
}

// A password of the requested length must come back whatever the caller asks
// for, because rejection sampling refills its buffer and an off-by-one in that
// loop would silently return a short password.
func TestTheRequestedLengthIsAlwaysReturned(t *testing.T) {
	for _, length := range []int{-5, 0, 1, 2, 17, 20, 24, 63, 64, 65, 200} {
		want := length
		if want <= 0 {
			want = 20 // The documented default.
		}
		if got := RandomPassword(length); len(got) != want {
			t.Fatalf("RandomPassword(%d) returned %d characters, want %d",
				length, len(got), want)
		}
	}
}

// Two consecutive passwords sharing a value would mean the generator is not
// drawing fresh bytes at all, which is the failure a constant-buffer bug
// produces.
func TestTwoPasswordsDiffer(t *testing.T) {
	seen := map[string]bool{}
	for range 500 {
		p := RandomPassword(24)
		if seen[p] {
			t.Fatalf("RandomPassword returned %q twice", p)
		}
		seen[p] = true
	}
}
