package logretention

import "testing"

// The range is the whole policy: a value outside it is refused rather than
// clamped, so the boundaries decide what an operator can actually ask for.
func TestTheAcceptedRange(t *testing.T) {
	for _, testCase := range []struct {
		days int
		want bool
	}{
		{0, false}, // Not "keep for ever": a table nothing prunes is the failure.
		{-1, false},
		{1, true},
		{30, true},
		{365, true},
		{366, false},
		{3000, false},
	} {
		if got := Valid(testCase.days); got != testCase.want {
			t.Errorf("Valid(%d) is %v, want %v", testCase.days, got, testCase.want)
		}
	}
}
