package domainblock

import (
	"slices"
	"testing"
)

// An operator pastes from a report, so the separators are whatever came with
// it. What must NOT happen is a name being repaired into something they never
// wrote.
func TestAPastedListIsSplitAndNormalized(t *testing.T) {
	blob := "Example-Bank.com\nlogin.example-bank.com, secure.example-bank.com;\t pay.example-bank.com.\n\n"
	got := parseEntries(blob)
	want := []string{
		"example-bank.com",
		"login.example-bank.com",
		"secure.example-bank.com",
		"pay.example-bank.com",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The same name twice in one paste must produce one entry, or the result
// counts report work that never happened.
func TestARepeatedNameIsCountedOnce(t *testing.T) {
	got := parseEntries("example.com\nEXAMPLE.COM\nexample.com.\n")
	if len(got) != 1 || got[0] != "example.com" {
		t.Errorf("got %q, want one entry of example.com", got)
	}
}

// A blob with nothing in it must produce nothing, so the handler can answer
// 400 instead of writing an empty row.
func TestAnEmptyPasteProducesNoEntries(t *testing.T) {
	for _, blob := range []string{"", "   ", "\n\n", ",;\t", "."} {
		if got := parseEntries(blob); len(got) != 0 {
			t.Errorf("%q produced %q", blob, got)
		}
	}
}
