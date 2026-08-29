package backups

import "testing"

// A tar exit of 1 ("file changed as we read it") must keep the archive, because
// a live session or cache directory moving mid-read still leaves a complete,
// restorable archive; only exit 2 and above discards it.
func TestTarArchiveUsableKeepsOnlyExitOne(t *testing.T) {
	cases := map[int]bool{1: true, 2: false, 3: false, 127: false}
	for code, want := range cases {
		if got := tarArchiveUsable(code); got != want {
			t.Errorf("tarArchiveUsable(%d) = %v, want %v", code, got, want)
		}
	}
}
