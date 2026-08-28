package antivirus

import "testing"

// stageForCode maps a process reason code to its kill-chain stage. It lives in
// procwatch_linux.go (the emit path), so this test is Linux-only.
func TestStageForCode(t *testing.T) {
	cases := map[string]string{
		reasonWebDownloader:   "c2",
		reasonWebPersistence:  "persistence",
		reasonWebShellCmd:     "execution",
		reasonUntrustedOrigin: "execution",
	}
	for code, want := range cases {
		if got := stageForCode(code); got != want {
			t.Fatalf("stageForCode(%q) = %q, want %q", code, got, want)
		}
	}
}
