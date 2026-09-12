package uievents

import (
	"os"
	"strings"
	"testing"
)

// recorderFile is the one module that holds the masking contract.
const recorderFile = "../../frontend/src/lib/replay.ts"

// recorderCode returns the recorder WITHOUT its comment lines.
//
// The contract is written out in that file's header, so a search over the whole
// file passes on the documentation alone: deleting the option from the record()
// call would leave the paragraph describing it and the test would still be
// green. Only the code counts here.
func recorderCode(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile(recorderFile)
	if err != nil {
		t.Fatalf("the recorder could not be read: %v", err)
	}
	var code strings.Builder
	for line := range strings.SplitSeq(string(source), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	return code.String()
}

// The masking contract is the ONLY thing standing between a session recording
// and every secret the panel puts on a screen: database passwords, mail
// passwords, API keys, customer data.
//
// It lives in TypeScript, which no Go test would otherwise read, and it is two
// lines long. Deleting either one keeps the recorder working and starts writing
// readable secrets into replay_events, where nothing downstream would notice.
// This test fails the build instead.
//
// Measured, not assumed: with both options a recording of a page carrying a
// domain name, a visible password, an API key and a textarea contained none of
// them; without maskTextSelector the domain name and the visible password were
// in the batch as they read on the screen.
func TestTheRecorderMasksEveryTextAndEveryInput(t *testing.T) {
	code := recorderCode(t)
	for _, required := range []struct {
		line string
		why  string
	}{
		{"maskTextSelector: '*'", "every text node on the screen would be recorded as it reads"},
		{"maskAllInputs: true", "every value typed into a form would be recorded as it was typed"},
	} {
		if !strings.Contains(code, required.line) {
			t.Errorf("%s is missing from %s, so %s", required.line, recorderFile, required.why)
		}
	}
}

// The recorder must not run on the screens that read the recordings back.
// Playing another account's session on a page that is itself being recorded
// stores that session a second time, in a table the first copy already fills.
func TestTheRecorderStaysOffTheLogScreens(t *testing.T) {
	code := recorderCode(t)
	for _, path := range []string{"/session-replay", "/request-log", "/app-log"} {
		if !strings.Contains(code, "'"+path+"'") {
			t.Errorf("%s is not excluded in %s, so the recorder would run on it", path, recorderFile)
		}
	}
}
