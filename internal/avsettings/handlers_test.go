package avsettings

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The response carries four views of the same limits. Dropping any of them
// leaves the operator with a belief rather than evidence: what they wrote, what
// the machine has, what "automatic" resolved to, and what the kernel is
// actually enforcing are four different answers and they disagree exactly when
// something has gone wrong.
func TestTheResponseCarriesEveryViewOfTheLimits(t *testing.T) {
	body, err := json.Marshal(Response{})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"settings"`, `"capacity"`, `"effective"`, `"kernel"`, `"scan_roots"`,
	} {
		if !strings.Contains(string(body), field) {
			t.Errorf("the settings response no longer carries %s: %s", field, body)
		}
	}
}

// A refused FIELD is the operator's input and carries a stable code the screen
// words in twelve languages. Anything else is the server failing, and
// presenting that as a field they typed wrong sends them looking in the wrong
// place.
func TestARefusedFieldAndAFailingServerAreAnsweredDifferently(t *testing.T) {
	source, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	if !strings.Contains(body, `if code := ReasonCode(err); code != "" {`) {
		t.Fatal("a refused field no longer carries its reason code")
	}
	if !strings.Contains(body, `map[string]string{"error": err.Error(), "reason": code}`) {
		t.Error("the refusal no longer answers with the panel's error shape plus a code")
	}
	if !strings.Contains(body, "http.StatusInternalServerError") {
		t.Error("a failing server is no longer separated from a refused field")
	}
}

// The write answers with the state read back AFTER it, not with what was sent.
// The two differ whenever the kernel refused a limit, which is the case this
// screen exists to make visible.
func TestTheWriteAnswersWithWhatIsStoredAndNotWithWhatWasSent(t *testing.T) {
	source, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	write := strings.Index(body, "if err := Write(r.Context(), h.DB, settings); err != nil {")
	readBack := strings.Index(body, "stored, err := Read(r.Context(), h.DB)")
	switch {
	case write < 0:
		t.Fatal("the write moved; this test has to follow it")
	case readBack < 0:
		t.Fatal("the write no longer reads the settings back")
	case readBack < write:
		t.Error("the settings are read back before they are written")
	}
	if !strings.Contains(body, "h.respond(w, stored)") {
		t.Error("the write answers with something other than what was stored")
	}
}

// Write applies the limits as well as storing them. Storing the row alone
// leaves the panel reporting a limit the kernel has never heard of.
func TestSavingAlsoApplies(t *testing.T) {
	source, err := os.ReadFile("avsettings.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	update := strings.Index(body, "UPDATE av_settings SET")
	apply := strings.Index(body, "if err := ApplyLimits(s); err != nil {")
	watch := strings.Index(body, "return ApplyWatcher(s)")
	switch {
	case update < 0:
		t.Fatal("the settings are no longer stored")
	case apply < 0:
		t.Fatal("saving no longer applies the resource limits")
	case watch < 0:
		t.Fatal("saving no longer starts or stops the watcher")
	case apply < update:
		t.Error("the limits are applied before the row is stored")
	case watch < apply:
		// A watcher started before the limits are written joins a slice
		// carrying the PREVIOUS values and keeps them until something else
		// rewrites the file.
		t.Error("the watcher is applied before the limits it should run under")
	}
	// And the validation runs first, or an invalid value reaches the slice file.
	validate := strings.Index(body, "if err := s.Validate(); err != nil {")
	if validate < 0 || validate > update {
		t.Error("a settings row is stored before it is validated")
	}
}
