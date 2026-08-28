package phpversion

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// opPaths points the job's three files at a temporary directory, so a test never
// touches /opt/servika.
func opPaths(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SERVIKA_PHPOP_LOG", filepath.Join(dir, "php-op.log"))
	t.Setenv("SERVIKA_PHPOP_STATE", filepath.Join(dir, "php-op.json"))
	t.Setenv("SERVIKA_PHPOP_WRAPPER", filepath.Join(dir, "php-op.sh"))
	return dir
}

// stubUnit reports a fixed systemd state and captures the script that would have
// been run, so the whole job surface works on a host without systemd.
func stubUnit(t *testing.T, state string, started *string) {
	t.Helper()
	originalState, originalLaunch := phpOpState, launchPHPOp
	phpOpState = func() string { return state }
	launchPHPOp = func(script string) error {
		if started != nil {
			*started = script
		}
		return nil
	}
	t.Cleanup(func() { phpOpState, launchPHPOp = originalState, originalLaunch })
}

func remiVersion(t *testing.T) VersionMetadata {
	t.Helper()
	for _, m := range SupportedVersions {
		if m.Resource == "remi" {
			return m
		}
	}
	t.Fatal("no Remi version is declared")
	return VersionMetadata{}
}

// The unit is the only truth about whether work is in flight. "activating"
// counts: systemd-run has returned but dnf has not taken the rpm lock yet, and a
// second operation started in that window meets the first one's transaction.
func TestAnOperationCountsAsRunningWhileTheUnitIsStarting(t *testing.T) {
	for _, state := range []string{"active", "activating"} {
		stubUnit(t, state, nil)
		if !phpOpRunning() {
			t.Errorf("state %q was not treated as running", state)
		}
	}
	// The other direction: a finished or absent unit must not block the next
	// operation, or one install would lock the screen for good.
	for _, state := range []string{"inactive", "failed", "unknown", ""} {
		stubUnit(t, state, nil)
		if phpOpRunning() {
			t.Errorf("state %q was treated as running", state)
		}
	}
}

// The screen polls the log while an operation runs, so an unbounded read would
// pull a runaway dnf transaction into memory on every tick.
func TestTheLogTailIsBoundedAndKeepsTheEnd(t *testing.T) {
	opPaths(t)
	body := strings.Repeat("a", maxOpLogBytes) + "THE-LAST-LINE"
	if err := os.WriteFile(os.Getenv("SERVIKA_PHPOP_LOG"), []byte(body), 0o640); err != nil {
		t.Fatalf("write the log: %v", err)
	}

	tail := readOpLog()
	if len(tail) != maxOpLogBytes {
		t.Errorf("tail = %d bytes, want %d", len(tail), maxOpLogBytes)
	}
	// The END is what matters: the beginning of a long dnf run is scrollback, the
	// end is what the operation is doing now.
	if !strings.HasSuffix(tail, "THE-LAST-LINE") {
		t.Error("the tail did not keep the end of the log")
	}
}

// A log shorter than the ceiling has to come back whole, or the bound above
// would be indistinguishable from returning nothing.
func TestAShortLogIsReturnedWhole(t *testing.T) {
	opPaths(t)
	if err := os.WriteFile(os.Getenv("SERVIKA_PHPOP_LOG"), []byte("two\nlines\n"), 0o640); err != nil {
		t.Fatalf("write the log: %v", err)
	}
	if tail := readOpLog(); tail != "two\nlines\n" {
		t.Errorf("tail = %q, want the whole log", tail)
	}
}

// The unit's own state does not say WHICH version is being worked on, so the
// descriptor is what lets a reopened page name it.
func TestStatusReportsWhichVersionIsBeingWorkedOn(t *testing.T) {
	opPaths(t)
	stubUnit(t, "active", nil)
	m := remiVersion(t)

	if err := startPHPOp(opDescriptor{Version: m.Version, Resource: m.Resource, Action: "install"},
		installScript(m)); err != nil {
		t.Fatalf("startPHPOp: %v", err)
	}

	recorder := httptest.NewRecorder()
	(&Handlers{}).Status(recorder, httptest.NewRequest("GET", "/php-versions/status", nil))
	if recorder.Code != 200 {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var payload struct {
		Running  bool   `json:"running"`
		Version  string `json:"version"`
		Resource string `json:"resource"`
		Action   string `json:"action"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	if !payload.Running || payload.Version != m.Version || payload.Resource != m.Resource || payload.Action != "install" {
		t.Errorf("payload = %+v, want the running install of %s", payload, m.Version)
	}
}

// With nothing ever started the screen must be told so, rather than resuming an
// operation that does not exist.
func TestStatusReportsNothingWhenNoOperationEverRan(t *testing.T) {
	opPaths(t)
	stubUnit(t, "inactive", nil)

	recorder := httptest.NewRecorder()
	(&Handlers{}).Status(recorder, httptest.NewRequest("GET", "/php-versions/status", nil))
	var payload struct {
		Running bool   `json:"running"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	if payload.Running || payload.Version != "" {
		t.Errorf("payload = %+v, want nothing running", payload)
	}
}

// The log is truncated at the start of an operation: the screen shows it as the
// output of the run it just began, and the previous run's output above it would
// read as part of this one.
func TestStartingAnOperationClearsThePreviousLog(t *testing.T) {
	opPaths(t)
	stubUnit(t, "activating", nil)
	if err := os.WriteFile(os.Getenv("SERVIKA_PHPOP_LOG"), []byte("output of an older run\n"), 0o640); err != nil {
		t.Fatalf("seed the log: %v", err)
	}

	m := remiVersion(t)
	if err := startPHPOp(opDescriptor{Version: m.Version, Resource: m.Resource, Action: "remove"},
		removeScript(m)); err != nil {
		t.Fatalf("startPHPOp: %v", err)
	}
	if strings.Contains(readOpLog(), "older run") {
		t.Error("the previous run's output survived into the new operation's log")
	}
}

// The handler no longer waits for dnf, so everything that used to run after it
// returned has to be in the script instead. A step left behind would produce a
// PHP that installs and then serves nothing.
func TestTheInstallScriptCarriesTheWholeSequence(t *testing.T) {
	opPaths(t)
	var script string
	stubUnit(t, "inactive", &script)
	m := remiVersion(t)

	if err := startPHPOp(opDescriptor{Version: m.Version, Resource: m.Resource, Action: "install"},
		installScript(m)); err != nil {
		t.Fatalf("startPHPOp: %v", err)
	}
	poolDir, _, service, _ := paths(m)
	for _, fragment := range []string{
		"dnf install -y", poolDir, "www.conf.disabled",
		"99-servika-input.ini", "max_input_vars = 10000",
		"systemctl enable --now", service,
	} {
		if !strings.Contains(script, fragment) {
			t.Errorf("the install script does not carry %q", fragment)
		}
	}
}

// A removal must stop the service before dnf, or packages are pulled out from
// under a pool that is still serving.
func TestTheRemoveScriptStopsTheServiceFirst(t *testing.T) {
	opPaths(t)
	var script string
	stubUnit(t, "inactive", &script)
	m := remiVersion(t)

	if err := startPHPOp(opDescriptor{Version: m.Version, Resource: m.Resource, Action: "remove"},
		removeScript(m)); err != nil {
		t.Fatalf("startPHPOp: %v", err)
	}
	stop := strings.Index(script, "systemctl disable --now")
	remove := strings.Index(script, "dnf remove -y")
	if stop == -1 || remove == -1 {
		t.Fatalf("the remove script is missing a step: %q", script)
	}
	if stop > remove {
		t.Error("dnf runs before the service is stopped")
	}
}

// Nothing caller-supplied reaches the wrapper today, and quoting is what keeps
// that true if a version code is ever less tame than "83".
func TestShellQuotingSurvivesAQuoteInAValue(t *testing.T) {
	got := shellQuote(`a'b`)
	if got != `'a'\''b'` {
		t.Errorf("shellQuote = %s, want the value in one quoted word", got)
	}
}

// The IonCube hook is appended AFTER the service is enabled, so the pool it
// reloads exists, and only when the hook is set, so an install job is unchanged
// on a build that never wired it.
func TestTheInstallScriptAppendsTheIonCubeHook(t *testing.T) {
	m := remiVersion(t)

	if strings.Contains(installScript(m), "IONCUBE-HOOK") {
		t.Fatal("the install script carried the hook while it was unset")
	}

	IonCubePostInstall = func(version string) string { return "\nIONCUBE-HOOK " + version + "\n" }
	t.Cleanup(func() { IonCubePostInstall = nil })

	script := installScript(m)
	marker := strings.Index(script, "IONCUBE-HOOK "+m.Version)
	if marker == -1 {
		t.Fatalf("the install script did not append the hook: %q", script)
	}
	enable := strings.Index(script, "systemctl enable --now")
	done := strings.Index(script, "Done: PHP")
	if enable == -1 || done == -1 || enable >= marker || marker >= done {
		t.Errorf("the hook is not between enabling the service and the final line (enable=%d hook=%d done=%d)", enable, marker, done)
	}
}
