package antivirus

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestOnlyTheDatabaseEngineIsUncontainable(t *testing.T) {
	// The engines that describe a file keep the button and the automatic pass.
	// Naming them explicitly rather than deriving them from a list means a new
	// engine added without thought about containment fails here rather than
	// silently losing its Contain action.
	for _, engine := range []string{"clamav", "heuristic", "wp-checksums", ""} {
		if !Containable(engine) {
			t.Errorf("%q lost its containment", engine)
		}
	}
	if Containable(EngineDatabase) {
		t.Error("a database finding was reported as containable; there is no file to move")
	}
}

// The three gates each close a different hole, so a change that keeps one and
// drops another leaves a real defect. The query stops the automatic pass
// counting a refusal as a failure, the handler stops the endpoint acting on a
// request the screen never offered, and the button stops the screen offering an
// action that can only fail.
func TestAllThreeGatesAreInPlace(t *testing.T) {
	// The automatic containment query must narrow on the engine. Without it a
	// database finding at critical level is selected, refused, and counted in
	// auto_quarantine_failed.
	auto := sourceOf(t, "autoquarantine.go")
	if !strings.Contains(auto, "f.engine <> ?") {
		t.Error("the automatic containment query does not narrow on the engine, so a database finding would be counted as a failed containment")
	}
	if !strings.Contains(auto, "EngineDatabase") {
		t.Error("the automatic containment query does not pass EngineDatabase")
	}

	// The handler must refuse before it resolves a path, because the endpoint is
	// reachable without the screen.
	handler := sourceOf(t, "quarantine.go")
	gate := regexp.MustCompile(`if !Containable\(engine\) \{\s*\n\s*return reasonNotAFile`)
	if !gate.MatchString(handler) {
		t.Error("quarantineFinding does not refuse an uncontainable engine")
	}
	// It has to come BEFORE homeRelative, or a finding whose file is not a path
	// answers av_path_outside_home, which reads as a fault on the tenant's tree
	// rather than as a finding with nothing to contain.
	if strings.Index(handler, "reasonNotAFile\n") > strings.Index(handler, "homeRelative(home, absolute)") {
		t.Error("the engine refusal runs after the path resolution")
	}
}

// The screens are the third gate, and they are in TypeScript, so the check is
// on the source. Both pages draw a Contain button, and the per-domain one used
// to gate on nothing but the quarantined flag.
func TestBothScreensGateTheContainButton(t *testing.T) {
	for _, page := range []string{
		"../../frontend/src/pages/MalwareScanPage.tsx",
		"../../frontend/src/pages/DomainAntivirusPage.tsx",
	} {
		body, err := os.ReadFile(page) // #nosec G304 -- fixed repository-relative path in a test.
		if err != nil {
			t.Fatalf("read %s: %v", page, err)
		}
		if !strings.Contains(string(body), "containable(") {
			t.Errorf("%s draws the Contain button without asking whether the finding is containable", page)
		}
	}
}
