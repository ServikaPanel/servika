package apps

import (
	"context"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"servika/internal/appruntime"
)

// What startup healing DOES for one application: it rewrites a unit that does
// not match the row, and it moves systemd to the state the row records.

// healedApp is the row a heal acts on.
func healedApp(enabled bool) App {
	return App{
		ID: 4, DomainID: 7, Name: "api", Runtime: "node", Version: "22",
		AppRoot: "api", Start: "node server.js", Mount: "/api/", Port: 30001, Enabled: enabled,
	}
}

// healScript answers the two queries a heal makes.
func healScript(systemUser string) *sqlScript {
	script := newScript()
	script.rows["SELECT system_user FROM domains WHERE id=?"] = [][]driver.Value{{systemUser}}
	script.rows["SELECT name, value FROM app_env"] = nil
	return script
}

// heal runs one application's repair against the fake host.
func heal(t *testing.T, script *sqlScript, app App) {
	t.Helper()
	healOne(context.Background(), scriptDB(t, script), app)
}

// A missing unit is written and the application is started.
func TestHealingWritesAMissingUnitAndStartsTheApplication(t *testing.T) {
	host := fakeHost(t)

	heal(t, healScript(testUser), healedApp(true))

	unit := host.unitBody(t, 4)
	if !strings.Contains(unit, "User="+testUser) {
		t.Fatalf("no unit was written:\n%s", unit)
	}
	if !strings.Contains(host.envBody(t, 4), "PORT=30001") {
		t.Error("the environment file was not published beside the unit")
	}
	if !host.ran("enable --now") {
		t.Errorf("the enabled application was not started: %v", host.calls)
	}
}

// A unit that already matches is left alone: rewriting it on every boot would
// reload systemd for nothing.
func TestHealingLeavesAMatchingUnitAlone(t *testing.T) {
	host := fakeHost(t)
	host.show = "ActiveState=active"
	app := healedApp(true)
	writeMatchingUnit(t, host, app)

	heal(t, healScript(testUser), app)

	if host.ran("daemon-reload") {
		t.Errorf("a matching unit was rewritten: %v", host.calls)
	}
	if host.ran("enable --now") {
		t.Errorf("a running application was started again: %v", host.calls)
	}
}

// The row says stopped. Restart=always means a process that came back on its
// own would otherwise stay up against the panel's own record.
func TestHealingStopsAnApplicationTheRowSaysIsOff(t *testing.T) {
	host := fakeHost(t)
	host.show = "ActiveState=active"
	app := healedApp(false)
	writeMatchingUnit(t, host, app)

	heal(t, healScript(testUser), app)

	if !host.ran("disable --now") {
		t.Errorf("the application the row says is off was left running: %v", host.calls)
	}
}

// writeMatchingUnit installs exactly the unit a heal would render, so the
// comparison finds no drift.
func writeMatchingUnit(t *testing.T, host *appHost, app App) {
	t.Helper()
	appDir := filepath.Join(host.home, testUser, app.AppRoot)
	interpreter, _ := resolveRuntimePath(appruntime.Node, app.Version)
	body := RenderUnit(app, testUser, appDir, []string{interpreter, "server.js"})
	if err := os.WriteFile(UnitPath(app.ID), []byte(body), 0o644); err != nil { // #nosec G306 -- a temp directory this test owns.
		t.Fatalf("plant the unit: %v", err)
	}
}

// Everything a heal refuses to act on. Each one leaves the host untouched:
// writing a unit from a row it could not fully read is worse than logging and
// moving on to the next application.
func TestHealingLeavesTheHostAloneWhenItCannotTrustTheRow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		app    App
		script func() *sqlScript
		setup  func(*testing.T, *appHost)
	}{
		{
			name: "the domain cannot be read",
			app:  healedApp(true),
			script: func() *sqlScript {
				script := healScript(testUser)
				script.fail["SELECT system_user FROM domains WHERE id=?"] = errors.New("connection lost")
				return script
			},
		},
		{
			name:   "the domain has no tenant login",
			app:    healedApp(true),
			script: func() *sqlScript { return healScript("root") },
		},
		{
			name: "the application directory would leave the home",
			app: func() App {
				app := healedApp(true)
				app.AppRoot = "../other"
				return app
			}(),
			script: func() *sqlScript { return healScript(testUser) },
		},
		{
			name: "the start command is not one",
			app: func() App {
				app := healedApp(true)
				app.Start = "  "
				return app
			}(),
			script: func() *sqlScript { return healScript(testUser) },
		},
		{
			name:   "the environment cannot be read",
			app:    healedApp(true),
			script: func() *sqlScript { return newScriptWithUnreadableEnv() },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := fakeHost(t)
			if tc.setup != nil {
				tc.setup(t, host)
			}

			heal(t, tc.script(), tc.app)

			if body := host.unitBody(t, tc.app.ID); body != "" {
				t.Errorf("a unit was written anyway:\n%s", body)
			}
			if host.ran("enable --now") || host.ran("disable --now") {
				t.Errorf("systemd was moved anyway: %v", host.calls)
			}
		})
	}
}

// newScriptWithUnreadableEnv answers the domain but refuses the environment.
func newScriptWithUnreadableEnv() *sqlScript {
	script := healScript(testUser)
	script.fail["SELECT name, value FROM app_env"] = errors.New("connection lost")
	return script
}

// A step of the rewrite that fails stops the rest of it: a unit pointing at an
// environment file that was not written would start the application without its
// database credentials.
func TestHealingStopsAtTheFirstStepThatFails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *appHost)
	}{
		{
			name:  "the environment file cannot be written",
			setup: func(t *testing.T, host *appHost) { replaceWithFile(t, host.envDir) },
		},
		{
			name:  "the log cannot be created",
			setup: func(t *testing.T, host *appHost) { replaceWithFile(t, host.logDir) },
		},
		{
			name: "the unit cannot be installed",
			setup: func(t *testing.T, host *appHost) {
				if err := os.RemoveAll(host.units); err != nil {
					t.Fatalf("remove the unit directory: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := fakeHost(t)
			tc.setup(t, host)

			heal(t, healScript(testUser), healedApp(true))

			if host.ran("enable --now") {
				t.Errorf("the application was started from a half-written host: %v", host.calls)
			}
		})
	}
}

// replaceWithFile puts a regular file where a directory belongs, so MkdirAll
// refuses.
func replaceWithFile(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("clear %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("plant a file at %s: %v", path, err)
	}
}

// A systemctl call that fails is logged and the heal moves on: the next
// application must still be repaired.
func TestHealingReportsASystemdCallThatFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		verb    string
		enabled bool
		show    string
	}{
		{name: "the application cannot be started", verb: "enable", enabled: true},
		{name: "the application cannot be stopped", verb: "disable", show: "ActiveState=active"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := fakeHost(t)
			host.failing[tc.verb] = true
			host.show = tc.show
			app := healedApp(tc.enabled)
			writeMatchingUnit(t, host, app)

			heal(t, healScript(testUser), app)

			if !host.ran(tc.verb + " --now") {
				t.Errorf("systemd was never asked: %v", host.calls)
			}
		})
	}
}

// The interpreter an application was created against is gone. Saying so is the
// whole repair: rewriting the unit against another one would run the
// application on a runtime nobody chose.
func TestHealingRefusesToRewriteAgainstADifferentRuntime(t *testing.T) {
	host := fakeHost(t)
	setForTest(t, &resolveRuntimePath, func(appruntime.Kind, string) (string, bool) { return "", false })

	heal(t, healScript(testUser), healedApp(true))

	if body := host.unitBody(t, 4); body != "" {
		t.Errorf("a unit was written against a runtime nobody chose:\n%s", body)
	}
}
