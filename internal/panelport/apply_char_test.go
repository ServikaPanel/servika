package panelport

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A port change rewrites the files that hold the two ports, asks nginx whether
// it accepts the result, and puts everything back when it does not. These pin
// which files each kind touches, what each refusal is called, and what the
// rollback restores.

// envFileText is the environment file a change reads its backend port from.
const envFileText = "SERVIKA_ENV=production\nSERVIKA_LISTEN=127.0.0.1:8080\nSERVIKA_DB_DSN=x\n"

// portHost is the fake host a change acts on: it records every command and
// answers the port probe from a table instead of dialling anything.
type portHost struct {
	calls []string
	// fail marks a command line fragment whose command fails.
	fail map[string]bool
	// failReloadFrom is the 1-based reload this host starts refusing at.
	failReloadFrom int
	reloads        int
	// answers maps a port to whether the probe finds something on it.
	answers  map[int]bool
	probed   []int
	domainAt string
}

// fakePortHost points every path and both seams at a directory of its own.
func fakePortHost(t *testing.T) *portHost {
	t.Helper()
	dir := t.TempDir()
	host := &portHost{fail: map[string]bool{}, answers: map[int]bool{}}

	t.Setenv("SERVIKA_ENV_FILE", filepath.Join(dir, "env"))
	t.Setenv("SERVIKA_PANEL_VHOST", filepath.Join(dir, "_panel.conf"))
	t.Setenv("SERVIKA_PANEL_DOMAIN_VHOST", filepath.Join(dir, "_panel_domain.conf"))
	t.Setenv("SERVIKA_PANEL_PORT_BACKUP_DIR", filepath.Join(dir, "backups"))
	t.Setenv("SERVIKA_PANEL_PORT_OUTCOME", filepath.Join(dir, "outcome.json"))
	t.Setenv("SERVIKA_PANEL_PORT_HELPER", filepath.Join(dir, "helper.sh"))
	host.domainAt = filepath.Join(dir, "_panel_domain.conf")

	writeFileFor(t, envPath(), envFileText)
	writeFileFor(t, panelVhostPath(), panelConf(t))

	previousRun, previousProbe := runCommand, portAnswers
	runCommand = func(_ context.Context, name string, arguments ...string) (string, error) {
		return host.answer(name, arguments)
	}
	portAnswers = func(_ context.Context, _ string, port int, _ time.Duration) bool {
		host.probed = append(host.probed, port)
		return host.answers[port]
	}
	t.Cleanup(func() { runCommand, portAnswers = previousRun, previousProbe })
	return host
}

// answer records one command and reports what the host makes of it.
func (h *portHost) answer(name string, arguments []string) (string, error) {
	line := strings.TrimSpace(name + " " + strings.Join(arguments, " "))
	h.calls = append(h.calls, line)
	if strings.Contains(line, "reload") {
		h.reloads++
		if h.failReloadFrom > 0 && h.reloads >= h.failReloadFrom {
			return "refused", errors.New("exit status 1")
		}
	}
	for fragment := range h.fail {
		if strings.Contains(line, fragment) {
			return "refused", errors.New("exit status 1")
		}
	}
	return "", nil
}

// ran reports whether a command carrying fragment was run.
func (h *portHost) ran(fragment string) bool {
	for _, call := range h.calls {
		if strings.Contains(call, fragment) {
			return true
		}
	}
	return false
}

func writeFileFor(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFileFor(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- a temp directory this test owns.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func removeFileFor(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
}

// currentPorts is what Current() reads from the fixture.
func currentPorts(t *testing.T) Ports {
	t.Helper()
	ports, err := Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	return ports
}

// A backend change moves the environment file AND the proxy_pass lines, because
// nginx would otherwise keep proxying to a port nothing is on.
func TestABackendPlanMovesTheEnvironmentAndTheProxy(t *testing.T) {
	fakePortHost(t)

	p, err := planChange(KindBackend, currentPorts(t), 9090)
	if err != nil {
		t.Fatalf("planChange: %v", err)
	}
	if p.oldPort != 8080 || p.newPort != 9090 {
		t.Errorf("plan = %+v", p)
	}
	if len(p.order) != 2 || p.order[0] != envPath() || p.order[1] != panelVhostPath() {
		t.Fatalf("order = %v, want the environment file then the vhost", p.order)
	}
	if !strings.Contains(p.files[envPath()], "SERVIKA_LISTEN=127.0.0.1:9090") {
		t.Errorf("the environment file was not moved:\n%s", p.files[envPath()])
	}
	if strings.Contains(p.files[panelVhostPath()], "127.0.0.1:8080") {
		t.Error("a proxy_pass line was left on the old port")
	}
}

// An external change moves the listen lines and does NOT touch the environment
// file: the backend keeps its own port.
func TestAnExternalPlanMovesOnlyTheListenLines(t *testing.T) {
	fakePortHost(t)

	p, err := planChange(KindExternal, currentPorts(t), 9443)
	if err != nil {
		t.Fatalf("planChange: %v", err)
	}
	if len(p.order) != 1 || p.order[0] != panelVhostPath() {
		t.Fatalf("order = %v, want only the vhost", p.order)
	}
	moved := p.files[panelVhostPath()]
	if !strings.Contains(moved, "listen 9443 ssl default_server;") ||
		!strings.Contains(moved, "listen [::]:9443 ssl default_server;") {
		t.Errorf("both listen lines did not move:\n%s", moved)
	}
	if !strings.Contains(moved, "proxy_pass http://127.0.0.1:8080;") {
		t.Error("the backend proxy moved with an external change")
	}
}

// The custom panel domain carries its own copy of both ports. A change that
// skipped it would leave that domain serving a blank page, and only for the one
// operator who set it up.
func TestTheCustomPanelDomainMovesWithThePanel(t *testing.T) {
	for _, tc := range []struct {
		name, kind, oldPort string
		newPort             int
	}{
		{"a backend change", KindBackend, "8080", 9090},
		{"an external change", KindExternal, "8443", 9443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := fakePortHost(t)
			writeFileFor(t, host.domainAt,
				"server {\n    proxy_pass http://127.0.0.1:"+tc.oldPort+";\n}\n")

			p, err := planChange(tc.kind, currentPorts(t), tc.newPort)
			if err != nil {
				t.Fatalf("planChange: %v", err)
			}
			moved, ok := p.files[panelDomainVhostPath()]
			if !ok {
				t.Fatalf("the custom domain was not in the plan: %v", p.order)
			}
			if strings.Contains(moved, ":"+tc.oldPort) {
				t.Errorf("the custom domain was left on the old port:\n%s", moved)
			}
		})
	}
}

// planCase is one refusal a plan makes before a single byte is written.
type planCase struct {
	name, kind string
	newPort    int
	setup      func(*testing.T)
	reason     string
}

func planRefusals() []planCase {
	return []planCase{
		{
			name: "the panel vhost cannot be read", kind: KindBackend, newPort: 9090,
			setup:  func(t *testing.T) { removeFileFor(t, panelVhostPath()) },
			reason: ReasonUnreadable,
		},
		{
			name: "the environment file cannot be read", kind: KindBackend, newPort: 9090,
			setup:  func(t *testing.T) { removeFileFor(t, envPath()) },
			reason: ReasonUnreadable,
		},
		{
			name: "the environment file has no listen assignment", kind: KindBackend, newPort: 9090,
			setup:  func(t *testing.T) { writeFileFor(t, envPath(), "SERVIKA_ENV=production\n") },
			reason: ReasonNotFound,
		},
		{
			name: "the vhost proxies to a different backend", kind: KindBackend, newPort: 9090,
			setup: func(t *testing.T) {
				writeFileFor(t, panelVhostPath(),
					"server {\n    listen 8443 ssl default_server;\n    proxy_pass http://127.0.0.1:7777;\n}\n")
			},
			reason: ReasonNotFound,
		},
		{
			name: "the vhost has no default_server listen line", kind: KindExternal, newPort: 9443,
			setup: func(t *testing.T) {
				writeFileFor(t, panelVhostPath(), "server {\n    listen 443 ssl;\n}\n")
			},
			reason: ReasonNotFound,
		},
		{name: "the kind is not one this moves", kind: "both", newPort: 9090, reason: ReasonUnknownKind},
		{name: "the panel is already on that port", kind: KindBackend, newPort: 8080, reason: ReasonSamePort},
	}
}

func TestAPlanRefusesWhatItCannotMove(t *testing.T) {
	for _, tc := range planRefusals() {
		t.Run(tc.name, func(t *testing.T) {
			fakePortHost(t)
			ports := currentPorts(t)
			if tc.setup != nil {
				tc.setup(t)
			}

			_, err := planChange(tc.kind, ports, tc.newPort)

			if got := ReasonOf(err); got != tc.reason {
				t.Fatalf("refused as %q (%v), want %q", got, err, tc.reason)
			}
		})
	}
}

// nginx refusing the new configuration also breaks the NEXT unrelated reload,
// so every file goes back before the refusal is reported.
func TestAConfigurationNginxRefusesIsPutBack(t *testing.T) {
	host := fakePortHost(t)
	host.fail["nginx -t"] = true
	before := readFileFor(t, panelVhostPath())

	p, err := planChange(KindExternal, currentPorts(t), 9443)
	if err != nil {
		t.Fatalf("planChange: %v", err)
	}
	_, err = writePlan(context.Background(), p)

	if got := ReasonOf(err); got != ReasonVerifyFailed {
		t.Fatalf("refused as %q (%v), want %q", got, err, ReasonVerifyFailed)
	}
	if readFileFor(t, panelVhostPath()) != before {
		t.Error("the vhost was left on the new port after nginx refused it")
	}
}

// The external change runs in process, so the request that asked for it is
// still here to be told what happened.
func TestAnExternalChangeThatAnswersIsKept(t *testing.T) {
	host := fakePortHost(t)
	host.answers[9443] = true

	if err := ApplyExternal(context.Background(), currentPorts(t), 9443); err != nil {
		t.Fatalf("ApplyExternal: %v", err)
	}
	if !strings.Contains(readFileFor(t, panelVhostPath()), "listen 9443 ssl default_server;") {
		t.Error("the vhost is not on the new port")
	}
	if !host.ran("nginx -t") || !host.ran("systemctl reload nginx") {
		t.Errorf("the change did not verify and reload: %v", host.calls)
	}
	if len(host.probed) != 1 || host.probed[0] != 9443 {
		t.Errorf("probed %v, want only the new port", host.probed)
	}
}

// Nothing answering on the new port puts the file back, and the answer names
// which of the two states the server ended in: "the change failed" and "the
// change failed and the old port is gone too" need different things from an
// operator.
func TestAnExternalChangeThatDoesNotAnswerRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name           string
		oldAnswers     bool
		failReloadFrom int
		reason         string
	}{
		{name: "the old port comes back", oldAnswers: true, reason: ReasonRolledBack},
		{name: "the old port is gone too", reason: ReasonRollbackFailed},
		{name: "nginx will not reload the old configuration", failReloadFrom: 2, reason: ReasonRollbackFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := fakePortHost(t)
			host.answers[8443] = tc.oldAnswers
			host.failReloadFrom = tc.failReloadFrom
			before := readFileFor(t, panelVhostPath())

			err := ApplyExternal(context.Background(), currentPorts(t), 9443)

			if got := ReasonOf(err); got != tc.reason {
				t.Fatalf("refused as %q (%v), want %q", got, err, tc.reason)
			}
			if readFileFor(t, panelVhostPath()) != before {
				t.Error("the vhost was left on a port nothing answers on")
			}
		})
	}
}

// A reload that fails on the first attempt is a verification failure, and it
// still reloads once more against the restored file.
func TestAnExternalChangeThatWillNotReloadIsPutBack(t *testing.T) {
	host := fakePortHost(t)
	host.failReloadFrom = 1
	before := readFileFor(t, panelVhostPath())

	err := ApplyExternal(context.Background(), currentPorts(t), 9443)

	if got := ReasonOf(err); got != ReasonVerifyFailed {
		t.Fatalf("refused as %q (%v), want %q", got, err, ReasonVerifyFailed)
	}
	if readFileFor(t, panelVhostPath()) != before {
		t.Error("the vhost was left on the new port")
	}
	if host.reloads != 2 {
		t.Errorf("reloaded %d times, want the failed one and the one after the rollback", host.reloads)
	}
	if len(host.probed) != 0 {
		t.Errorf("probed %v, want nothing after a reload that failed", host.probed)
	}
}

// A backend change cannot verify itself: moving that port restarts the process
// running the check. It writes an outcome file and hands the rest to a detached
// helper.
func TestABackendChangeHandsOffToTheHelper(t *testing.T) {
	host := fakePortHost(t)

	if err := StartBackendChange(context.Background(), currentPorts(t), 9090, 42); err != nil {
		t.Fatalf("StartBackendChange: %v", err)
	}
	outcome, ok := ReadOutcome()
	if !ok || outcome.HistoryID != 42 || outcome.State != StateRunning ||
		outcome.Kind != KindBackend || outcome.OldPort != 8080 || outcome.NewPort != 9090 {
		t.Fatalf("outcome = %+v, ok = %v", outcome, ok)
	}
	if !strings.Contains(readFileFor(t, envPath()), "SERVIKA_LISTEN=127.0.0.1:9090") {
		t.Error("the environment file is not on the new port")
	}
	if !host.ran("systemd-run --unit=" + helperUnit + " --collect " + helperPath()) {
		t.Errorf("the helper was not started: %v", host.calls)
	}
	if len(host.probed) != 0 {
		t.Errorf("probed %v, want nothing: the helper does the waiting", host.probed)
	}
	helper := readFileFor(t, helperPath())
	if !strings.Contains(helper, "NEW_PORT=9090") || !strings.Contains(helper, "OLD_PORT=8080") {
		t.Errorf("the helper does not carry both ports:\n%s", helper)
	}
	if !strings.Contains(helper, "cp -p '"+backupOf(t, envPath())+"' '"+envPath()+"'") {
		t.Errorf("the helper cannot put the environment file back:\n%s", helper)
	}
}

// backupOf returns the one backup taken for a path.
func backupOf(t *testing.T, path string) string {
	t.Helper()
	flat := strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "_")
	entries, err := os.ReadDir(backupDir())
	if err != nil {
		t.Fatalf("read the backup directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), flat+".") {
			return filepath.Join(backupDir(), entry.Name())
		}
	}
	t.Fatalf("no backup was taken for %s", path)
	return ""
}

// A helper that will not start leaves nothing behind: the files go back and the
// outcome file is cleared, so the screen does not report a change in flight
// that nothing is running.
func TestAHelperThatWillNotStartLeavesNothingBehind(t *testing.T) {
	host := fakePortHost(t)
	host.fail["systemd-run"] = true
	before := readFileFor(t, envPath())

	err := StartBackendChange(context.Background(), currentPorts(t), 9090, 42)

	if got := ReasonOf(err); got != ReasonVerifyFailed {
		t.Fatalf("refused as %q (%v), want %q", got, err, ReasonVerifyFailed)
	}
	if readFileFor(t, envPath()) != before {
		t.Error("the environment file was left on the new port")
	}
	if _, ok := ReadOutcome(); ok {
		t.Error("an outcome file was left behind")
	}
}
