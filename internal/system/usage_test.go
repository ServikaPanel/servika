package system

import (
	"errors"
	"strings"
	"testing"
)

type failingReader struct {
	data []byte
	err  error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

func TestScanLinesReturnsScannerError(t *testing.T) {
	readErr := errors.New("system data read failed")
	reader := &failingReader{data: []byte("first\nsecond\n"), err: readErr}
	var lines []string

	err := scanLines(reader, func(line string) bool {
		lines = append(lines, line)
		return true
	})

	if !errors.Is(err, readErr) {
		t.Fatalf("scanLines() error = %v, want %v", err, readErr)
	}
	if got := strings.Join(lines, ","); got != "first,second" {
		t.Fatalf("scanLines() visited %q, want %q", got, "first,second")
	}
}

// panel_version must report the version main is actually running, which arrives
// through StartVersionCheck. ReadInfo caches the whole SystemInfo, so a version
// copied into that cache would survive every later change; both a cold and a warm
// read are checked because only the warm one catches that.
func TestReadInfoReportsTheRunningVersion(t *testing.T) {
	versionMu.Lock()
	previousCurrent := versionCurrent
	versionCurrent = "9.9.9"
	versionMu.Unlock()
	infoCacheMu.Lock()
	previousCache := infoCache
	infoCache = nil
	infoCacheMu.Unlock()
	t.Cleanup(func() {
		versionMu.Lock()
		versionCurrent = previousCurrent
		versionMu.Unlock()
		infoCacheMu.Lock()
		infoCache = previousCache
		infoCacheMu.Unlock()
	})

	if got := ReadInfo().PanelVersion; got != "9.9.9" {
		t.Fatalf("cold ReadInfo() panel_version = %q, want %q", got, "9.9.9")
	}

	versionMu.Lock()
	versionCurrent = "9.9.10"
	versionMu.Unlock()

	if got := ReadInfo().PanelVersion; got != "9.9.10" {
		t.Fatalf("warm ReadInfo() panel_version = %q, want %q", got, "9.9.10")
	}
}

// The panel changes the hostname itself, so a cached copy would report the old
// name until the service restarts. Only the warm read catches that, which is why
// both are checked.
func TestReadInfoReportsTheCurrentHostname(t *testing.T) {
	previousRead := hostnameRead
	hostnameRead = func() (string, error) { return "before.example.com", nil }
	infoCacheMu.Lock()
	previousCache := infoCache
	infoCache = nil
	infoCacheMu.Unlock()
	t.Cleanup(func() {
		hostnameRead = previousRead
		infoCacheMu.Lock()
		infoCache = previousCache
		infoCacheMu.Unlock()
	})

	if got := ReadInfo().Hostname; got != "before.example.com" {
		t.Fatalf("cold ReadInfo() hostname = %q, want %q", got, "before.example.com")
	}

	hostnameRead = func() (string, error) { return "after.example.com", nil }

	if got := ReadInfo().Hostname; got != "after.example.com" {
		t.Fatalf("warm ReadInfo() hostname = %q, want %q", got, "after.example.com")
	}
}

func TestParseUnitStateSeparatesMissingFromStopped(t *testing.T) {
	tests := []struct {
		name              string
		output            string
		installed, active bool
	}{
		{name: "running", output: "LoadState=loaded\nActiveState=active\n", installed: true, active: true},
		{name: "stopped", output: "LoadState=loaded\nActiveState=inactive\n", installed: true},
		{name: "never installed", output: "LoadState=not-found\nActiveState=inactive\n"},
		{name: "masked counts as installed", output: "LoadState=masked\nActiveState=inactive\n", installed: true},
		{name: "failed unit is installed", output: "LoadState=loaded\nActiveState=failed\n", installed: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			installed, active := parseUnitState(tc.output)
			if installed != tc.installed || active != tc.active {
				t.Fatalf("parseUnitState() = (%v, %v), want (%v, %v)", installed, active, tc.installed, tc.active)
			}
		})
	}
}

// These two exercise the PROBE rather than ReadServices, because ReadServices
// serves a cached list and would answer with whatever the previous test left
// behind. The cache itself is covered in snapshot_test.go.
func TestProbeServicesOmitsUnitsThatAreNotInstalled(t *testing.T) {
	previous := systemctlProbe
	// Only the panel's own unit exists on this imaginary host.
	systemctlProbe = func(name string) (bool, bool) { return name == "servika", name == "servika" }
	t.Cleanup(func() { systemctlProbe = previous })

	services := probeServices()
	if len(services) != 1 {
		t.Fatalf("probeServices() returned %d services, want only the installed one", len(services))
	}
	if services[0].Name != "servika" || !services[0].Enabled {
		t.Fatalf("probeServices() returned %+v, want the running servika unit", services[0])
	}
}

// A systemctl that cannot be run must not empty the list: reporting nothing would
// read as "this host has no services", which is a worse lie than the old
// everything-is-down list.
func TestProbeServicesKeepsEveryUnitWhenSystemctlIsUnavailable(t *testing.T) {
	previous := systemctlProbe
	systemctlProbe = func(string) (bool, bool) { return true, false }
	t.Cleanup(func() { systemctlProbe = previous })

	if got, want := len(probeServices()), len(serviceList); got != want {
		t.Fatalf("probeServices() returned %d services, want all %d", got, want)
	}
}

func TestScanLinesStopsWhenVisitorRequests(t *testing.T) {
	var lines []string

	err := scanLines(strings.NewReader("first\nsecond\n"), func(line string) bool {
		lines = append(lines, line)
		return false
	})

	if err != nil {
		t.Fatalf("scanLines() returned an unexpected error: %v", err)
	}
	if got := strings.Join(lines, ","); got != "first" {
		t.Fatalf("scanLines() visited %q, want %q", got, "first")
	}
}
