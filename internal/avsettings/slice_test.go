package avsettings

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The live update must be --runtime. Without it systemd writes a persistent
// drop-in under /etc/systemd/system.control/, which OVERRIDES the slice file
// this same function just wrote, so every later change from the screen is
// silently ignored by the kernel (measured on systemd 252).
func TestTheLiveUpdateIsRuntimeOnly(t *testing.T) {
	var calls [][]string
	restore := sliceCommand
	sliceCommand = func(name string, arg ...string) *exec.Cmd {
		calls = append(calls, append([]string{name}, arg...))
		// "true" succeeds, so is-active reports the slice as holding a process
		// and the live-update branch runs.
		return exec.Command("true")
	}
	t.Cleanup(func() { sliceCommand = restore })

	dir := t.TempDir()
	restorePath := slicePath
	slicePath = dir + "/" + SliceName
	t.Cleanup(func() { slicePath = restorePath })

	if err := ApplyLimits(Settings{CPUPercent: 150, RAMMB: 400, IOWeight: 50}); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	var setProperty []string
	for _, c := range calls {
		if len(c) > 1 && c[1] == "set-property" {
			setProperty = c
		}
	}
	if setProperty == nil {
		t.Fatalf("set-property was never called; calls: %v", calls)
	}
	if !slices.Contains(setProperty, "--runtime") {
		t.Errorf("set-property without --runtime writes a PERSISTENT drop-in that "+
			"overrides the slice file forever: %v", setProperty)
	}
	if !slices.Contains(setProperty, "CPUQuota=150%") {
		t.Errorf("the live update did not carry the new quota: %v", setProperty)
	}
}

// An earlier set-property drop-in overrides the slice file and a daemon-reload
// does not clear it, so an operator raising the limit would read the new value
// on the screen while the kernel enforced the old one. Measured on systemd 252:
// file 200%/800M plus set-property 150%/400M, then the file edited to 300%/900M,
// leaves the kernel on 150000 100000 / 419430400. `systemctl revert` clears it
// and does not delete the slice file, and the kernel follows the file again.
//
// The revert has to come BEFORE the reload; afterwards, the reload it undoes
// has already happened.
func TestAnEarlierOverrideIsClearedBeforeTheReload(t *testing.T) {
	var order []string
	restore := sliceCommand
	sliceCommand = func(name string, arg ...string) *exec.Cmd {
		if len(arg) > 0 {
			order = append(order, arg[0])
		}
		return exec.Command("true")
	}
	t.Cleanup(func() { sliceCommand = restore })

	restorePath := slicePath
	slicePath = t.TempDir() + "/" + SliceName
	t.Cleanup(func() { slicePath = restorePath })

	if err := ApplyLimits(Settings{CPUPercent: 150, RAMMB: 400, IOWeight: 50}); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	revert, reload := slices.Index(order, "revert"), slices.Index(order, "daemon-reload")
	if revert < 0 {
		t.Fatalf("an earlier override is never cleared, so the file is ignored: %v", order)
	}
	if reload < 0 {
		t.Fatalf("the manager is never reloaded: %v", order)
	}
	if revert > reload {
		t.Errorf("revert ran after the reload, so the reload it undoes already happened: %v", order)
	}
}

// A failure to clear the override is reported, not swallowed. Reporting success
// there would tell the operator a limit is in force while the kernel is still
// enforcing the previous one.
func TestAFailedRevertIsReported(t *testing.T) {
	restore := sliceCommand
	sliceCommand = func(name string, arg ...string) *exec.Cmd {
		if len(arg) > 0 && arg[0] == "revert" {
			return exec.Command("false")
		}
		return exec.Command("true")
	}
	t.Cleanup(func() { sliceCommand = restore })

	restorePath := slicePath
	slicePath = t.TempDir() + "/" + SliceName
	t.Cleanup(func() { slicePath = restorePath })

	err := ApplyLimits(Settings{CPUPercent: 150, RAMMB: 400, IOWeight: 50})
	if err == nil {
		t.Fatal("a failed revert was reported as a successful apply")
	}
	if !strings.Contains(err.Error(), "override") {
		t.Errorf("the error does not name what failed: %v", err)
	}
}

// A slice holding no process reports inactive, which is the state of every
// server before its first scan. It must not be treated as a failure to apply.
func TestAnIdleSliceIsNotAFailure(t *testing.T) {
	var calls [][]string
	restore := sliceCommand
	sliceCommand = func(name string, arg ...string) *exec.Cmd {
		calls = append(calls, append([]string{name}, arg...))
		if len(arg) > 0 && arg[0] == "is-active" {
			return exec.Command("false") // rc != 0, as an empty slice reports
		}
		return exec.Command("true")
	}
	t.Cleanup(func() { sliceCommand = restore })

	dir := t.TempDir()
	restorePath := slicePath
	slicePath = dir + "/" + SliceName
	t.Cleanup(func() { slicePath = restorePath })

	if err := ApplyLimits(Settings{CPUPercent: 150, RAMMB: 400, IOWeight: 50}); err != nil {
		t.Fatalf("an idle slice was reported as a failure: %v", err)
	}
	for _, c := range calls {
		if len(c) > 1 && c[1] == "set-property" {
			t.Errorf("set-property was called on a slice with no process: %v", c)
		}
	}
	// The file is still the persistent source of truth and must have been
	// written whatever the live state was.
	if b, err := os.ReadFile(slicePath); err != nil {
		t.Fatalf("the slice file was not written: %v", err)
	} else if !strings.Contains(string(b), "CPUQuota=150%") {
		t.Errorf("the slice file does not carry the limit:\n%s", b)
	}
}

// The production path. "I wrote a slice file" and "the kernel is enforcing a
// limit" are different claims, and only this test makes the second one. It
// writes the real unit, puts a real process in it, and reads the value out of
// the cgroup filesystem rather than out of systemd's own report.
//
// It needs root and a running systemd, so it is skipped on every development
// machine. Run it on a real host after a systemd upgrade.
func TestTheKernelReallyEnforcesTheSlice(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required: this test writes a real systemd unit")
	}
	if err := exec.Command("systemctl", "is-system-running").Run(); err != nil {
		// is-system-running exits non-zero for "degraded" too, which is fine;
		// what matters is that systemctl could talk to a manager at all.
		if _, lookErr := exec.LookPath("systemctl"); lookErr != nil {
			t.Skip("no systemd on this host")
		}
	}

	if err := ApplyLimits(Settings{CPUPercent: 150, RAMMB: 400, IOWeight: 50}); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	t.Cleanup(func() {
		_ = exec.Command("systemctl", "stop", "servika-av-selftest.service").Run()
		_ = os.Remove(slicePath)
		_ = exec.Command("systemctl", "revert", SliceName).Run()
		_ = exec.Command("systemctl", "daemon-reload").Run()
	})

	// A slice with nothing in it has no cgroup directory, so the limit has to
	// be read with a process actually placed inside.
	if out, err := exec.Command("systemd-run", "--unit=servika-av-selftest",
		"--slice="+SliceName, "sleep", "60").CombinedOutput(); err != nil {
		t.Fatalf("could not place a process in the slice: %s: %v", out, err)
	}

	group, err := exec.Command("systemctl", "show", "-p", "ControlGroup", "--value", SliceName).Output()
	if err != nil {
		t.Fatalf("the slice reports no control group: %v", err)
	}
	base := "/sys/fs/cgroup" + strings.TrimSpace(string(group))

	// 150% of one core, expressed as a quota over a 100ms period.
	if b, err := os.ReadFile(base + "/cpu.max"); err != nil {
		t.Errorf("cpu.max is unreadable: %v", err)
	} else if got := strings.TrimSpace(string(b)); got != "150000 100000" {
		t.Errorf("cpu.max = %q, want \"150000 100000\"", got)
	}
	// 400M in bytes.
	if b, err := os.ReadFile(base + "/memory.max"); err != nil {
		t.Errorf("memory.max is unreadable: %v", err)
	} else if got := strings.TrimSpace(string(b)); got != "419430400" {
		t.Errorf("memory.max = %q, want \"419430400\"", got)
	}

	// An override this package did not write pins the limit and survives every
	// reboot. An operator's own set-property produces exactly this, and so did
	// an older panel that omitted --runtime. Nothing but the revert in
	// ApplyLimits clears it, so without that step the panel would report the
	// limit it wrote while the kernel enforced 111%.
	if out, err := exec.Command("systemctl", "set-property", SliceName,
		"CPUQuota=111%", "MemoryMax=333M").CombinedOutput(); err != nil {
		t.Fatalf("could not plant a foreign override: %s: %v", out, err)
	}
	if b, err := os.ReadFile(base + "/cpu.max"); err != nil {
		t.Fatalf("cpu.max is unreadable: %v", err)
	} else if got := strings.TrimSpace(string(b)); got != "111000 100000" {
		t.Fatalf("the planted override did not take effect, so the rest of this "+
			"test proves nothing: cpu.max = %q", got)
	}

	if err := ApplyLimits(Settings{CPUPercent: 250, RAMMB: 600, IOWeight: 50}); err != nil {
		t.Fatalf("second apply failed: %v", err)
	}

	// The reload is what makes this a real assertion. `set-property --runtime`
	// wins LIVE even against a persistent drop-in, so reading the cgroup right
	// after the apply reports 250% whether or not the foreign override was
	// cleared. Measured: the very next daemon-reload hands the slice back to
	// /etc/systemd/system.control and the kernel snaps to 111000 100000. A
	// reload happens on any unit install anywhere on the server, so this is the
	// state the scan actually runs in.
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		t.Fatalf("daemon-reload failed: %s: %v", out, err)
	}
	if b, err := os.ReadFile(base + "/cpu.max"); err != nil {
		t.Errorf("cpu.max is unreadable after the second apply: %v", err)
	} else if got := strings.TrimSpace(string(b)); got != "250000 100000" {
		t.Errorf("a foreign override outlived the apply: cpu.max = %q, want \"250000 100000\"", got)
	}
	if b, err := os.ReadFile(base + "/memory.max"); err != nil {
		t.Errorf("memory.max is unreadable after the second apply: %v", err)
	} else if got := strings.TrimSpace(string(b)); got != "629145600" {
		t.Errorf("a foreign override outlived the apply: memory.max = %q, want \"629145600\"", got)
	}
}
