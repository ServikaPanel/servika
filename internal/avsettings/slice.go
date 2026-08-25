package avsettings

// The cgroup the scan runs in, and the proof that it is real.
//
// Three facts decide everything here, and none of them is visible from the code
// alone. All were measured against systemd 252 on AlmaLinux 9 with cgroup v2.
//
// A `systemctl set-property` drop-in OVERRIDES the unit file, and a
// daemon-reload does not clear it. Measured: a slice file at 200%/800M plus a
// set-property of 150%/400M leaves the kernel on 150000 100000 / 419430400, and
// editing the file to 300%/900M afterwards changes NOTHING. WITHOUT --runtime
// that drop-in lands in /etc/systemd/system.control/ and survives reboots, so
// the limit is pinned for good and the screen reports a number the kernel has
// never enforced. WITH --runtime it lands in /run and is gone at the next boot.
// That is the whole difference, and it is why the live update carries the flag,
// which is what internal/resourcelimit already does for tenant slices.
//
// A stale drop-in from THIS package cannot accumulate during one boot, because
// a slice stays active once its first unit has run (measured: it still reports
// active after that unit stops) and every apply from then on refreshes the
// drop-in with the value it just wrote to the file. What CAN be there is an
// override this package did not write: an operator's own `systemctl
// set-property`, or an older panel that wrote a persistent one. `systemctl
// revert` clears both, and it does NOT delete this package's own slice file
// (measured: it removed the /etc and /run drop-ins, left the slice file in
// place, and the kernel went back to the file's value). That holds only because
// no vendor unit of this name exists, so the file is not an override of
// anything.
//
// A slice holding no process reports inactive (rc=3), so the live-update branch
// does not run before the first scan. That is not a failure: `systemctl show`
// on an inactive slice already reports the file's values, and the first scan
// launched into it is confined by them (measured: cpu.max 200000 100000).
//
// The name is servika-av.slice, which systemd resolves under an implicit
// servika.slice parent (measured), beside every servika-c_<user>.slice a tenant
// gets.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	// SliceName is the cgroup a scan is launched into.
	SliceName = "servika-av.slice"
	sliceDir  = "/etc/systemd/system"
)

// slicePath is where the persistent definition lives. It is a variable so a
// test can assert what was written without needing root and without touching
// the host's real systemd directory.
var slicePath = sliceDir + "/" + SliceName

// sliceCommand is replaceable in tests. Nothing here may run systemctl during
// an ordinary test run.
var sliceCommand = exec.Command

// TasksMax bounds how many processes the scan may fan out into. It is not a
// setting: the scan is one process plus at most one clamscan child, so a
// ceiling here only bounds a runaway and has nothing for an operator to tune.
const sliceTasksMax = 64

// SliceContent renders the slice definition for a settings row. It is separate
// from ApplyLimits so a test can assert the rendering without a systemd.
func SliceContent(s Settings) string {
	e := s.Resolve(ServerCapacity())
	return fmt.Sprintf(`# Servika malware scan resource slice, managed by the panel.
# DO NOT EDIT; change it from the panel (Antivirus, resource limits).
#
# A scan is I/O and CPU heavy. An unlimited scanner slows down the very sites it
# is protecting, so it becomes an outage of its own. These limits are enforced
# by the KERNEL; an in-process "go slower" loop is not enforced by anything.
[Unit]
Description=Servika malware scan slice
Before=slices.target

[Slice]
CPUAccounting=yes
MemoryAccounting=yes
IOAccounting=yes
TasksAccounting=yes

# CPUQuota is a CEILING and CPUWeight is a SHARE. The ceiling is the same on an
# idle server and on a busy one, so without a weight the scan takes its quota
# out of real traffic exactly when there is real traffic. A weight costs nothing
# while nobody else wants the processor.
CPUQuota=%d%%
CPUWeight=%d
MemoryMax=%dM
MemoryHigh=%dM
IOWeight=%d
TasksMax=%d
`, e.CPUPercent, e.CPUWeight, e.RAMMB, e.RAMMB*90/100, e.IOWeight, sliceTasksMax)
}

// ApplyLimits writes the slice and, when it already holds a running scan,
// updates the live cgroup too.
func ApplyLimits(s Settings) error {
	// #nosec G306 -- root-owned systemd unit that the manager must read; no secret is stored here.
	if err := os.WriteFile(slicePath, []byte(SliceContent(s)), 0644); err != nil {
		return fmt.Errorf("write av slice: %w", err)
	}
	// Drop any set-property override BEFORE reloading, or the file just written
	// is ignored and the kernel keeps enforcing whatever wrote that override.
	// This package cannot leave a stale one behind within a boot, but an
	// operator's own set-property or an older panel's persistent drop-in can,
	// and nothing else on this path would ever clear it.
	if out, err := sliceCommand("systemctl", "revert", SliceName).CombinedOutput(); err != nil {
		return fmt.Errorf("clear earlier av slice overrides: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if out, err := sliceCommand("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("daemon-reload: %s: %w", strings.TrimSpace(string(out)), err)
	}
	// Only a slice that currently holds a process can be updated live, and the
	// file above is what a later scan will read anyway.
	if err := sliceCommand("systemctl", "is-active", "--quiet", SliceName).Run(); err != nil {
		return nil
	}
	e := s.Resolve(ServerCapacity())
	out, err := sliceCommand("systemctl", "set-property", "--runtime", SliceName,
		fmt.Sprintf("CPUQuota=%d%%", e.CPUPercent),
		fmt.Sprintf("CPUWeight=%d", e.CPUWeight),
		fmt.Sprintf("MemoryMax=%dM", e.RAMMB),
		fmt.Sprintf("MemoryHigh=%dM", e.RAMMB*90/100),
		fmt.Sprintf("IOWeight=%d", e.IOWeight)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("update running av slice: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// Kernel state values that are not a measurement.
const (
	// KernelUnmeasured means systemd could not be asked at all.
	KernelUnmeasured = "unmeasured"
	// KernelIdle means the slice is defined but holds no process yet, so there
	// is nothing for the kernel to be enforcing. It is NOT a failure, and
	// reporting it as one would make every server look broken until its first
	// scan.
	KernelIdle = "idle"
)

// KernelLimits is what systemd reports for the slice right now.
type KernelLimits struct {
	// Active is false while the slice holds no process.
	Active bool `json:"active"`
	// Values are systemd's own property names and its own answers, unedited.
	Values map[string]string `json:"values"`
}

// ReadKernelLimits asks systemd what it is enforcing, rather than reporting
// what was written.
//
// "I wrote the limit" and "the kernel is enforcing it" are different claims,
// and the screen shows this one beside the stored row so an operator reads the
// second rather than inferring it from the first.
func ReadKernelLimits() KernelLimits {
	k := KernelLimits{Values: map[string]string{}}
	k.Active = sliceCommand("systemctl", "is-active", "--quiet", SliceName).Run() == nil
	for _, property := range []string{"CPUQuotaPerSecUSec", "CPUWeight", "MemoryMax", "MemoryHigh", "IOWeight", "TasksMax"} {
		b, err := sliceCommand("systemctl", "show", "-p", property, "--value", SliceName).Output()
		if err != nil {
			k.Values[property] = KernelUnmeasured
			continue
		}
		value := strings.TrimSpace(string(b))
		if value == "" {
			value = KernelUnmeasured
		}
		k.Values[property] = value
	}
	return k
}
