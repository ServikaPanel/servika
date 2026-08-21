package avsettings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A slice the panel never wrote is created IMPLICITLY by systemd with no limit
// on it at all, and the cgroup path still carries the slice name. Measured on
// real systemd: CPUQuota, MemoryMax and TasksMax all report infinity while a
// scan launched into it reports the slice in its own /proc/self/cgroup.
//
// So the path is not the question. These cases pin both halves.
func TestBeingInTheSliceIsNotTheSameAsBeingLimited(t *testing.T) {
	root := t.TempDir()
	restore := cgroupRoot
	cgroupRoot = root
	t.Cleanup(func() { cgroupRoot = restore })

	const cgroup = "/servika.slice/" + SliceName + "/servika-av-watch.service"
	sliceDir := filepath.Join(root, "servika.slice", SliceName)
	if err := os.MkdirAll(sliceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(sliceDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// 1) The implicit slice: in the right place, limited by nothing.
	write("cpu.max", "max 100000\n")
	write("memory.max", "max\n")
	write("pids.max", "max\n")
	if Confined(cgroup) {
		t.Error("a slice carrying no limit at all was reported as confining the scan")
	}

	// 2) CPU capped, memory left alone. An operator may cap one and not the
	//    other, and that is a limited scan.
	write("cpu.max", "150000 100000\n")
	if !Confined(cgroup) {
		t.Error("a CPU-capped slice was reported as unlimited")
	}

	// 3) Memory capped, CPU left alone.
	write("cpu.max", "max 100000\n")
	write("memory.max", "838860800\n")
	if !Confined(cgroup) {
		t.Error("a memory-capped slice was reported as unlimited")
	}

	// 4) Outside the slice entirely, however the limits read.
	if Confined("/system.slice/something-else.service") {
		t.Error("a cgroup outside the antivirus slice was reported as confined")
	}
}

// An unreadable cgroup counts as UNLIMITED. The other direction reports a slice
// nobody could measure as limited, which is exactly the reassurance this check
// exists to withhold.
func TestAnUnreadableCgroupIsNotReportedAsLimited(t *testing.T) {
	restore := cgroupRoot
	cgroupRoot = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { cgroupRoot = restore })

	if Confined("/servika.slice/" + SliceName + "/x.service") {
		t.Error("a cgroup that could not be read was reported as confined")
	}
}

// The slice file has to exist before the first scan, and nothing but this call
// creates it.
//
// ApplyLimits used to run only when an operator SAVED the settings screen, so
// on an installation where nobody ever did, the file did not exist. Measured on
// real systemd: systemd then creates the slice implicitly, reports CPUQuota,
// MemoryMax and TasksMax as infinity, and a sweep launched into it runs
// unlimited. End to end against the real binary and the real schema, with the
// file absent the sweep recorded confined=0 and named the reason; with the file
// this package writes, confined=1.
//
// ApplyWatcher and ApplyScheduleTimer must NOT join it: both start or restart a
// unit, and doing that at boot interrupts the watcher of an operator who
// changed nothing, on every panel restart.
func TestTheStartupPathWritesTheSliceAndStartsNoUnit(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "cmd", "server", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	main := string(body)
	if !strings.Contains(main, "avsettings.ApplyLimits(s)") {
		t.Error("the resource slice is no longer written at startup, so a server " +
			"where the settings were never saved scans with no limit at all")
	}
	for _, call := range []string{"avsettings.ApplyWatcher(", "avsettings.ApplyScheduleTimer("} {
		if strings.Contains(main, call) {
			t.Errorf("%s runs at startup, which restarts a unit on every panel restart", call)
		}
	}
}

// The cgroup path arrives from a worker that read it in another process and
// handed it back through a file, so it is confined to cgroupRoot rather than
// trusted. A traversal must not read an arbitrary file and answer with its
// first field.
func TestACgroupPathCannotEscapeTheCgroupRoot(t *testing.T) {
	root := t.TempDir()
	restore := cgroupRoot
	cgroupRoot = filepath.Join(root, "cgroup")
	t.Cleanup(func() { cgroupRoot = restore })

	if err := os.MkdirAll(cgroupRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	// A file outside the root whose first field is not "max", so reading it
	// would be reported as a real limit.
	outside := filepath.Join(root, "cpu.max")
	if err := os.WriteFile(outside, []byte("150000 100000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := readCgroupField("/../", "cpu.max"); ok {
		t.Error("a traversal read a file outside the cgroup root")
	}
	if SliceHasLimit("/../") {
		t.Error("a traversal was reported as a slice carrying a limit")
	}
}
