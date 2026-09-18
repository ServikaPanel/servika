package appmetrics

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These tests put a cgroup tree in a temporary directory and answer the
// systemctl call from a script, so what is measured is this package's reading
// and arithmetic rather than the host's systemd.

// fakeUnit points the package at a temporary cgroup tree and a scripted
// systemctl answer, and clears the caches so tests do not see each other.
func fakeUnit(t *testing.T, properties map[string]string, files map[string]string) {
	t.Helper()
	root := t.TempDir()

	dir := filepath.Join(root, properties["ControlGroup"])
	if properties["ControlGroup"] != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create the cgroup directory: %v", err)
		}
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	previousRoot, previousShow, previousDisk := cgroupRoot, showUnit, diskUsage
	cgroupRoot = root
	showUnit = func(context.Context, string) (map[string]string, error) { return properties, nil }
	diskUsage = func(context.Context, string) (int64, error) { return 0, errors.New("not measured") }
	t.Cleanup(func() {
		cgroupRoot, showUnit, diskUsage = previousRoot, previousShow, previousDisk
		resetCaches()
	})
	resetCaches()
}

func resetCaches() {
	sampleMu.Lock()
	samples = map[string]cpuSample{}
	sampleMu.Unlock()
	diskMu.Lock()
	diskCache = map[string]diskEntry{}
	diskMu.Unlock()
}

// A running unit reports what its cgroup holds.
func TestARunningUnitReportsItsCGroupNumbers(t *testing.T) {
	fakeUnit(t,
		map[string]string{
			"ControlGroup": "/system.slice/servika-hostapp-gitea.service",
			"ActiveState":  "active",
			"SubState":     "running",
			"NRestarts":    "3",
		},
		map[string]string{
			"memory.current": "104857600\n",
			"memory.peak":    "209715200\n",
			"pids.current":   "17\n",
			"pids.max":       "512\n",
			"cpu.stat":       "usage_usec 4200000\nuser_usec 3000000\nsystem_usec 1200000\n",
		})

	m := Collect(context.Background(), "servika-hostapp-gitea.service", "")

	if m.MemoryBytes != 104857600 || m.MemoryPeakBytes != 209715200 {
		t.Errorf("memory = %d / peak %d", m.MemoryBytes, m.MemoryPeakBytes)
	}
	if m.Tasks != 17 || m.TasksMax != 512 {
		t.Errorf("tasks = %d / max %d", m.Tasks, m.TasksMax)
	}
	if m.CPUMicros != 4200000 {
		t.Errorf("cpu = %d micros, want the usage_usec line", m.CPUMicros)
	}
	if m.ActiveState != "active" || m.SubState != "running" || m.Restarts != 3 {
		t.Errorf("state = %q/%q restarts %d", m.ActiveState, m.SubState, m.Restarts)
	}
}

// The cgroup path comes from systemd, not from the unit name. A server
// application sits under system.slice and a tenant application sits under its
// customer's own slice, so a path computed here would be wrong for one of them.
func TestTheCGroupPathComesFromSystemd(t *testing.T) {
	fakeUnit(t,
		map[string]string{
			"ControlGroup": "/servika.slice/servika-c_example.slice/servika-app-4.service",
			"ActiveState":  "active",
		},
		map[string]string{"memory.current": "512\n"})

	m := Collect(context.Background(), "servika-app-4.service", "")

	if m.CGroup != "/servika.slice/servika-c_example.slice/servika-app-4.service" {
		t.Errorf("CGroup = %q", m.CGroup)
	}
	if m.MemoryBytes != 512 {
		t.Errorf("memory = %d; the tenant slice path was not followed", m.MemoryBytes)
	}
}

// `max` in pids.max means no limit, and it is reported as Unlimited rather than
// as a number the screen would draw as a bar.
func TestAnUnlimitedTaskCeilingIsReportedAsUnlimited(t *testing.T) {
	fakeUnit(t,
		map[string]string{"ControlGroup": "/system.slice/x.service", "ActiveState": "active"},
		map[string]string{"pids.max": "max\n"})

	if got := Collect(context.Background(), "x.service", "").TasksMax; got != Unlimited {
		t.Errorf("TasksMax = %d, want Unlimited", got)
	}
}

// A unit that is not running has no cgroup directory at all. The snapshot still
// carries the state, because taking the state away would leave the screen with
// nothing to say about a stopped application.
func TestAStoppedUnitStillReportsItsState(t *testing.T) {
	fakeUnit(t,
		map[string]string{
			"ControlGroup": "",
			"ActiveState":  "inactive",
			"SubState":     "dead",
		},
		nil)

	m := Collect(context.Background(), "x.service", "")

	if m.ActiveState != "inactive" || m.SubState != "dead" {
		t.Errorf("state = %q/%q", m.ActiveState, m.SubState)
	}
	if m.MemoryBytes != 0 || m.CPUPercent != 0 {
		t.Errorf("a stopped unit reported %d bytes and %.2f%%", m.MemoryBytes, m.CPUPercent)
	}
}

// The first reading of a unit reports zero. A cgroup counts cumulative
// microseconds, so one sample cannot say what share of the last second was
// used, and inventing one would report a busy application as idle or the
// reverse.
func TestTheFirstReadingReportsNoPercentage(t *testing.T) {
	resetCaches()
	t.Cleanup(resetCaches)

	if got := cpuPercent("x.service", 1_000_000, time.Now()); got != 0 {
		t.Errorf("the first reading reported %.2f%%", got)
	}
}

// A second reading a second later, with one second of CPU consumed, is 100%.
func TestASecondReadingDividesTheDeltaByTheInterval(t *testing.T) {
	resetCaches()
	t.Cleanup(resetCaches)
	start := time.Now()
	cpuPercent("x.service", 1_000_000, start)

	got := cpuPercent("x.service", 2_000_000, start.Add(time.Second))

	if got < 99.9 || got > 100.1 {
		t.Errorf("CPU = %.2f%%, want 100", got)
	}
}

// Two readings closer together than minSample do not replace the stored sample.
// Dividing by a few milliseconds makes the answer rounding noise, and dropping
// the baseline would leave the next call with nothing to subtract from either.
func TestTwoReadingsTooCloseTogetherKeepTheBaseline(t *testing.T) {
	resetCaches()
	t.Cleanup(resetCaches)
	start := time.Now()
	cpuPercent("x.service", 1_000_000, start)

	if got := cpuPercent("x.service", 1_100_000, start.Add(10*time.Millisecond)); got != 0 {
		t.Errorf("a 10ms interval reported %.2f%%", got)
	}
	// The baseline is still the first reading, so a full interval measures from
	// it rather than from the discarded one.
	if got := cpuPercent("x.service", 2_000_000, start.Add(time.Second)); got < 99.9 || got > 100.1 {
		t.Errorf("CPU = %.2f%%, want 100 measured from the kept baseline", got)
	}
}

// A counter that went backwards means the unit restarted. That is not negative
// CPU use.
func TestARestartedCounterIsNotNegativeUse(t *testing.T) {
	resetCaches()
	t.Cleanup(resetCaches)
	start := time.Now()
	cpuPercent("x.service", 5_000_000, start)

	if got := cpuPercent("x.service", 1_000, start.Add(time.Second)); got != 0 {
		t.Errorf("a restarted counter reported %.2f%%", got)
	}
}

// systemd writes `n/a` for a unit that never started. None of the values it
// uses for "no time" is a time.
func TestAnAbsentStartTimestampIsNotAnUptime(t *testing.T) {
	for _, stamp := range []string{"", "0", "n/a", "not a date"} {
		if got := uptimeFrom(stamp); got != 0 {
			t.Errorf("uptimeFrom(%q) = %d, want 0", stamp, got)
		}
	}
}

// A real timestamp becomes seconds, so the screen formats the duration in the
// reader's own language.
func TestAStartTimestampBecomesSeconds(t *testing.T) {
	stamp := time.Now().Add(-90 * time.Second).UTC().Format("Mon 2006-01-02 15:04:05 MST")

	got := uptimeFrom(stamp)

	if got < 85 || got > 95 {
		t.Errorf("uptime = %d seconds, want about 90", got)
	}
}

// The disk size is cached, because `du` walks the whole tree.
func TestTheDiskSizeIsMeasuredOnceAndThenCached(t *testing.T) {
	resetCaches()
	previous := diskUsage
	calls := 0
	diskUsage = func(context.Context, string) (int64, error) {
		calls++
		return 4096, nil
	}
	t.Cleanup(func() { diskUsage = previous; resetCaches() })

	first := diskBytes(context.Background(), "/opt/servika-apps/gitea")
	second := diskBytes(context.Background(), "/opt/servika-apps/gitea")

	if first != 4096 || second != 4096 {
		t.Errorf("sizes = %d and %d", first, second)
	}
	if calls != 1 {
		t.Errorf("du ran %d times, want 1", calls)
	}
}

// A failed measurement keeps the last known size rather than reporting zero: a
// tree that is briefly unreadable is not a tree that became empty.
func TestAFailedMeasurementKeepsTheLastKnownSize(t *testing.T) {
	resetCaches()
	previous := diskUsage
	diskUsage = func(context.Context, string) (int64, error) { return 8192, nil }
	t.Cleanup(func() { diskUsage = previous; resetCaches() })
	diskBytes(context.Background(), "/tree")

	diskMu.Lock()
	diskCache["/tree"] = diskEntry{bytes: 8192, at: time.Now().Add(-2 * diskTTL)}
	diskMu.Unlock()
	diskUsage = func(context.Context, string) (int64, error) { return 0, errors.New("du failed") }

	if got := diskBytes(context.Background(), "/tree"); got != 8192 {
		t.Errorf("size = %d, want the last known 8192", got)
	}
}

// Forget drops a removed unit's cached state, so it does not hold a CPU sample
// and a disk size for ever.
func TestForgetDropsARemovedUnit(t *testing.T) {
	resetCaches()
	t.Cleanup(resetCaches)
	cpuPercent("gone.service", 1000, time.Now())

	Forget("gone.service", "/tree")

	sampleMu.Lock()
	_, present := samples["gone.service"]
	sampleMu.Unlock()
	if present {
		t.Error("the removed unit kept its CPU sample")
	}
}

// Retain drops every unit that is no longer installed, which is what a list
// endpoint can do in one pass.
func TestRetainDropsEveryUnitThatIsGone(t *testing.T) {
	resetCaches()
	t.Cleanup(resetCaches)
	now := time.Now()
	cpuPercent("kept.service", 1000, now)
	cpuPercent("gone.service", 1000, now)

	Retain(map[string]bool{"kept.service": true})

	sampleMu.Lock()
	_, kept := samples["kept.service"]
	_, gone := samples["gone.service"]
	sampleMu.Unlock()
	if !kept {
		t.Error("an installed unit lost its CPU sample")
	}
	if gone {
		t.Error("a removed unit kept its CPU sample")
	}
}
