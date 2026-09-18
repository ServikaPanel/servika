// Package appmetrics reads what one systemd unit is actually consuming.
//
// The panel could already say whether a unit was active. It could not say how
// much memory it held, how much CPU it was taking, how many tasks it had or how
// often it had restarted, so an operator whose server was slow had no way to
// tell WHICH application was responsible without leaving the panel.
//
// Everything comes from cgroup v2 and from systemd itself. The cgroup path is
// NOT computed from the unit name: a server application sits under
// system.slice, a tenant application sits under its customer's own slice, and
// systemd is the only thing that knows where it put a unit. It is asked with
// `systemctl show -p ControlGroup`, so a slice layout that changes needs no
// change here.
package appmetrics

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Unlimited is what TasksMax reports when the cgroup says `max`.
const Unlimited = -1

const (
	showTimeout = 3 * time.Second
	diskTimeout = 5 * time.Second
	// diskTTL bounds how often `du` runs. A 500 MB tree costs hundreds of
	// milliseconds to walk and its size changes slowly, so a live answer is not
	// worth the IO on every screen refresh.
	diskTTL = 5 * time.Minute
	// minSample is the shortest interval a CPU percentage is computed over.
	// Below it the two counter reads are close enough that rounding dominates
	// the answer, so the previous percentage is kept instead.
	minSample = 500 * time.Millisecond
)

// Metrics is one snapshot of one unit.
//
// Uptime is SECONDS rather than a formatted string, because the panel renders
// twelve languages and a duration written in Go is translated in none of them.
type Metrics struct {
	Unit            string    `json:"unit"`
	CGroup          string    `json:"cgroup,omitempty"`
	MemoryBytes     int64     `json:"memory_bytes"`
	MemoryPeakBytes int64     `json:"memory_peak_bytes"`
	CPUMicros       int64     `json:"cpu_micros"`
	CPUPercent      float64   `json:"cpu_percent"`
	Tasks           int       `json:"tasks"`
	TasksMax        int       `json:"tasks_max"`
	DiskBytes       int64     `json:"disk_bytes"`
	ActiveState     string    `json:"active_state"`
	SubState        string    `json:"sub_state"`
	UptimeSeconds   int64     `json:"uptime_seconds"`
	Restarts        int       `json:"restarts"`
	At              time.Time `json:"at"`
}

// The values below are variables only so a test can point them somewhere other
// than the host. None of them is operator configuration.
var (
	cgroupRoot = "/sys/fs/cgroup"
	showUnit   = systemctlShow
	diskUsage  = duBytes
)

// cpuSample is the previous CPU counter reading for one unit. A cgroup reports
// cumulative microseconds, so a percentage needs two readings.
type cpuSample struct {
	micros int64
	at     time.Time
}

var (
	sampleMu sync.Mutex
	samples  = map[string]cpuSample{}
)

type diskEntry struct {
	bytes int64
	at    time.Time
}

var (
	diskMu    sync.Mutex
	diskCache = map[string]diskEntry{}
)

// Collect reads one unit. `tree` is the directory whose size is reported, and
// an empty one skips the disk walk.
//
// Every field degrades to its zero value on its own. A unit that is not running
// has no cgroup directory at all, and answering "0 bytes, inactive" is the
// truth; failing the whole snapshot because one file is absent would take the
// state away from the screen as well.
func Collect(ctx context.Context, unit, tree string) Metrics {
	m := Metrics{Unit: unit, At: time.Now()}
	properties, err := showUnit(ctx, unit)
	if err == nil {
		applyProperties(&m, properties)
	}
	if m.CGroup != "" {
		readCGroup(&m, filepath.Join(cgroupRoot, m.CGroup))
	}
	m.CPUPercent = cpuPercent(unit, m.CPUMicros, m.At)
	m.DiskBytes = diskBytes(ctx, tree)
	return m
}

// Forget drops the cached state of a unit that no longer exists, so a removed
// application does not hold a CPU sample and a disk size for ever.
func Forget(unit, tree string) {
	sampleMu.Lock()
	delete(samples, unit)
	sampleMu.Unlock()
	if tree == "" {
		return
	}
	diskMu.Lock()
	delete(diskCache, tree)
	diskMu.Unlock()
}

// Retain drops every cached unit that is not in the given set.
func Retain(units map[string]bool) {
	sampleMu.Lock()
	defer sampleMu.Unlock()
	for unit := range samples {
		if !units[unit] {
			delete(samples, unit)
		}
	}
}

// applyProperties copies what systemd reported into the snapshot.
func applyProperties(m *Metrics, properties map[string]string) {
	m.CGroup = properties["ControlGroup"]
	m.ActiveState = properties["ActiveState"]
	m.SubState = properties["SubState"]
	m.Restarts, _ = strconv.Atoi(properties["NRestarts"])
	m.UptimeSeconds = uptimeFrom(properties["ActiveEnterTimestamp"])
}

// uptimeFrom reads systemd's own timestamp format.
//
// systemd writes `n/a` for a unit that has never started, and an empty value or
// a bare `0` are both possible as well; none of them is a time.
func uptimeFrom(stamp string) int64 {
	stamp = strings.TrimSpace(stamp)
	if stamp == "" || stamp == "0" || stamp == "n/a" {
		return 0
	}
	started, err := time.Parse("Mon 2006-01-02 15:04:05 MST", stamp)
	if err != nil {
		return 0
	}
	seconds := int64(time.Since(started).Seconds())
	if seconds < 0 {
		return 0
	}
	return seconds
}

// readCGroup fills in what cgroup v2 reports for the unit.
func readCGroup(m *Metrics, dir string) {
	m.MemoryBytes = readInt(filepath.Join(dir, "memory.current"))
	m.MemoryPeakBytes = readInt(filepath.Join(dir, "memory.peak"))
	m.Tasks = int(readInt(filepath.Join(dir, "pids.current")))
	m.TasksMax = int(readInt(filepath.Join(dir, "pids.max")))
	m.CPUMicros = readUsage(filepath.Join(dir, "cpu.stat"))
}

// cpuPercent turns two readings of a cumulative counter into a percentage.
//
// The first reading of a unit only records a baseline and reports zero: there
// is nothing to subtract from yet, and inventing a number from one sample would
// report a busy application as idle or the reverse.
func cpuPercent(unit string, micros int64, now time.Time) float64 {
	sampleMu.Lock()
	defer sampleMu.Unlock()
	previous, seen := samples[unit]
	if !seen || micros <= 0 {
		samples[unit] = cpuSample{micros: micros, at: now}
		return 0
	}
	elapsed := now.Sub(previous.at)
	if elapsed < minSample {
		// Too close together to measure. The stored sample is deliberately NOT
		// replaced, so the next call still has a usable interval to divide by.
		return 0
	}
	delta := micros - previous.micros
	samples[unit] = cpuSample{micros: micros, at: now}
	if delta <= 0 {
		// The counter restarted with the unit.
		return 0
	}
	return float64(delta) * 100.0 / float64(elapsed.Microseconds())
}

// diskBytes answers the size of a tree, from the cache when it is fresh.
func diskBytes(ctx context.Context, tree string) int64 {
	if tree == "" {
		return 0
	}
	diskMu.Lock()
	entry, ok := diskCache[tree]
	diskMu.Unlock()
	if ok && time.Since(entry.at) < diskTTL {
		return entry.bytes
	}
	size, err := diskUsage(ctx, tree)
	if err != nil {
		return entry.bytes
	}
	diskMu.Lock()
	diskCache[tree] = diskEntry{bytes: size, at: time.Now()}
	diskMu.Unlock()
	return size
}

// systemctlShow asks systemd for the properties of one unit.
func systemctlShow(ctx context.Context, unit string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, showTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "systemctl", "show", unit,
		"-p", "ControlGroup,ActiveState,SubState,ActiveEnterTimestamp,NRestarts").Output()
	if err != nil {
		return nil, err
	}
	properties := map[string]string{}
	for line := range strings.SplitSeq(string(output), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		properties[name] = strings.TrimSpace(value)
	}
	return properties, nil
}

// duBytes measures a directory.
//
// -x stops the walk at a mount boundary, so a bind mount inside a tenant tree
// is not counted as that tenant's own bytes and cannot make the walk wander
// into another account's files.
func duBytes(ctx context.Context, tree string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, diskTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "du", "-sbx", tree).Output()
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return 0, nil
	}
	return strconv.ParseInt(fields[0], 10, 64)
}

// readInt reads one number out of a cgroup file. `max` is the literal cgroup
// writes for no limit, and it is reported as Unlimited rather than as a number.
func readInt(path string) int64 {
	// #nosec G304 -- a path under the cgroup root, built from what systemd reported.
	body, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	text := strings.TrimSpace(string(body))
	if text == "max" {
		return Unlimited
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0
	}
	return value
}

// readUsage reads usage_usec out of cpu.stat, which is a list of `name value`
// lines rather than a single number.
func readUsage(path string) int64 {
	// #nosec G304 -- a path under the cgroup root, built from what systemd reported.
	body, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for line := range strings.SplitSeq(string(body), "\n") {
		rest, found := strings.CutPrefix(line, "usage_usec ")
		if !found {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
		if err != nil {
			return 0
		}
		return value
	}
	return 0
}
