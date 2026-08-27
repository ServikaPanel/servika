// Package avsettings holds what the malware scanner inspects, what it may do
// about what it finds, and what the kernel lets it spend doing so.
//
// It imports nothing from the rest of the panel on purpose. internal/antivirus
// reads these settings on every scan, so anything this package imported would
// become an import of internal/antivirus too, and the settings would stop being
// something a scheduler or a handler can read on its own.
//
// The resource limits are not merely a database row. Saving them is not the
// same as applying them, and applying them is not the same as the kernel
// enforcing them: a child process started by a service joins the SERVICE's
// cgroup, so a slice file on disk confines nothing until something is launched
// into that slice. This package writes the file and reads back what the kernel
// actually reports, and the two are shown side by side rather than merged.
package avsettings

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Scope values. 'host' walks the tenant trees only; 'server' walks the whole
// filesystem with the exclusion list applied.
const (
	ScopeHost   = "host"
	ScopeServer = "server"
)

// MinCriticalThreshold is the lowest critical score an operator may set.
//
// A zero or negative threshold would make every inspected file critical, and
// with auto-quarantine on that empties a live site. The floor is not a
// judgement about tuning; it is the point below which the setting stops
// describing malware at all.
const MinCriticalThreshold = 20

// Settings is one row of av_settings. Every field here has a consumer; see the
// migration for why the three upstream settings that had none are absent.
type Settings struct {
	RuleEngine         bool   `json:"rule_engine"`
	LocationHeuristics bool   `json:"location_heuristics"`
	WPIntegrity        bool   `json:"wp_integrity"`
	CriticalThreshold  int    `json:"critical_threshold"`
	AutoQuarantine     bool   `json:"auto_quarantine"`
	Scope              string `json:"scope"`
	ExcludedPaths      string `json:"excluded_paths"`
	CPUPercent         int    `json:"cpu_percent"`
	RAMMB              int    `json:"ram_mb"`
	IOWeight           int    `json:"io_weight"`
	// CPUWeight is the scan's SHARE of a contended processor, which is a
	// different question from CPUPercent, its ceiling. The ceiling is the same
	// whether the server is idle or busy, so it is taken out of real traffic
	// exactly when there is real traffic; the weight is what decides who yields.
	CPUWeight      int  `json:"cpu_weight"`
	ScheduledScan  bool `json:"scheduled_scan"`
	ScheduledHour  int  `json:"scheduled_hour"`
	Realtime       bool `json:"realtime"`
	ScanWorkers    int  `json:"scan_workers"`
	FileRatePerSec int  `json:"file_rate_per_sec"`
}

// Capacity is what this server actually has, and what the panel proposes when a
// limit is left on automatic.
//
// The screen shows it so an operator sizing a limit sees "two of eight cores"
// rather than an abstract percentage. Choosing a ceiling without knowing what
// is being capped is not a decision.
type Capacity struct {
	CPUCores       int `json:"cpu_cores"`
	TotalRAMMB     int `json:"total_ram_mb"`
	SuggestCPUPct  int `json:"suggest_cpu_percent"`
	SuggestRAMMB   int `json:"suggest_ram_mb"`
	SuggestWorkers int `json:"suggest_workers"`
}

// Effective is a Settings after every "0 = automatic" has been resolved.
type Effective struct {
	CPUPercent     int `json:"cpu_percent"`
	RAMMB          int `json:"ram_mb"`
	IOWeight       int `json:"io_weight"`
	CPUWeight      int `json:"cpu_weight"`
	ScanWorkers    int `json:"scan_workers"`
	FileRatePerSec int `json:"file_rate_per_sec"`
}

// Reason codes for a refused write. The screen renders twelve languages, so the
// refusal has to be identifiable without reading its English sentence.
const (
	ReasonScopeInvalid     = "av_scope_invalid"
	ReasonThresholdTooLow  = "av_threshold_too_low"
	ReasonIOWeightRange    = "av_io_weight_out_of_range"
	ReasonNegativeLimit    = "av_limit_negative"
	ReasonHourOutOfRange   = "av_scheduled_hour_out_of_range"
	ReasonCPUPercentTooBig = "av_cpu_percent_too_large"
	ReasonRAMTooSmall      = "av_ram_too_small"
	ReasonRAMTooLarge      = "av_ram_too_large"
	ReasonWorkersRange     = "av_scan_workers_out_of_range"
	ReasonFileRateRange    = "av_file_rate_out_of_range"
	ReasonCPUWeightRange   = "av_cpu_weight_out_of_range"
)

// Refusal carries a stable code beside its English message.
type Refusal struct {
	Code    string
	Message string
}

func (r *Refusal) Error() string { return r.Message }

func refuse(code, msg string) error { return &Refusal{Code: code, Message: msg} }

// ReasonCode reports the stable code behind an error, or "" when the error is
// not a refusal (a database failure, for example, which is not the operator's
// input being wrong).
func ReasonCode(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

// minRAMMB is the floor for a manually set memory ceiling.
//
// The scanner's own working set scales with the rule count rather than with
// file size, but it still has to hold one file's read window (3 MiB for PHP)
// plus the Go runtime. A ceiling below this does not slow the scan down, it
// makes the kernel kill it, and a scan that is killed reports a partial sweep.
const minRAMMB = 128

// maxCPUPercent bounds a manually set CPU quota at 64 full cores. systemd
// accepts a quota larger than the machine has, which then means "no limit"
// while the screen still shows a number.
const maxCPUPercent = 6400

// MaxScanWorkers bounds how many files the sweep inspects at once.
//
// The ceiling is set by the slice, not by taste. The scan runs inside
// servika-av.slice, which carries TasksMax=64, and that counts every THREAD in
// the cgroup: the Go runtime's own threads plus one per worker plus whatever a
// clamscan subprocess adds. Letting an operator ask for 64 workers means the
// kernel refuses to create the last of them, and a scan short of workers looks
// exactly like a slow scan. Half the slice's budget leaves room for everything
// that is not a worker.
const MaxScanWorkers = 32

// MaxFileRatePerSec bounds the files-per-second ceiling.
//
// The rate becomes a ticker interval of time.Second/rate, and NewTicker PANICS
// on a non-positive duration. At this ceiling the interval is 10 microseconds,
// which is far faster than any disk can serve a file anyway, so the bound costs
// nothing real and removes the value that would crash the worker.
const MaxFileRatePerSec = 100000

// MaxCgroupWeight is the ceiling systemd accepts for CPUWeight and IOWeight.
// Both map to the same cgroup v2 idea, so they share one bound.
const MaxCgroupWeight = 10000

// defaultCPUWeight is what a CPU weight of 0 resolves to.
//
// It is the same number IOWeight already resolves to, and for the same reason:
// the scan is worth half of a site it is protecting. A weight is a SHARE, so
// this costs nothing on an idle server. Measured on cgroup v2 with both groups
// pinned to one core, a weight-10 group alone took 99% of that core, and the
// same group against a weight-100 group took 9% while the other took 90%.
//
// It is deliberately not 1. A scan that never gets the processor under
// sustained load never finishes, and a sweep that ran out of its budget is
// recorded as a partial one, which is the answer this whole feature exists to
// avoid producing every night.
const defaultCPUWeight = 50

// ServerCapacity MEASURES the host. It never assumes.
func ServerCapacity() Capacity {
	c := Capacity{CPUCores: runtime.NumCPU()}
	c.TotalRAMMB = totalRAMMB()

	// systemd reads CPUQuota as a percentage of ONE core: 100% is a whole core,
	// so a quarter of an eight-core server is 200%. A quarter is a defensible
	// ceiling for work whose whole purpose is to protect sites it must not slow
	// down, and the operator can raise it from the screen.
	// A half-core floor keeps the scan usable on a single-core server.
	c.SuggestCPUPct = max(c.CPUCores*100/4, 50)

	// Memory: an eighth of the machine, floor 256M, ceiling 2048M. The scanner
	// reads one file at a time against a bounded window, so a larger ceiling
	// buys nothing and only delays the point at which a runaway is stopped.
	c.SuggestRAMMB = c.TotalRAMMB / 8
	switch {
	case c.SuggestRAMMB < 256:
		c.SuggestRAMMB = 256
	case c.SuggestRAMMB > 2048:
		c.SuggestRAMMB = 2048
	}

	c.SuggestWorkers = suggestWorkers(c.SuggestCPUPct)
	return c
}

// suggestWorkers derives a pool size from the CPU quota rather than from the
// core count. The quota is what the kernel will actually let the scan run, so a
// worker beyond it does not scan a file sooner: it waits in the run queue while
// holding its share of the memory ceiling. One worker per full core of quota,
// floor 1, capped at the slice's budget.
func suggestWorkers(cpuPct int) int {
	return min(max(cpuPct/100, 1), MaxScanWorkers)
}

// totalRAMMB reads MemTotal. It returns 0 where /proc/meminfo does not exist,
// which is every non-Linux development machine: the suggestion clamps above
// turn that into the 256M floor rather than into a limit of zero, so a value
// this could not measure never becomes a ceiling that stops the scan.
func totalRAMMB() int {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0
		}
		return kb / 1024
	}
	return 0
}

// Resolve turns "0 = automatic" into the values that will actually be applied.
//
// What the panel SHOWS and what is written into the slice go through this one
// function. Computing them separately is how a screen ends up reporting one
// limit while the kernel enforces another.
func (s Settings) Resolve(c Capacity) Effective {
	e := Effective{CPUPercent: s.CPUPercent, RAMMB: s.RAMMB, IOWeight: s.IOWeight}
	if e.CPUPercent <= 0 {
		e.CPUPercent = c.SuggestCPUPct
	}
	if e.RAMMB <= 0 {
		e.RAMMB = c.SuggestRAMMB
	}
	if e.IOWeight <= 0 {
		e.IOWeight = 50
	}
	// A weight of 0 never reaches the slice. systemd REFUSES CPUWeight=0 with
	// "Numerical result out of range" and then IGNORES the line, leaving the
	// kernel default of 100, so the scan would silently compete with tenant
	// sites on equal footing while the screen showed a number.
	e.CPUWeight = s.CPUWeight
	if e.CPUWeight <= 0 {
		e.CPUWeight = defaultCPUWeight
	}
	e.ScanWorkers = s.ScanWorkers
	if e.ScanWorkers <= 0 {
		e.ScanWorkers = c.SuggestWorkers
	}
	// A capacity that was never measured leaves SuggestWorkers at zero, and a
	// worker pool of zero scans nothing at all rather than scanning slowly.
	if e.ScanWorkers <= 0 {
		e.ScanWorkers = 1
	}
	// The file rate has no automatic value: 0 means no ceiling, which is what
	// an operator who has not thought about it should get.
	e.FileRatePerSec = s.FileRatePerSec
	return e
}

// ScanRoots reports the directories a sweep walks.
//
// The default is 'host', which is /home alone. Walking the whole filesystem
// cannot be the default: a scanner inside /var/lib/mysql is reading data files
// no PHP-FPM pool will ever execute, and it burns the disk I/O of every site on
// the server to do it. An operator has to choose that deliberately.
func (s Settings) ScanRoots() []string {
	if s.Scope == ScopeServer {
		return []string{"/"}
	}
	return []string{"/home"}
}

// ExcludedList splits the stored exclusion list into entries.
func (s Settings) ExcludedList() []string {
	var out []string
	for line := range strings.SplitSeq(s.ExcludedPaths, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// Excluded reports whether a path is covered by the exclusion list.
//
// An entry starting with "/" is an absolute PREFIX and matches at a path
// separator only, so excluding /var never excludes /variable. Any other entry
// is a relative name matched against WHOLE path segments.
func (s Settings) Excluded(path string) bool { return PathExcluded(s.ExcludedList(), path) }

// PathExcluded is the same test against an explicit list.
//
// The scan runs in a separate process that has no database connection, so it
// receives the list in its request rather than reading the settings row. Both
// sides call this one function, or the screen would describe an exclusion the
// scanner does not apply. The real-time watcher calls it too, so a hole here is
// a hole in every detection path at once.
//
// A relative entry matches a whole SEGMENT and never a substring. The
// substring form was an escape, not a convenience: measured against the list
// this panel used to seed, `/home/c_x/public_html/wp-content/uploads/node_modules/shell.php`
// was excluded, so a tenant who could write a directory anywhere under their
// document root hid a webshell from the sweep AND from the watcher by running
// `mkdir node_modules`. Nothing reported it, because an excluded file is not a
// file that was inspected and cleared.
//
// Segment matching alone does not close that, which is why migration 0109 also
// removes the relative entries this panel seeded: a real `node_modules` segment
// is still excluded, wherever it sits. What segment matching closes is the
// other half, where `notnode_modulesbar` matched a rule written for
// `node_modules`.
func PathExcluded(list []string, path string) bool {
	path = filepath.ToSlash(path)
	for _, e := range list {
		e = filepath.ToSlash(e)
		if strings.HasPrefix(e, "/") {
			// Trailing slashes are trimmed so "/var/cache" and "/var/cache/"
			// mean the same thing. An operator types both.
			prefix := strings.TrimRight(e, "/")
			if prefix == "" {
				// "/" alone would exclude the whole filesystem and is almost
				// certainly a typo. Refusing it here rather than at the write
				// path as well, because the list travels through a request file
				// that outlives the code that wrote it.
				continue
			}
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				return true
			}
			continue
		}
		segment := strings.Trim(e, "/")
		if segment == "" {
			continue
		}
		for part := range strings.SplitSeq(path, "/") {
			if part == segment {
				return true
			}
		}
	}
	return false
}

// Read loads the single settings row.
func Read(ctx context.Context, db *sql.DB) (Settings, error) {
	var s Settings
	err := db.QueryRowContext(ctx, `SELECT rule_engine, location_heuristics, wp_integrity,
		critical_threshold, auto_quarantine, scope, excluded_paths,
		cpu_percent, ram_mb, io_weight, cpu_weight, scheduled_scan, scheduled_hour,
		realtime, scan_workers, file_rate_per_sec
		FROM av_settings WHERE id=1`).
		Scan(&s.RuleEngine, &s.LocationHeuristics, &s.WPIntegrity,
			&s.CriticalThreshold, &s.AutoQuarantine, &s.Scope, &s.ExcludedPaths,
			&s.CPUPercent, &s.RAMMB, &s.IOWeight, &s.CPUWeight, &s.ScheduledScan, &s.ScheduledHour,
			&s.Realtime, &s.ScanWorkers, &s.FileRatePerSec)
	return s, err
}

// Validate refuses a setting the scanner could not honour, with a stable code.
//
// Every check runs on the WRITE path rather than only where the screen draws
// the field: a value stored here is read by a scheduler and by a detached
// subprocess, neither of which has a form to refuse it in.
//
// It takes the capacity because one of the rules genuinely depends on the
// machine: a memory ceiling is only a ceiling while it is below what the host
// has. Passing the measurement in rather than taking it here also keeps the
// tests independent of whatever machine they run on.
func (s Settings) Validate(c Capacity) error {
	if s.Scope != ScopeHost && s.Scope != ScopeServer {
		return refuse(ReasonScopeInvalid, "scope must be "+ScopeHost+" or "+ScopeServer)
	}
	if s.CriticalThreshold < MinCriticalThreshold {
		return refuse(ReasonThresholdTooLow,
			"critical threshold must be at least "+strconv.Itoa(MinCriticalThreshold)+
				" (a lower one reports every inspected file as malware)")
	}
	if s.IOWeight < 1 || s.IOWeight > MaxCgroupWeight {
		return refuse(ReasonIOWeightRange,
			"io weight must be between 1 and "+strconv.Itoa(MaxCgroupWeight))
	}
	// This is the ONLY place a bad weight is caught. systemd parses
	// CPUWeight=0 as out of range, prints "ignoring", and starts anyway with
	// the kernel default, and `systemd-analyze verify` still exits 0 on that
	// file (both measured on systemd 257), so nothing downstream reports it.
	if s.CPUWeight < 0 || s.CPUWeight > MaxCgroupWeight {
		return refuse(ReasonCPUWeightRange,
			"cpu weight must be between 1 and "+strconv.Itoa(MaxCgroupWeight)+
				" or 0 for automatic")
	}
	if s.CPUPercent < 0 || s.RAMMB < 0 {
		return refuse(ReasonNegativeLimit, "resource limits cannot be negative (0 means automatic)")
	}
	if s.CPUPercent > maxCPUPercent {
		return refuse(ReasonCPUPercentTooBig,
			"cpu percent cannot exceed "+strconv.Itoa(maxCPUPercent))
	}
	if s.RAMMB > 0 && s.RAMMB < minRAMMB {
		return refuse(ReasonRAMTooSmall,
			"memory ceiling must be at least "+strconv.Itoa(minRAMMB)+
				"M or 0 for automatic (a lower one is killed rather than slowed)")
	}
	// The other end of the same rule the CPU quota already carries: the kernel
	// accepts a MemoryMax the machine cannot reach, and such a ceiling can never
	// fire, so the screen would report a limit that constrains nothing. The test
	// is >= rather than >, because a ceiling equal to MemTotal is unreachable
	// too: the kernel and every other process eat from the same memory.
	//
	// An unmeasurable host (TotalRAMMB 0, which is every machine without a
	// readable /proc/meminfo) is skipped rather than refused. There is no honest
	// number to compare against there, and refusing is the opposite of the
	// direction SuggestRAMMB's clamp already takes for the same measurement.
	if c.TotalRAMMB > 0 && s.RAMMB >= c.TotalRAMMB {
		return refuse(ReasonRAMTooLarge,
			"memory ceiling must be below this server's "+strconv.Itoa(c.TotalRAMMB)+
				"M of memory or 0 for automatic (a higher one never takes effect)")
	}
	if s.ScheduledHour < 0 || s.ScheduledHour > 23 {
		return refuse(ReasonHourOutOfRange, "scheduled hour must be between 0 and 23")
	}
	if s.ScanWorkers < 0 || s.ScanWorkers > MaxScanWorkers {
		return refuse(ReasonWorkersRange,
			"scan workers must be between 1 and "+strconv.Itoa(MaxScanWorkers)+
				" or 0 for automatic")
	}
	if s.FileRatePerSec < 0 || s.FileRatePerSec > MaxFileRatePerSec {
		return refuse(ReasonFileRateRange,
			"file rate must be between 1 and "+strconv.Itoa(MaxFileRatePerSec)+
				" files per second or 0 for no ceiling")
	}
	return nil
}

// writeRow stores the settings and nothing else.
//
// It is separate from Write so the column list can be exercised against a real
// server without also reaching systemd. The two lists here and in Read are
// written by hand, and a name that drifts from the schema COMPILES: the failure
// shows up only as a setting that saves and reads back as its zero value.
func writeRow(ctx context.Context, db *sql.DB, s Settings) error {
	_, err := db.ExecContext(ctx, `UPDATE av_settings SET
		rule_engine=?, location_heuristics=?, wp_integrity=?,
		critical_threshold=?, auto_quarantine=?, scope=?, excluded_paths=?,
		cpu_percent=?, ram_mb=?, io_weight=?, cpu_weight=?, scheduled_scan=?, scheduled_hour=?,
		realtime=?, scan_workers=?, file_rate_per_sec=?
		WHERE id=1`,
		s.RuleEngine, s.LocationHeuristics, s.WPIntegrity,
		s.CriticalThreshold, s.AutoQuarantine, s.Scope, s.ExcludedPaths,
		s.CPUPercent, s.RAMMB, s.IOWeight, s.CPUWeight, s.ScheduledScan, s.ScheduledHour,
		s.Realtime, s.ScanWorkers, s.FileRatePerSec)
	return err
}

// Write validates, stores, and then applies the resource limits.
//
// The two are inseparable. Storing the row without rewriting the slice leaves
// the panel reporting a limit the kernel has never heard of, which is the exact
// failure this package exists to prevent.
func Write(ctx context.Context, db *sql.DB, s Settings) error {
	if err := s.Validate(ServerCapacity()); err != nil {
		return err
	}
	if err := writeRow(ctx, db, s); err != nil {
		return err
	}
	if err := ApplyLimits(s); err != nil {
		return err
	}
	// The watcher is applied AFTER the limits, so a watcher that starts here
	// starts into a slice that already carries the values just saved. The other
	// order gives it the previous limits until something else rewrites them.
	if err := ApplyWatcher(s); err != nil {
		return err
	}
	// The sweep timer is last, for the same reason and one more: a sweep the
	// timer starts a second later reads the row that was just written, so the
	// row has to be there first.
	return ApplyScheduleTimer(s)
}
