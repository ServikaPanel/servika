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
	ScheduledScan      bool   `json:"scheduled_scan"`
	ScheduledHour      int    `json:"scheduled_hour"`
}

// Capacity is what this server actually has, and what the panel proposes when a
// limit is left on automatic.
//
// The screen shows it so an operator sizing a limit sees "two of eight cores"
// rather than an abstract percentage. Choosing a ceiling without knowing what
// is being capped is not a decision.
type Capacity struct {
	CPUCores      int `json:"cpu_cores"`
	TotalRAMMB    int `json:"total_ram_mb"`
	SuggestCPUPct int `json:"suggest_cpu_percent"`
	SuggestRAMMB  int `json:"suggest_ram_mb"`
}

// Effective is a Settings after every "0 = automatic" has been resolved.
type Effective struct {
	CPUPercent int `json:"cpu_percent"`
	RAMMB      int `json:"ram_mb"`
	IOWeight   int `json:"io_weight"`
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
	return c
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
// An entry starting with "/" is an absolute prefix and matches at a path
// SEPARATOR only, so excluding /var never excludes /variable. Any other entry
// is a fragment matched anywhere in the path, which is what makes "node_modules/"
// and "/wp-content/cache/" work at any depth.
func (s Settings) Excluded(path string) bool { return PathExcluded(s.ExcludedList(), path) }

// PathExcluded is the same test against an explicit list.
//
// The scan runs in a separate process that has no database connection, so it
// receives the list in its request rather than reading the settings row. Both
// sides call this one function, or the screen would describe an exclusion the
// scanner does not apply.
func PathExcluded(list []string, path string) bool {
	for _, e := range list {
		if strings.HasPrefix(e, "/") && !strings.HasSuffix(e, "/") {
			if path == e || strings.HasPrefix(path, e+"/") {
				return true
			}
			continue
		}
		if strings.Contains(path, e) {
			return true
		}
	}
	return false
}

// Read loads the single settings row.
func Read(ctx context.Context, db *sql.DB) (Settings, error) {
	var s Settings
	err := db.QueryRowContext(ctx, `SELECT rule_engine, location_heuristics, wp_integrity,
		critical_threshold, auto_quarantine, scope, excluded_paths,
		cpu_percent, ram_mb, io_weight, scheduled_scan, scheduled_hour
		FROM av_settings WHERE id=1`).
		Scan(&s.RuleEngine, &s.LocationHeuristics, &s.WPIntegrity,
			&s.CriticalThreshold, &s.AutoQuarantine, &s.Scope, &s.ExcludedPaths,
			&s.CPUPercent, &s.RAMMB, &s.IOWeight, &s.ScheduledScan, &s.ScheduledHour)
	return s, err
}

// Validate refuses a setting the scanner could not honour, with a stable code.
//
// Every check runs on the WRITE path rather than only where the screen draws
// the field: a value stored here is read by a scheduler and by a detached
// subprocess, neither of which has a form to refuse it in.
func (s Settings) Validate() error {
	if s.Scope != ScopeHost && s.Scope != ScopeServer {
		return refuse(ReasonScopeInvalid, "scope must be "+ScopeHost+" or "+ScopeServer)
	}
	if s.CriticalThreshold < MinCriticalThreshold {
		return refuse(ReasonThresholdTooLow,
			"critical threshold must be at least "+strconv.Itoa(MinCriticalThreshold)+
				" (a lower one reports every inspected file as malware)")
	}
	if s.IOWeight < 1 || s.IOWeight > 10000 {
		return refuse(ReasonIOWeightRange, "io weight must be between 1 and 10000")
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
	if s.ScheduledHour < 0 || s.ScheduledHour > 23 {
		return refuse(ReasonHourOutOfRange, "scheduled hour must be between 0 and 23")
	}
	return nil
}

// Write validates, stores, and then applies the resource limits.
//
// The two are inseparable. Storing the row without rewriting the slice leaves
// the panel reporting a limit the kernel has never heard of, which is the exact
// failure this package exists to prevent.
func Write(ctx context.Context, db *sql.DB, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `UPDATE av_settings SET
		rule_engine=?, location_heuristics=?, wp_integrity=?,
		critical_threshold=?, auto_quarantine=?, scope=?, excluded_paths=?,
		cpu_percent=?, ram_mb=?, io_weight=?, scheduled_scan=?, scheduled_hour=?
		WHERE id=1`,
		s.RuleEngine, s.LocationHeuristics, s.WPIntegrity,
		s.CriticalThreshold, s.AutoQuarantine, s.Scope, s.ExcludedPaths,
		s.CPUPercent, s.RAMMB, s.IOWeight, s.ScheduledScan, s.ScheduledHour); err != nil {
		return err
	}
	return ApplyLimits(s)
}
