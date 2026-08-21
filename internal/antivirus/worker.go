package antivirus

// The scan runs in a SUBPROCESS, and that is the only way the resource limit is
// real.
//
// A child process started by a service joins the SERVICE's cgroup, not a slice
// of its own. The scan used to be a goroutine inside servika-server, and
// servika.service carries no resource settings at all, so writing a slice file
// confined nothing whatever it said. The scan therefore has to be LAUNCHED into
// the slice, which is what systemd-run does.
//
// Everything below was measured against systemd 252 on AlmaLinux 9, cgroup v2:
//
//	--wait --collect --quiet places the unit in the slice and PROPAGATES the
//	child's exit code (a child exiting 7 gave systemd-run rc=7).
//	--property=EnvironmentFile=<path> hands the child the panel's configuration,
//	and the LEADING DASH is required: a missing file without it fails the unit
//	(rc=1) instead of starting it with defaults.
//	--property=RuntimeMaxSec=3 killed a 60-second child after 3 seconds.
//	TMPDIR is NOT inherited. systemd-run builds a fresh unit environment, so
//	without --setenv the child and every clamscan it spawns would fall back to
//	/tmp, which on AlmaLinux 10 is a tmpfs and is exactly what pinTempDir exists
//	to keep large temp streams off.
//
// The child NEVER touches the database. It reads its request from a file and
// writes its findings to a file, so internal/antivirus stays the only place
// that knows the av_findings schema, and the panel process stays the only one
// holding a connection.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"servika/internal/avsettings"
	"servika/internal/config"
)

// workerFlag is the argument that turns servika-server into a scan worker.
const workerFlag = "scan-worker"

// resultLimit bounds the JSON the worker writes back. The findings list is
// bounded by the 50000-file walk cap, but a bound that is only implied by
// another bound is not one: a corrupt or truncated file must be refused rather
// than read into memory.
const resultLimit = 64 << 20

// ScanRequest is what the parent hands the worker. It carries no credentials.
//
// The layer switches travel WITH the request rather than being read from the
// database by the worker, which is what keeps the worker free of a connection.
// A zero value scans nothing and reports nothing, so every caller states what
// it wants explicitly instead of inheriting a default from a struct literal.
type ScanRequest struct {
	Roots []string `json:"roots"`
	// RuleEngine opens files and weighs their content.
	RuleEngine bool `json:"rule_engine"`
	// LocationHeuristics judges a file by where it sits, without reading it.
	LocationHeuristics bool `json:"location_heuristics"`
	// CriticalThreshold is the score at which a file is called critical rather
	// than suspicious. Zero means the shipped value.
	CriticalThreshold int `json:"critical_threshold"`
	// Excluded are the paths the walk does not descend into. It is empty for a
	// per-domain scan, whose root is one tenant tree, and carries the operator's
	// list for a server-wide sweep.
	Excluded []string `json:"excluded"`
	// Workers is how many files are inspected at once. Zero or less means one,
	// which is what every scan did before the pool existed.
	Workers int `json:"workers"`
	// FileRatePerSec caps how many files a second are inspected across the
	// whole pool. Zero means no ceiling. The cgroup CPU quota does not cover
	// this: a scan is mostly disk reads, and cgroup v2 io.weight is a relative
	// share rather than an absolute cap.
	FileRatePerSec int `json:"file_rate_per_sec"`
	// AutoQuarantine is read by the PANEL after the worker returns, never by the
	// worker. It travels here only so both scan paths read the settings once,
	// and it is deliberately not serialised: a worker that could act on it would
	// be a worker that moves a customer's files.
	AutoQuarantine bool `json:"-"`
}

// DefaultRequest is the scan every caller wants unless an operator has said
// otherwise: both layers on, the shipped threshold.
func DefaultRequest(roots ...string) ScanRequest {
	return ScanRequest{Roots: roots, RuleEngine: true, LocationHeuristics: true}
}

// ScanResult is what the worker hands back.
type ScanResult struct {
	Scanned int `json:"scanned"`
	// Partial is true when the budget ran out before the walk finished. A
	// partial sweep presented as a clean bill of health is the worst answer this
	// feature can give, so it travels back explicitly rather than being inferred
	// from the parent's own clock.
	Partial bool `json:"partial"`
	// Cgroup is the control group the scan OBSERVED itself running in.
	//
	// "systemd-run was asked to use the slice" and "the scan ran in the slice"
	// are different claims. A --slice that an older systemd ignored, or a unit
	// that landed elsewhere, would leave the panel reporting a resource limit
	// that never applied, which is the one thing av_scans.confined exists to
	// prevent. The parent believes the worker rather than its own request.
	Cgroup string `json:"cgroup"`
	// Nice is the scheduling priority the scan OBSERVED itself running at, for
	// the same reason Cgroup is observed rather than assumed: a --nice an older
	// systemd ignored would otherwise read as a courtesy that was extended.
	Nice     int       `json:"nice"`
	Findings []Finding `json:"findings"`
}

// observedNice reports this process's nice value, or 0 where it cannot be read.
//
// It reads /proc/self/stat rather than calling syscall.Getpriority, because that
// wrapper returns the RAW platform answer and the two platforms disagree about
// what that is. Measured: on Linux a process at nice 0 answers 20 and one at
// nice 10 answers 10, so the value is 20 minus the nice level; on macOS an
// ordinary process answers 0, which is the nice level itself. One conversion
// cannot be right for both, and the field it feeds is a claim about what the
// scheduler actually did.
//
// Field 19 of /proc/self/stat is the nice level, unambiguously. The worker only
// ever runs on Linux, so a missing file is not a case that reaches production.
func observedNice() int {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}
	// The second field is the executable name in parentheses and may itself
	// contain spaces, so the fields are counted from the closing bracket.
	closing := strings.LastIndexByte(string(b), ')')
	if closing < 0 {
		return 0
	}
	fields := strings.Fields(string(b)[closing+1:])
	// After the name, field 3 is the state, so the nice level (field 19) is at
	// index 16 of what is left.
	if len(fields) < 17 {
		return 0
	}
	nice, err := strconv.Atoi(fields[16])
	if err != nil {
		return 0
	}
	return nice
}

// selfCgroup reports this process's cgroup v2 path, or "" where it cannot be
// read. The format is a single "0::<path>" line.
func selfCgroup() string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if after, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok {
			return after
		}
	}
	return ""
}

// RunWorkerIfAsked answers "-scan-worker <request> <result>" and reports whether
// it did.
//
// It runs before config.Load, exactly like the port reporter: a scan needs the
// paths from the environment file, not the JWT secret or a database handle, and
// requiring those would make the worker fail on a panel that cannot start.
func RunWorkerIfAsked() bool {
	if len(os.Args) < 2 || (os.Args[1] != "-"+workerFlag && os.Args[1] != "--"+workerFlag) {
		return false
	}
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "usage: servika-server -%s <request.json> <result.json>\n", workerFlag)
		os.Exit(2)
	}
	if err := runWorker(os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintf(os.Stderr, "scan worker: %v\n", err)
		os.Exit(1)
	}
	return true
}

func runWorker(requestPath, resultPath string) error {
	// #nosec G304 G703 -- a server-internal temp path this process's own parent placed on argv; no tenant string reaches it.
	b, err := os.ReadFile(requestPath)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	var req ScanRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return fmt.Errorf("parse request: %w", err)
	}
	if len(req.Roots) == 0 {
		return errors.New("the request names no root to scan")
	}
	// The signed rule package the panel last verified, if there is one. This
	// process does not fetch: it is confined and its budget is for reading
	// files. A failure here leaves the built-in set running, which is what a
	// worker did before packages existed, so it is reported and not fatal.
	if err := LoadRulesFromDisk(); err != nil && !errors.Is(err, ErrRuleKeyAbsent) && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "scan worker: packaged rules not in use: %v\n", err)
	}
	// The unit's own RuntimeMaxSec is the outer bound; this one exists so the
	// worker writes what it found before being killed, rather than being killed
	// with the result file still empty.
	ctx, cancel := context.WithTimeout(context.Background(), scanBudget)
	defer cancel()

	result := executeScan(ctx, req)
	out, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	// #nosec G306 G703 -- root-owned handoff file, 0600, inside the 0700 temp directory this process's parent created; the path is server-internal.
	if err := os.WriteFile(resultPath, out, 0600); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

// executeScan is the scan itself, with no process boundary in it. Both the
// worker binary and the unconfined fallback call this one function, so the two
// paths cannot drift into scanning different things.
func executeScan(ctx context.Context, req ScanRequest) ScanResult {
	result := ScanResult{Cgroup: selfCgroup(), Nice: observedNice()}
	for _, root := range req.Roots {
		scanned, findings, complete := runScan(ctx, root, req)
		result.Scanned += scanned
		result.Findings = append(result.Findings, findings...)
		if !complete {
			result.Partial = true
		}
		if ctx.Err() != nil {
			break
		}
	}
	return result
}

// systemdRunBin is replaceable in tests.
var systemdRunBin = func() (string, error) { return exec.LookPath("systemd-run") }

// confinable reports whether this host can place the scan in the slice.
//
// systemd-run being installed is not enough: it is present on a machine whose
// init is not systemd, where it cannot talk to a manager at all. /run/systemd/
// system is the documented test for "systemd is running as the init system".
func confinable() (string, bool) {
	bin, err := systemdRunBin()
	if err != nil {
		return "", false
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return "", false
	}
	return bin, true
}

// Scan runs one sweep and reports whether the kernel confined it.
//
// A systemd-run failure is NOT quietly downgraded to an unconfined run. An
// operator who set a limit would otherwise get an unlimited scan across every
// site on the server, reported as a normal one. The unconfined path exists only
// for a host that has no systemd at all, and it is recorded as unconfined so
// nothing later reads it as a limit that was applied.
func Scan(ctx context.Context, req ScanRequest, label string) (ScanResult, bool, error) {
	bin, ok := confinable()
	if !ok {
		return executeScan(ctx, req), false, nil
	}
	result, err := scanViaSystemd(ctx, bin, req, label)
	if err != nil {
		return ScanResult{}, false, err
	}
	// The worker's own observation decides this, not the request that was made,
	// and being IN the slice is not enough: a slice the panel never wrote is
	// created implicitly by systemd with no limit on it at all, so the path
	// alone would report an unlimited scan as a confined one.
	confined := avsettings.Confined(result.Cgroup)
	if !confined {
		// #nosec G706 -- the logged value is this process's child's own /proc/self/cgroup line, supplied by the kernel; no tenant string reaches it.
		log.Printf("antivirus: the scan ran in %q, which is not %s carrying a "+
			"resource limit; the limits did not apply", result.Cgroup, avsettings.SliceName)
	}
	return result, confined, nil
}

func scanViaSystemd(ctx context.Context, bin string, req ScanRequest, label string) (ScanResult, error) {
	self, err := os.Executable()
	if err != nil {
		return ScanResult{}, fmt.Errorf("locate the panel binary: %w", err)
	}
	// MkdirTemp with an empty dir argument honours the pinned TMPDIR, which
	// keeps this off AlmaLinux 10's tmpfs /tmp.
	dir, err := os.MkdirTemp("", "servika-avscan")
	if err != nil {
		return ScanResult{}, fmt.Errorf("create the scan handoff directory: %w", err)
	}
	// MkdirTemp creates the directory 0700, so nothing else on the host can read
	// the request or the findings on their way between the two processes.
	defer func() { _ = os.RemoveAll(dir) }()

	requestPath := filepath.Join(dir, "request.json")
	resultPath := filepath.Join(dir, "result.json")
	body, err := json.Marshal(req)
	if err != nil {
		return ScanResult{}, fmt.Errorf("encode the scan request: %w", err)
	}
	// #nosec G306 G703 -- root-owned handoff file, 0600, inside the 0700 temp
	// directory created just above; the path is server-internal.
	if err := os.WriteFile(requestPath, body, 0o600); err != nil {
		return ScanResult{}, fmt.Errorf("write the scan request: %w", err)
	}

	args := []string{
		"--wait", "--collect", "--quiet",
		"--unit=" + unitName(label),
		"--slice=" + avsettings.SliceName,
		"--property=EnvironmentFile=-" + config.EnvFile(),
		"--property=RuntimeMaxSec=" + strconv.Itoa(int(unitBudget.Seconds())),
		"--setenv=TMPDIR=" + os.TempDir(),
		// The slice's CPUQuota and IOWeight are not the whole story. A quota
		// bounds how much CPU the scan may take but says nothing about how
		// eagerly the kernel schedules it against a site serving a request, and
		// cgroup v2 io.weight is a RELATIVE share rather than an absolute cap.
		// These two hand the kernel's schedulers a separate signal: measured on
		// systemd 252, the child really runs at nice 10 and ionice reports
		// `idle` against `0` and `none: prio 0` without them.
		//
		// They are applied to EVERY scan, not only the scheduled one. A sweep an
		// operator starts by hand reads the same disks, and they usually start
		// it because something is already wrong on that server.
		"--nice=" + strconv.Itoa(scanNice),
		"--property=IOSchedulingClass=idle",
		self, "-" + workerFlag, requestPath, resultPath,
	}
	// #nosec G204 G702 -- fixed binary with separate args (no shell); every value is a
	// panel-controlled path or a sanitised unit label, never tenant input.
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if err != nil {
		return ScanResult{}, fmt.Errorf("run the scan in %s: %s: %w",
			avsettings.SliceName, strings.TrimSpace(string(out)), err)
	}

	return readResult(resultPath)
}

func readResult(path string) (ScanResult, error) {
	f, err := os.Open(path) // #nosec G304 -- path is this process's own temp file.
	if err != nil {
		return ScanResult{}, fmt.Errorf("the scan produced no result file: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return ScanResult{}, fmt.Errorf("stat the scan result: %w", err)
	}
	if info.Size() > resultLimit {
		return ScanResult{}, fmt.Errorf("the scan result is %d bytes, over the %d-byte limit",
			info.Size(), resultLimit)
	}
	var result ScanResult
	if err := json.NewDecoder(f).Decode(&result); err != nil {
		// A result that cannot be read is a FAILED scan, never an empty one.
		// Returning no findings here would report a sweep that never completed
		// as a clean site.
		return ScanResult{}, fmt.Errorf("parse the scan result: %w", err)
	}
	return result, nil
}

// Three deadlines, each outside the one before it, so the innermost is what
// normally fires.
//
//	scanBudget    the worker's own context: it stops walking and WRITES what it
//	              found, marked partial.
//	unitBudget    RuntimeMaxSec: systemd kills a worker that is wedged rather
//	              than merely slow, and the result file is then absent.
//	parentBudget  the panel's context around systemd-run itself.
//
// Ordering them the other way round would make the outer one fire first and
// throw away findings the worker already had.
const (
	unitBudget   = scanBudget + 2*time.Minute
	parentBudget = unitBudget + time.Minute
)

// scanNice is the scheduling priority the scan subprocess runs at.
//
// 10 is the value a nightly maintenance job conventionally takes: enough to
// yield to anything a visitor is waiting on, not so much that the scan never
// finishes inside its budget. It is a hint to the CPU scheduler and is separate
// from the slice's CPUQuota, which is a ceiling rather than a priority.
const scanNice = 10

// unitName builds a transient unit name from a caller-supplied label.
//
// The label reaches a systemd unit name, so only characters systemd accepts in
// one survive. A scan id is all this ever passes, but the sanitiser is here
// rather than at the call site because a unit name is not a place to find out
// later that an assumption was wrong.
func unitName(label string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '-', r == '_':
			return r
		}
		return '-'
	}, label)
	if safe == "" {
		safe = "adhoc"
	}
	if len(safe) > 32 {
		safe = safe[:32]
	}
	return "servika-av-scan-" + safe
}
