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
type ScanRequest struct {
	Roots []string `json:"roots"`
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
	Cgroup   string    `json:"cgroup"`
	Findings []Finding `json:"findings"`
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
	result := ScanResult{Cgroup: selfCgroup()}
	for _, root := range req.Roots {
		scanned, findings := runScan(ctx, root)
		result.Scanned += scanned
		result.Findings = append(result.Findings, findings...)
		if ctx.Err() != nil {
			result.Partial = true
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
	// The worker's own observation decides this, not the request that was made.
	confined := strings.Contains(result.Cgroup, "/"+avsettings.SliceName+"/")
	if !confined {
		// #nosec G706 -- the logged value is this process's child's own /proc/self/cgroup line, supplied by the kernel; no tenant string reaches it.
		log.Printf("antivirus: the scan was launched into %s but ran in %q; "+
			"the resource limits did not apply", avsettings.SliceName, result.Cgroup)
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
