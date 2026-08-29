// Package phpversion provides dynamic PHP version discovery, installation, and removal.
package phpversion

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"servika/internal/httpx"
)

// SupportedVersions contains PHP versions provided for AlmaLinux 10.
var SupportedVersions = []VersionMetadata{
	{"7.4", "74", "remi"},
	{"8.0", "80", "remi"},
	{"8.1", "81", "remi"},
	{"8.2", "82", "remi"},
	{"8.3", "", "appstream"}, // Native AppStream version.
	{"8.3", "83", "remi"},
	{"8.4", "84", "remi"},
	{"8.5", "85", "remi"},
	{"8.6", "86", "remi"},
}

// VersionMetadata identifies a supported PHP distribution.
type VersionMetadata struct {
	Version  string `json:"version"`
	Code     string `json:"code"`     // Remi package prefix such as "74" or "82".
	Resource string `json:"resource"` // "remi" | "appstream"
}

// Version describes a supported PHP distribution and its runtime state.
type Version struct {
	VersionMetadata
	Loaded      bool   `json:"loaded"`
	Installable bool   `json:"installable"`
	PoolDir     string `json:"pool_dir,omitempty"`
	SockDir     string `json:"sock_dir,omitempty"`
	Service     string `json:"service,omitempty"`
	PHPBin      string `json:"php_bin,omitempty"`
	RealVersion string `json:"real_version,omitempty"` // For example, "8.3.31".
	ModuleCount int    `json:"module_count,omitempty"`
	Description string `json:"description,omitempty"`
}

// ---- Availability cache ----
// PERF: dnf shell-out is expensive (~0.85s per package) and can hang for SECONDS when dnf is
// locked or slow (e.g. panel update running dnf). Previously packageAvailable() ran this on
// the REQUEST PATH (synchronous, 20s timeout) — every caller of AllVersions() (especially
// /php/versions from the Domains page) would stall. Now dnf is ONLY called in the background
// sweeper goroutine; the request path only READS the cache and NEVER blocks.
//
// FALSE-NEGATIVE FIX: the dnf probe is now THREE-STATE (available, checked). "dnf definitely
// said NO" (checked=true, available=false) and "could not ASK dnf" (checked=false: timeout/lock/error)
// are DISTINCT. Previously both collapsed to a single false → a transient dnf lock would turn the
// ENTIRE cache to false, causing a bogus "EOL/unavailable" 409 when the user tried to install
// a version that was actually installable.
var (
	availabilityMu    sync.Mutex
	availabilityCache = map[string]bool{} // pkg -> CONFIRMED installable (only written when checked=true)
	sweeperOnce       sync.Once

	// dnfProbe: background sweep probe (fills display cache). Injectable for tests.
	// Returns (available, checked). checked=false → could not ask dnf, PRESERVE previous value.
	dnfProbe = func(pkg string) (available bool, checked bool) {
		return dnfProbeCore(pkg, dnfTimeout)
	}
	// dnfLiveProbe: install-gate LIVE authoritative probe (long timeout). Injectable for tests.
	dnfLiveProbe = func(pkg string) (available bool, checked bool) {
		return dnfProbeCore(pkg, dnfAuthTimeout)
	}
)

const (
	availabilityTTL = 10 * time.Minute // background sweep period
	dnfTimeout      = 25 * time.Second // sweep per-package upper bound (3s→25s: dnf slow/first metadata load was too short → persistent false-negatives)
	dnfAuthTimeout  = 30 * time.Second // install-gate live authoritative probe upper bound
)

// StartAvailabilitySweeper starts the background dnf sweep loop (once). Called from main at
// server startup; idempotent. Runs the initial sweep and periodic refresh in a goroutine.
// Also starts an async dnf makecache to pre-warm metadata so the first sweep does not
// time out on stale or missing metadata and produce false negatives.
func StartAvailabilitySweeper() {
	sweeperOnce.Do(func() {
		go warmMetadata()
		go sweepLoop()
	})
}

// warmMetadata runs dnf makecache once at startup to pre-warm metadata. Fire-and-forget;
// independent goroutine from the sweep — does not starve it.
func warmMetadata() {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "dnf", "-q", "makecache").Run()
}

// sweepLoop runs an initial sweep at boot and refreshes every availabilityTTL. All Remi
// package availability is probed and the cache updated. Runs independently of the request path.
func sweepLoop() {
	sweepOnce()
	t := time.NewTicker(availabilityTTL)
	defer t.Stop()
	for range t.C {
		sweepOnce()
	}
}

// sweepOnce performs a single dnf scan round.
// NO ATOMIC-WIPE: only packages where dnf gave a DEFINITE answer (checked=true) are updated;
// packages that "could not be asked" (checked=false: timeout/lock) PRESERVE their previous
// cache value. This prevents a single transient failed round from flipping all previous true
// values to false (last-known-good preservation).
func sweepOnce() {
	// Start with a copy of the current cache — entries with checked=false retain their old value.
	availabilityMu.Lock()
	fresh := make(map[string]bool, len(availabilityCache))
	maps.Copy(fresh, availabilityCache)
	availabilityMu.Unlock()

	seen := map[string]bool{}
	for _, m := range SupportedVersions {
		if m.Resource != "remi" {
			continue // appstream is always available; no need to ask dnf
		}
		pkg := "php" + m.Code + "-php-fpm"
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		available, checked := dnfProbe(pkg)
		if checked {
			fresh[pkg] = available // definite answer → write
		}
		// checked=false → fresh[pkg] RETAINS previous value (if any); unknown otherwise.
	}

	// DYNAMIC DISCOVERY: enumerate the phpXX-php-fpm packages Remi actually offers,
	// so a PHP version added upstream (8.7, 9.0) appears in the panel WITHOUT a code
	// change. A repoquery listing IS the availability proof, so each discovered
	// package is marked available here rather than probed a second time. This runs
	// in the background sweep only, never the request path, keeping AllVersions()
	// dnf-free the way the availability cache does. On failure discoverRemiVersions
	// returns nil and the previous discovery is kept (last-known-good).
	if found := discoverRemiVersions(); found != nil {
		for _, m := range found {
			fresh["php"+m.Code+"-php-fpm"] = true
		}
		discoveredMu.Lock()
		discoveredCache = found
		discoveredMu.Unlock()
	}

	availabilityMu.Lock()
	availabilityCache = fresh
	availabilityMu.Unlock()
}

// ---- Dynamic Remi version discovery ----
// SupportedVersions is a fixed list; discovery ADDS to it, so a version that
// appears in Remi later shows up on its own. It never removes a curated entry.

// reRemiFPM matches a Remi fpm package name "php83-php-fpm" and captures the
// two-digit code. Remi uses a single-digit major and minor (php74 … php90).
var reRemiFPM = regexp.MustCompile(`^php([0-9])([0-9])-php-fpm$`)

var (
	discoveredMu    sync.Mutex
	discoveredCache []VersionMetadata
)

// discoverRemiVersions lists the phpXX-php-fpm packages Remi offers. It runs a
// single dnf repoquery, which is expensive and can hang under a dnf lock, so it
// is called ONLY from the background sweep. An error returns nil and the caller
// keeps whatever the last successful discovery found.
func discoverRemiVersions() []VersionMetadata {
	ctx, cancel := context.WithTimeout(context.Background(), dnfTimeout)
	defer cancel()
	out, err := systemCommandContext(ctx, "dnf", "repoquery", "-q", "--qf", "%{name}\n", "php*-php-fpm").Output()
	if err != nil {
		return nil
	}
	return parseRemiFPMVersions(string(out))
}

// parseRemiFPMVersions turns dnf repoquery output into version metadata, deduped
// by code. It is pure so the parse is tested without a real dnf; a line that is
// not a phpXX-php-fpm name (php-fpm, php83-php-cli, blank) is ignored.
func parseRemiFPMVersions(output string) []VersionMetadata {
	seen := map[string]bool{}
	var found []VersionMetadata
	for line := range strings.SplitSeq(output, "\n") {
		m := reRemiFPM.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		code := m[1] + m[2]
		if seen[code] {
			continue
		}
		seen[code] = true
		found = append(found, VersionMetadata{Version: m[1] + "." + m[2], Code: code, Resource: "remi"})
	}
	return found
}

// mergedMetadata returns the fixed SupportedVersions plus every Remi version the
// background sweep discovered that the fixed list does not already name. It reads
// only in-memory state (no dnf), so it is safe on the request path.
func mergedMetadata() []VersionMetadata {
	out := append([]VersionMetadata(nil), SupportedVersions...)
	discoveredMu.Lock()
	found := discoveredCache
	discoveredMu.Unlock()
	for _, m := range found {
		exists := false
		for _, d := range out {
			if d.Code == m.Code && d.Resource == m.Resource {
				exists = true
				break
			}
		}
		if !exists {
			out = append(out, m)
		}
	}
	return out
}

// dnfProbeCore performs a THREE-STATE dnf probe for a single package. Returns (available, checked):
//   - (true,  true)  → dnf ran and listed the package (installed OR in repository) = DEFINITELY available.
//   - (false, true)  → dnf ran and returned "No match" = DEFINITELY absent (EOL/removed).
//   - (false, false) → COULD NOT ASK dnf (timeout/lock/metadata error) = UNKNOWN.
//
// Distinguishing "definitely absent" from "could not ask" is the CORE of this package:
// timeout ≠ unavailable.
func dnfProbeCore(pkg string, timeout time.Duration) (available bool, checked bool) {
	// 1) Installed? (fast path) — success means definitely available.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if systemCommandContext(ctx, "dnf", "-q", "list", "--installed", pkg).Run() == nil {
		return true, true
	}

	// 2) Available in repository? Use output + ctx to distinguish "definitely absent" from "could not ask".
	ctx2, cancel2 := context.WithTimeout(context.Background(), timeout)
	defer cancel2()
	out, err := systemCommandContext(ctx2, "dnf", "-q", "list", "--available", pkg).CombinedOutput()
	if err == nil {
		return true, true // dnf ran and listed the package → definitely available
	}
	// dnf returned non-zero / error. Was it timeout/lock or genuine "No match"?
	if ctx2.Err() == context.DeadlineExceeded {
		return false, false // timed out → could not ask
	}
	low := strings.ToLower(string(out))
	if strings.Contains(low, "no match") || strings.Contains(low, "no matching") {
		return false, true // dnf spoke clearly: package absent (EOL/removed)
	}
	// Lock ("waiting for process", "another app is currently holding"), metadata/network error, etc.
	// → not confident. Treat as "could not ask" to avoid false negatives.
	return false, false
}

// systemCommandContext creates a privileged command without inheriting panel secrets.
func systemCommandContext(ctx context.Context, name string, arguments ...string) *exec.Cmd {
	// #nosec G204 G702 -- fixed binary with separate args (no shell); tenant input is validated before exec.
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
	}
	return command
}

// packageAvailable reports whether a PHP package is installable on this OS — DISPLAY hint.
// REQUEST PATH — NEVER calls dnf, only reads the cache. AppStream is always available.
// When the cache is empty (first boot, sweep not yet completed) returns a safe default
// (false = "not yet known") and guarantees the sweeper has started; the request NEVER
// blocks for seconds. Once the sweep finishes the real values land in the cache and
// subsequent requests get correct results instantly.
// WARNING: this is for DISPLAY only; the INSTALL gate does NOT trust this — it asks live dnf.
func packageAvailable(m VersionMetadata) bool {
	if m.Resource == "appstream" {
		return true // system default is always present
	}
	StartAvailabilitySweeper() // idempotent; main already starts it at boot, this is a safety net
	pkg := "php" + m.Code + "-php-fpm"
	availabilityMu.Lock()
	v, ok := availabilityCache[pkg]
	availabilityMu.Unlock()
	if ok {
		return v
	}
	// Cache not yet populated → don't block the request; default to false. Once the sweep
	// completes the correct value lands in the cache.
	return false
}

// availabilityVerify performs a LIVE authoritative installability check for the INSTALL gate.
// DOES NOT use the cache — asks dnf directly (long timeout). Returns (available, checked):
//   - checked=true,  available=false → dnf DEFINITELY returned "No match" → safe to emit "EOL/unavailable".
//   - checked=false                  → could not ask dnf (lock/busy) → NEVER say "EOL/unavailable" (false negative!).
//
// AppStream is always available.
func availabilityVerify(m VersionMetadata) (available bool, checked bool) {
	if m.Resource == "appstream" {
		return true, true
	}
	pkg := "php" + m.Code + "-php-fpm"
	return dnfLiveProbe(pkg)
}

// paths returns installation paths for version metadata.
func paths(m VersionMetadata) (poolDir, sockDir, service, phpBin string) {
	if m.Resource == "appstream" {
		return "/etc/php-fpm.d", "/run/php-fpm", "php-fpm", "/usr/bin/php"
	}
	pre := "/opt/remi/php" + m.Code + "/root"
	return "/etc/opt/remi/php" + m.Code + "/php-fpm.d",
		"/var/opt/remi/php" + m.Code + "/run/php-fpm",
		"php" + m.Code + "-php-fpm",
		pre + "/usr/bin/php"
}

// Discover fills runtime metadata for one version.
func Discover(m VersionMetadata) Version {
	s := Version{VersionMetadata: m}
	s.PoolDir, s.SockDir, s.Service, s.PHPBin = paths(m)
	// Consider the version installed when its PHP binary exists.
	if _, err := os.Stat(s.PHPBin); err == nil {
		s.Loaded = true
		s.Installable = true
		// Read module count and the actual version.
		if out, err := systemCommandContext(context.Background(), s.PHPBin, "-v").Output(); err == nil {
			line, _, _ := strings.Cut(string(out), "\n")
			// "PHP 8.3.31 (cli) ..."
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				s.RealVersion = parts[1]
			}
		}
		if out, err := systemCommandContext(context.Background(), s.PHPBin, "-m").Output(); err == nil {
			lines := strings.Split(string(out), "\n")
			n := 0
			for _, ln := range lines {
				ln = strings.TrimSpace(ln)
				if ln != "" && !strings.HasPrefix(ln, "[") {
					n++
				}
			}
			s.ModuleCount = n
		}
	} else {
		// Installability (DISPLAY): when not installed check cache (non-blocking).
		// Even when cache returns "false" the INSTALL gate re-verifies via live dnf.
		s.Installable = packageAvailable(m)
	}
	if m.Resource == "appstream" {
		s.Description = "System default (AlmaLinux AppStream)"
	} else {
		s.Description = "Remi modular, development/test/legacy"
	}
	return s
}

// ---- Version scan cache ----
//
// PERF: Discover execs `php -v` AND `php -m` for every INSTALLED version, so one
// AllVersions() call costs two execs per installed version. Measured with a
// counter against the real call chain, GET /php-settings runs AllVersions()
// TWICE (versionInfo resolves the domain's version, then runtimeChoicesWithSource
// lists them all), which on a host carrying six versions is 24 execs on the
// request path. The dnf half of Discover was already off the request path
// through availabilityCache above; these execs were not.
//
// The set of installed versions only changes when somebody installs or removes
// one, so it is cached. The TTL is a backstop for a change made OUTSIDE the
// panel, such as an operator running dnf by hand; changes the panel itself makes
// are invalidated explicitly at the two points that make them (see job.go).
const allVersionsTTL = 60 * time.Second

var (
	allVersionsMu    sync.Mutex
	allVersionsCache []Version
	allVersionsAt    time.Time

	// discoverAll is the uncached scan. It is a variable so a test can count how
	// often the cache actually recomputes, which is the same shape dnfProbe,
	// phpOpState and launchPHPOp already use in this package.
	discoverAll = func() []Version {
		metas := mergedMetadata()
		out := make([]Version, 0, len(metas))
		for _, m := range metas {
			out = append(out, Discover(m))
		}
		// Sort installed versions first, then by version descending.
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].Loaded != out[j].Loaded {
				return out[i].Loaded
			}
			return compareVersions(out[i].Version, out[j].Version) > 0
		})
		return out
	}
)

// InvalidateAllVersions drops the scan cache.
//
// It is called from the points that CHANGE the answer rather than left to the
// TTL, because a version install or removal is exactly the moment an operator is
// watching the list and a minute of stale data reads as the operation having
// done nothing.
func InvalidateAllVersions() {
	allVersionsMu.Lock()
	allVersionsCache = nil
	allVersionsMu.Unlock()
}

// AllVersions discovers all supported versions.
//
// The returned slice is a COPY. Handing out the cached slice would give every
// caller one backing array, so a caller that sorted or appended to its result
// would silently rewrite what the next one reads. Nine elements cost nothing and
// the whole class of defect goes with them.
func AllVersions() []Version {
	allVersionsMu.Lock()
	if allVersionsCache != nil && time.Since(allVersionsAt) < allVersionsTTL {
		cached := append([]Version(nil), allVersionsCache...)
		allVersionsMu.Unlock()
		return cached
	}
	allVersionsMu.Unlock()

	// Deliberately computed OUTSIDE the lock: Discover execs, and holding the
	// mutex across it would serialise every concurrent reader behind one scan.
	// Two racing scans both write and the last wins, which is harmless because
	// the answer does not depend on who computed it.
	out := discoverAll()

	allVersionsMu.Lock()
	allVersionsCache = out
	allVersionsAt = time.Now()
	allVersionsMu.Unlock()
	return append([]Version(nil), out...)
}

func compareVersions(a, b string) int {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		ia, ib := 0, 0
		_, _ = fmt.Sscanf(pa[i], "%d", &ia)
		_, _ = fmt.Sscanf(pb[i], "%d", &ib)
		if ia != ib {
			return ia - ib
		}
	}
	return 0
}

// DefaultBundle contains extensions for modern PHP versions.
var DefaultBundle = []string{
	"php-fpm",
	"php-cli",
	"php-mysqlnd",
	"php-mbstring",
	"php-bcmath",
	"php-intl",
	"php-gd",
	"php-soap",
	"php-opcache",
	"php-pdo",
	"php-xml",
	"php-zip",
	"php-pgsql",
	"php-ldap",
}

// PackageNames builds package names for a version.
func PackageNames(m VersionMetadata) []string {
	pre := "php"
	if m.Resource == "remi" {
		pre = "php" + m.Code + "-php"
	}
	out := make([]string, 0, len(DefaultBundle))
	for _, p := range DefaultBundle {
		out = append(out, strings.Replace(p, "php", pre, 1))
	}
	return out
}

// ----- HTTP -----

// Handlers provides HTTP handlers for PHP version management.
type Handlers struct {
	DB *sql.DB
}

func (h *Handlers) List(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"versions": AllVersions(),
	})
}

type opReq struct {
	Version  string `json:"version"`
	Resource string `json:"resource"`
}

func (h *Handlers) Install(w http.ResponseWriter, r *http.Request) {
	var req opReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var m VersionMetadata
	for _, d := range SupportedVersions {
		if d.Version == req.Version && d.Resource == req.Resource {
			m = d
			break
		}
	}
	if m.Version == "" {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported version")
		return
	}

	// Graceful pre-check — LIVE AUTHORITATIVE dnf (NOT cache). Goal: PREVENT false negatives.
	// Only emit "EOL/unavailable" when dnf DEFINITELY returned "No match" (checked && !available).
	// If dnf could not be asked (lock/busy) NEVER say "unavailable" — return a distinct "could not
	// verify" message instead, so the user is not misled. A transient dnf lock no longer produces
	// a bogus 409.
	available, checked := availabilityVerify(m)
	if checked && !available {
		httpx.WriteError(w, http.StatusConflict,
			fmt.Sprintf("PHP %s is unavailable from the configured repositories (likely EOL). Select an installable version.", req.Version))
		return
	}
	if !checked {
		httpx.WriteError(w, http.StatusConflict,
			fmt.Sprintf("could not verify PHP %s availability right now (dnf may be busy or locked — another install may be in progress). Please try again in a few minutes.", req.Version))
		return
	}

	// dnf holds the rpm lock for the whole transaction, so a second operation
	// started now would wait on it and its output would interleave in one log.
	if phpOpRunning() {
		httpx.WriteError(w, http.StatusConflict,
			"a PHP version operation is already running — try again when it finishes")
		return
	}

	// From here the work is detached: pulling a PHP stack from a slow mirror
	// outlasts the router's own ceiling, and an operator who starts an install
	// and closes the tab must still get the install.
	descriptor := opDescriptor{Version: m.Version, Resource: m.Resource, Action: "install"}
	if err := startPHPOp(descriptor, installScript(m)); err != nil {
		log.Printf("php install %s (%s): %v", m.Version, m.Resource, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not start the installation")
		return
	}

	// 202: the installation has STARTED. Its outcome belongs to the status and
	// log endpoints the screen polls.
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"started": true,
		"version": m.Version,
		"source":  m.Resource,
	})
}

func (h *Handlers) Remove(w http.ResponseWriter, r *http.Request) {
	var req opReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Resource == "appstream" {
		httpx.WriteError(w, http.StatusForbidden,
			"AppStream PHP is the system default and cannot be removed")
		return
	}
	var m VersionMetadata
	for _, d := range SupportedVersions {
		if d.Version == req.Version && d.Resource == req.Resource {
			m = d
			break
		}
	}
	if m.Version == "" || m.Resource != "remi" {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported version")
		return
	}

	// Check whether any domain uses this version. FAIL-CLOSED: a count error must
	// not bypass this guard and let dnf remove a PHP still serving live tenants.
	var count int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM domains WHERE php_version=?`, req.Version).Scan(&count); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not verify version usage")
		return
	}
	if count > 0 {
		httpx.WriteError(w, http.StatusConflict,
			fmt.Sprintf("%d domains use this version; migrate them to another version first", count))
		return
	}

	// Stop PHP-FPM.
	if phpOpRunning() {
		httpx.WriteError(w, http.StatusConflict,
			"a PHP version operation is already running — try again when it finishes")
		return
	}

	// Detached for the same reason an install is, and the wrapper stops the
	// service before dnf so packages are not pulled from under a running pool.
	descriptor := opDescriptor{Version: m.Version, Resource: m.Resource, Action: "remove"}
	if err := startPHPOp(descriptor, removeScript(m)); err != nil {
		log.Printf("php remove %s (%s): %v", m.Version, m.Resource, err)
		httpx.WriteError(w, http.StatusInternalServerError, "could not start the removal")
		return
	}

	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"started": true,
		"version": m.Version,
	})
}
