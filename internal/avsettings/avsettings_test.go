package avsettings

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sourceOf(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// The suggestion clamps must hold on a machine where the measurement is not
// available at all. Go tests run natively on macOS here, where /proc/meminfo
// does not exist and totalRAMMB returns 0; an assertion on the measured value
// would fail on every development machine, and a suggestion of 0 MB would
// become a memory ceiling of zero that kills the scan instantly.
func TestTheSuggestionsSurviveAnUnmeasurableHost(t *testing.T) {
	c := ServerCapacity()
	t.Logf("measured: %d cores, %d MB RAM", c.CPUCores, c.TotalRAMMB)
	t.Logf("suggests: CPUQuota=%d%% MemoryMax=%dM", c.SuggestCPUPct, c.SuggestRAMMB)

	if c.CPUCores < 1 {
		t.Fatal("core count could not be measured")
	}
	if c.SuggestCPUPct < 50 {
		t.Errorf("cpu suggestion below the half-core floor: %d%%", c.SuggestCPUPct)
	}
	if c.SuggestRAMMB < 256 {
		t.Errorf("ram suggestion below the 256M floor: %dM", c.SuggestRAMMB)
	}
	if c.SuggestRAMMB > 2048 {
		t.Errorf("ram suggestion above the 2048M ceiling: %dM", c.SuggestRAMMB)
	}
	// The suggestion must not consume the server it is protecting.
	if c.SuggestCPUPct > c.CPUCores*100/2 {
		t.Errorf("cpu suggestion takes over half the machine: %d%% of %d%%",
			c.SuggestCPUPct, c.CPUCores*100)
	}
	if runtime.GOOS == "linux" && c.TotalRAMMB < 1 {
		t.Error("/proc/meminfo exists on linux and MemTotal must be readable")
	}
}

func TestAutomaticResolvesAndAManualValueIsKept(t *testing.T) {
	c := ServerCapacity()

	auto := Settings{}.Resolve(c)
	if auto.CPUPercent != c.SuggestCPUPct || auto.RAMMB != c.SuggestRAMMB {
		t.Errorf("zero did not resolve to the suggestion: %d/%d vs %d/%d",
			auto.CPUPercent, auto.RAMMB, c.SuggestCPUPct, c.SuggestRAMMB)
	}
	if auto.IOWeight != 50 {
		t.Errorf("zero io weight did not resolve to 50: %d", auto.IOWeight)
	}

	manual := Settings{CPUPercent: 150, RAMMB: 700, IOWeight: 90}.Resolve(c)
	if manual.CPUPercent != 150 || manual.RAMMB != 700 || manual.IOWeight != 90 {
		t.Errorf("a manual value was overwritten by the suggestion: %d/%d/%d",
			manual.CPUPercent, manual.RAMMB, manual.IOWeight)
	}
}

func TestScopeDecidesTheRoots(t *testing.T) {
	if got := (Settings{Scope: ScopeHost}).ScanRoots(); len(got) != 1 || got[0] != "/home" {
		t.Errorf("host scope must be /home, got %v", got)
	}
	if got := (Settings{Scope: ScopeServer}).ScanRoots(); len(got) != 1 || got[0] != "/" {
		t.Errorf("server scope must be /, got %v", got)
	}
	// An unset scope must not fall through to the whole filesystem.
	if got := (Settings{}).ScanRoots(); len(got) != 1 || got[0] != "/home" {
		t.Errorf("an unset scope must default to /home, got %v", got)
	}
}

func TestExclusionMatchesOnASeparatorAndNotOnAPrefix(t *testing.T) {
	s := Settings{ExcludedPaths: "/var/lib/mysql\n/proc\nnode_modules/\n/wp-content/cache/\n"}
	cases := []struct {
		path string
		want bool
	}{
		{"/var/lib/mysql", true},
		{"/var/lib/mysql/ibdata1", true},
		// The whole point of anchoring on a separator: a different directory
		// that merely starts with the same letters is NOT excluded.
		{"/var/lib/mysqldata/x.php", false},
		{"/proc/1/cmdline", true},
		{"/procedures/x.php", false},
		// A relative entry matches a whole SEGMENT.
		{"/home/c_a/public_html/node_modules/left-pad/index.js", true},
		{"/home/c_a/public_html/my-node_modules/x.php", false},
		{"/home/c_a/public_html/node_modules_old/x.php", false},
		// An entry that starts with "/" is an absolute prefix even when it also
		// ends with one, so it anchors at the root rather than matching a
		// fragment at any depth. This entry is removed from the seeded list by
		// migration 0109 and is kept here only to pin what it means when an
		// operator types one like it.
		{"/wp-content/cache/x.php", true},
		{"/home/c_a/public_html/wp-content/cache/x.php", false},
		{"/home/c_a/public_html/wp-content/uploads/x.php", false},
		{"/home/c_a/public_html/index.php", false},
	}
	for _, c := range cases {
		if got := s.Excluded(c.path); got != c.want {
			t.Errorf("Excluded(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// The escape this matcher was changed for, kept as its own test because it is
// the finding rather than a property of the syntax.
//
// A substring test excluded any path CONTAINING a listed fragment, and the
// panel seeded `node_modules/`. Measured before the fix: a webshell under
// `wp-content/uploads/node_modules/` was excluded from the nightly sweep and
// from the real-time watcher alike, so `mkdir node_modules` hid it completely
// and nothing reported it, because an excluded file is not a file that was
// inspected and cleared.
//
// Segment matching alone does not close this: a real `node_modules` segment is
// still excluded wherever it sits. Migration 0109 removes the seeded entries,
// and this test holds both halves together.
func TestATenantCannotHideAFileByCreatingADirectory(t *testing.T) {
	const planted = "/home/c_a/public_html/wp-content/uploads/node_modules/shell.php"

	// What the panel seeds today, after migration 0109.
	seeded := Settings{ExcludedPaths: "/proc\n/sys\n/dev\n/run\n/var/lib/mysql\n" +
		"/var/lib/containers\n/var/cache\n/var/backups\n" +
		"/var/lib/servika/quarantine\n/opt/servika"}
	if seeded.Excluded(planted) {
		t.Error("a webshell under a directory the tenant created is still excluded from the scan")
	}
	// The system paths the seed exists for still work.
	for _, p := range []string{"/proc/1/cmdline", "/var/lib/mysql/ibdata1", "/opt/servika/bin/x"} {
		if !seeded.Excluded(p) {
			t.Errorf("%s is no longer excluded, so the scan reads it on every pass", p)
		}
	}
	// And an operator who deliberately re-adds the entry gets what they asked
	// for, at any depth. The fix is the seeded default, not a refusal.
	if !(Settings{ExcludedPaths: "node_modules/"}).Excluded(planted) {
		t.Error("an operator's own relative exclusion no longer applies at depth")
	}
}

// The seeded list is the other half, and it is the half segment matching cannot
// close: a real `node_modules` segment stays excluded wherever it sits, so the
// entry itself has to go.
//
// 0106 cannot be edited, because the runner tracks an applied migration by
// checksum and calls log.Fatalf on a mismatch, so 0109 removes them instead.
// This reads both files and holds them together.
func TestEveryRelativeEntryTheSeedAddsIsRemovedAgain(t *testing.T) {
	seed := readMigration(t, "0106_av_settings.sql")
	removal := readMigration(t, "0109_av_exclusions.sql")

	// The seeded literal is one SQL string with escaped newlines in it.
	start := strings.Index(seed, "INSERT INTO av_settings (id, excluded_paths) VALUES (1,")
	if start < 0 {
		t.Fatal("0106 no longer seeds the exclusion list; this test has to follow it")
	}
	open := strings.Index(seed[start:], "'")
	rest := seed[start+open+1:]
	literal := rest[:strings.Index(rest, "'")]

	var relative []string
	for entry := range strings.SplitSeq(literal, `\n`) {
		if entry != "" && !strings.HasPrefix(entry, "/") {
			relative = append(relative, entry)
		}
	}
	if len(relative) == 0 {
		t.Skip("the seed carries no relative entry, so there is nothing to remove")
	}
	for _, entry := range relative {
		if !strings.Contains(removal, `'\n`+entry+`\n'`) {
			t.Errorf("0106 seeds the relative entry %q and 0109 does not remove it, "+
				"so a tenant hides a file by creating a directory of that name", entry)
		}
	}
}

func readMigration(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func TestTheExclusionListIgnoresBlankLines(t *testing.T) {
	s := Settings{ExcludedPaths: "/proc\n\n   \n/sys\n"}
	if got := s.ExcludedList(); len(got) != 2 {
		t.Errorf("blank lines were not dropped: %v", got)
	}
	// A blank entry read as a fragment would match every path on the server and
	// exclude the entire scan.
	if s.Excluded("/home/c_a/public_html/index.php") {
		t.Error("a blank exclusion line excluded an ordinary path")
	}
}

// Every refusal needs a failing path and a passing one, or the check is not
// measuring anything.
func TestValidateRefusesWhatTheScannerCouldNotHonour(t *testing.T) {
	// A fixed capacity rather than the real host's, so the table below says the
	// same thing on a laptop and on a hosting server.
	host := Capacity{CPUCores: 8, TotalRAMMB: 16384}

	ok := Settings{Scope: ScopeHost, CriticalThreshold: 100, IOWeight: 50, ScheduledHour: 4}
	if err := ok.Validate(host); err != nil {
		t.Fatalf("a valid row was refused: %v", err)
	}

	cases := []struct {
		name string
		set  func(*Settings)
		code string
	}{
		{"empty scope", func(s *Settings) { s.Scope = "" }, ReasonScopeInvalid},
		{"unknown scope", func(s *Settings) { s.Scope = "everything" }, ReasonScopeInvalid},
		{"zero threshold", func(s *Settings) { s.CriticalThreshold = 0 }, ReasonThresholdTooLow},
		{"threshold below floor", func(s *Settings) { s.CriticalThreshold = MinCriticalThreshold - 1 }, ReasonThresholdTooLow},
		{"io weight zero", func(s *Settings) { s.IOWeight = 0 }, ReasonIOWeightRange},
		{"io weight too big", func(s *Settings) { s.IOWeight = 10001 }, ReasonIOWeightRange},
		{"negative cpu", func(s *Settings) { s.CPUPercent = -1 }, ReasonNegativeLimit},
		{"negative ram", func(s *Settings) { s.RAMMB = -1 }, ReasonNegativeLimit},
		{"cpu beyond 64 cores", func(s *Settings) { s.CPUPercent = maxCPUPercent + 1 }, ReasonCPUPercentTooBig},
		{"ram below the working set", func(s *Settings) { s.RAMMB = minRAMMB - 1 }, ReasonRAMTooSmall},
		// A ceiling at or above what the machine has can never fire, so it is a
		// number on the screen and nothing in the kernel.
		{"ram at what the machine has", func(s *Settings) { s.RAMMB = 16384 }, ReasonRAMTooLarge},
		{"ram above what the machine has", func(s *Settings) { s.RAMMB = 999999 }, ReasonRAMTooLarge},
		{"hour below range", func(s *Settings) { s.ScheduledHour = -1 }, ReasonHourOutOfRange},
		{"hour above range", func(s *Settings) { s.ScheduledHour = 24 }, ReasonHourOutOfRange},
	}
	for _, c := range cases {
		s := ok
		c.set(&s)
		err := s.Validate(host)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if got := ReasonCode(err); got != c.code {
			t.Errorf("%s: reason %q, want %q", c.name, got, c.code)
		}
	}

	// Zero is automatic, not a refused negative.
	auto := ok
	auto.CPUPercent, auto.RAMMB = 0, 0
	if err := auto.Validate(host); err != nil {
		t.Errorf("automatic limits were refused: %v", err)
	}
	// A hour of 0 is midnight, not an unset value.
	midnight := ok
	midnight.ScheduledHour = 0
	if err := midnight.Validate(host); err != nil {
		t.Errorf("midnight was refused: %v", err)
	}
	// One below what the machine has is a real ceiling and is accepted.
	fits := ok
	fits.RAMMB = 16383
	if err := fits.Validate(host); err != nil {
		t.Errorf("a ceiling below the machine's memory was refused: %v", err)
	}
}

// A host whose memory could not be measured keeps working. There is no honest
// number to compare a ceiling against there, and refusing every ceiling would
// take the setting away on exactly the machines the panel knows least about.
func TestAnUnmeasurableHostDoesNotRefuseEveryCeiling(t *testing.T) {
	blind := Capacity{CPUCores: 8, TotalRAMMB: 0}
	s := Settings{Scope: ScopeHost, CriticalThreshold: 100, IOWeight: 50, ScheduledHour: 4, RAMMB: 999999}
	if err := s.Validate(blind); err != nil {
		t.Errorf("an unmeasurable host refused a ceiling: %v", err)
	}

	// The same value is refused the moment the memory IS measured, so the skip
	// above is the measurement failing rather than the rule being absent.
	seeing := Capacity{CPUCores: 8, TotalRAMMB: 16384}
	err := s.Validate(seeing)
	if got := ReasonCode(err); got != ReasonRAMTooLarge {
		t.Errorf("a measured host answered %q, want %q", got, ReasonRAMTooLarge)
	}
}

func TestReasonCodeIsEmptyForANonRefusal(t *testing.T) {
	if got := ReasonCode(nil); got != "" {
		t.Errorf("nil carried a reason code: %q", got)
	}
	// A database failure is not the operator's input being wrong, and the
	// screen must not word it as a refused field.
	if got := ReasonCode(errString("connection refused")); got != "" {
		t.Errorf("a plain error carried a reason code: %q", got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestTheSliceCarriesTheResolvedValuesAndNotTheStoredZeroes(t *testing.T) {
	c := ServerCapacity()

	// A manual row renders exactly what was asked for.
	body := SliceContent(Settings{CPUPercent: 150, RAMMB: 400, IOWeight: 50})
	for _, want := range []string{"CPUQuota=150%", "MemoryMax=400M", "MemoryHigh=360M", "IOWeight=50"} {
		if !strings.Contains(body, want) {
			t.Errorf("slice is missing %q:\n%s", want, body)
		}
	}
	// --runtime is what keeps a later edit of this file effective; the live
	// update path is asserted separately, but a slice that rendered a zero
	// would make that moot.
	if strings.Contains(body, "CPUQuota=0%") || strings.Contains(body, "MemoryMax=0M") {
		t.Errorf("a stored zero reached the slice instead of the suggestion:\n%s", body)
	}

	// An automatic row renders the suggestion, never 0.
	auto := SliceContent(Settings{})
	if !strings.Contains(auto, "CPUQuota="+strconv.Itoa(c.SuggestCPUPct)+"%") {
		t.Errorf("automatic cpu did not render the suggestion (%d%%):\n%s", c.SuggestCPUPct, auto)
	}
	if !strings.Contains(auto, "MemoryMax="+strconv.Itoa(c.SuggestRAMMB)+"M") {
		t.Errorf("automatic ram did not render the suggestion (%dM):\n%s", c.SuggestRAMMB, auto)
	}
}

// The worker ceiling is set by the slice, not by taste. TasksMax counts every
// thread in the cgroup, so a pool sized at the slice's whole budget leaves no
// room for the Go runtime's own threads or for a clamscan subprocess, and the
// kernel refuses the last workers rather than reporting anything.
func TestTheWorkerCeilingLeavesRoomInsideTheSliceBudget(t *testing.T) {
	if MaxScanWorkers >= sliceTasksMax {
		t.Errorf("a ceiling of %d workers fills the slice's TasksMax of %d",
			MaxScanWorkers, sliceTasksMax)
	}
	if MaxScanWorkers < 2 {
		t.Errorf("a ceiling of %d makes the pool pointless", MaxScanWorkers)
	}
}

// time.NewTicker panics on a non-positive duration, and the rate becomes
// time.Second/rate. The ceiling is what keeps that division above zero.
func TestTheFileRateCeilingCannotProduceAZeroInterval(t *testing.T) {
	if interval := time.Second / time.Duration(MaxFileRatePerSec); interval <= 0 {
		t.Fatalf("a rate of %d gives a ticker interval of %v, which panics",
			MaxFileRatePerSec, interval)
	}
}

// An automatic worker count follows the CPU quota, because a worker beyond the
// quota does not scan a file sooner: it waits in the run queue while holding
// its share of the memory ceiling.
func TestAnAutomaticWorkerCountFollowsTheQuotaAndIsNeverZero(t *testing.T) {
	cases := []struct {
		name   string
		cpuPct int
		want   int
	}{
		{"eight cores, a quarter of them", 200, 2},
		{"one core, half of it", 50, 1},
		{"nothing measured at all", 0, 1},
		{"a quota larger than the slice can run", 100 * (MaxScanWorkers + 5), MaxScanWorkers},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := suggestWorkers(c.cpuPct); got != c.want {
				t.Errorf("suggested %d workers, want %d", got, c.want)
			}
			resolved := (Settings{}).Resolve(Capacity{SuggestWorkers: suggestWorkers(c.cpuPct)}).ScanWorkers
			if resolved != c.want {
				t.Errorf("resolved %d workers, want %d", resolved, c.want)
			}
		})
	}
	// A capacity nothing filled in must not resolve to a pool of zero, which
	// would scan no files at all rather than scanning slowly.
	if got := (Settings{}).Resolve(Capacity{}).ScanWorkers; got != 1 {
		t.Errorf("an unmeasured capacity resolved to %d workers", got)
	}
	// An explicit count wins over the suggestion.
	if got := (Settings{ScanWorkers: 7}).Resolve(Capacity{SuggestWorkers: 2}).ScanWorkers; got != 7 {
		t.Errorf("an explicit worker count resolved to %d", got)
	}
}

// The file rate has NO automatic value. 0 means no ceiling, and resolving it to
// some suggested number would throttle every installation that never asked for
// a limit.
func TestAnUnsetFileRateStaysUnlimited(t *testing.T) {
	if got := (Settings{}).Resolve(ServerCapacity()).FileRatePerSec; got != 0 {
		t.Errorf("an unset file rate resolved to %d instead of no ceiling", got)
	}
}

// Both new fields are refused out of range rather than clamped, because a
// clamped value leaves the screen showing a number the scan is not using.
func TestTheThroughputSettingsAreRefusedOutOfRange(t *testing.T) {
	host := Capacity{CPUCores: 8, TotalRAMMB: 16384}
	base := Settings{Scope: ScopeHost, CriticalThreshold: 100, IOWeight: 50}
	cases := []struct {
		name string
		s    Settings
		code string
	}{
		{"negative workers", func() Settings { s := base; s.ScanWorkers = -1; return s }(), ReasonWorkersRange},
		{"workers past the slice budget", func() Settings { s := base; s.ScanWorkers = MaxScanWorkers + 1; return s }(), ReasonWorkersRange},
		{"negative file rate", func() Settings { s := base; s.FileRatePerSec = -1; return s }(), ReasonFileRateRange},
		{"file rate that zeroes the ticker", func() Settings { s := base; s.FileRatePerSec = MaxFileRatePerSec + 1; return s }(), ReasonFileRateRange},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ReasonCode(c.s.Validate(host)); got != c.code {
				t.Errorf("refused with %q, want %q", got, c.code)
			}
		})
	}
	// And the automatic values are accepted, or turning the feature off would
	// be impossible.
	ok := base
	ok.ScanWorkers, ok.FileRatePerSec = 0, 0
	if err := ok.Validate(host); err != nil {
		t.Errorf("the automatic values were refused: %v", err)
	}
}

// Every column the row carries has to be read back and written, or a setting
// saves and then reads as its zero value on the next request.
func TestTheNewColumnsAreBothReadAndWritten(t *testing.T) {
	source := sourceOf(t, "avsettings.go")
	for _, column := range []string{"realtime", "scan_workers", "file_rate_per_sec", "cpu_weight"} {
		if strings.Count(source, column) < 2 {
			t.Errorf("%s does not appear in both the SELECT and the UPDATE", column)
		}
	}
	for _, field := range []string{"&s.Realtime", "&s.ScanWorkers", "&s.FileRatePerSec", "&s.CPUWeight"} {
		if !strings.Contains(source, field) {
			t.Errorf("the row no longer scans into %s", field)
		}
	}
}

// The CPU weight is refused out of range rather than clamped, and the reason is
// not symmetry with the other fields.
//
// systemd is the layer that would otherwise catch it, and measured on systemd
// 257 it does not: CPUWeight=0 is answered "Failed to parse CPUWeight=0,
// ignoring: Numerical result out of range", the unit starts anyway on the
// kernel default of 100, and `systemd-analyze verify` on that same file still
// exits 0. So a value refused by the kernel leaves no trace anywhere except a
// scan that quietly competes with tenant sites on equal footing.
func TestTheCPUWeightIsRefusedOutOfRange(t *testing.T) {
	host := Capacity{CPUCores: 8, TotalRAMMB: 16384}
	base := Settings{Scope: ScopeHost, CriticalThreshold: 100, IOWeight: 50}
	for _, c := range []struct {
		name   string
		weight int
	}{
		{"negative", -1},
		{"past what systemd accepts", MaxCgroupWeight + 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := base
			s.CPUWeight = c.weight
			if got := ReasonCode(s.Validate(host)); got != ReasonCPUWeightRange {
				t.Errorf("refused with %q, want %q", got, ReasonCPUWeightRange)
			}
		})
	}
	// Both ends of the accepted range, and the automatic value. Without these
	// the test above would pass on a Validate that refused everything.
	for _, weight := range []int{0, 1, MaxCgroupWeight} {
		s := base
		s.CPUWeight = weight
		if err := s.Validate(host); err != nil {
			t.Errorf("a weight of %d was refused: %v", weight, err)
		}
	}
}

// An unset weight resolves to the automatic value, and a set one is passed
// through. The resolved value is what reaches the slice, so a zero surviving
// here is a line systemd ignores.
func TestAnUnsetCPUWeightResolvesToTheAutomaticValue(t *testing.T) {
	if got := (Settings{}).Resolve(ServerCapacity()).CPUWeight; got != defaultCPUWeight {
		t.Errorf("an unset weight resolved to %d, want %d", got, defaultCPUWeight)
	}
	if got := (Settings{CPUWeight: 7}).Resolve(ServerCapacity()).CPUWeight; got != 7 {
		t.Errorf("a weight of 7 resolved to %d", got)
	}
}
