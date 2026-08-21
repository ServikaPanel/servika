package avsettings

import (
	"runtime"
	"strconv"
	"strings"
	"testing"
)

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
		{"/home/c_a/public_html/node_modules/left-pad/index.js", true},
		{"/home/c_a/public_html/wp-content/cache/x.php", true},
		{"/home/c_a/public_html/wp-content/uploads/x.php", false},
		{"/home/c_a/public_html/index.php", false},
	}
	for _, c := range cases {
		if got := s.Excluded(c.path); got != c.want {
			t.Errorf("Excluded(%q) = %v, want %v", c.path, got, c.want)
		}
	}
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
	ok := Settings{Scope: ScopeHost, CriticalThreshold: 100, IOWeight: 50, ScheduledHour: 4}
	if err := ok.Validate(); err != nil {
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
		{"hour below range", func(s *Settings) { s.ScheduledHour = -1 }, ReasonHourOutOfRange},
		{"hour above range", func(s *Settings) { s.ScheduledHour = 24 }, ReasonHourOutOfRange},
	}
	for _, c := range cases {
		s := ok
		c.set(&s)
		err := s.Validate()
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
	if err := auto.Validate(); err != nil {
		t.Errorf("automatic limits were refused: %v", err)
	}
	// A hour of 0 is midnight, not an unset value.
	midnight := ok
	midnight.ScheduledHour = 0
	if err := midnight.Validate(); err != nil {
		t.Errorf("midnight was refused: %v", err)
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
