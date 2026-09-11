package antivirus

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"servika/internal/avsettings"
)

const (
	domainUserQuery  = "SELECT system_user FROM domains WHERE id=?"
	avSettingsQuery  = "FROM av_settings WHERE id=1"
	getLockQuery     = "SELECT GET_LOCK(?, 0)"
	autoFindingQuery = "FROM av_findings f JOIN domains d ON d.id = f.domain_id"
	lastSweepQuery   = "SELECT UNIX_TIMESTAMP(started_at) FROM av_scans"
)

// avSettingsRow is the av_settings row avsettings.Read scans, in its column order.
func avSettingsRow(s avsettings.Settings) [][]driver.Value {
	return [][]driver.Value{{
		s.RuleEngine, s.LocationHeuristics, int64(s.CriticalThreshold), s.AutoQuarantine, s.Scope, s.ExcludedPaths,
		int64(s.CPUPercent), int64(s.RAMMB), int64(s.IOWeight), int64(s.CPUWeight), s.ScheduledScan, int64(s.ScheduledHour),
		s.Realtime, int64(s.ScanWorkers), int64(s.FileRatePerSec), s.ProcessMonitor,
	}}
}

// fakeScans stands in for the scan a handler or a sweep starts.
type fakeScans struct {
	mu       sync.Mutex
	reqs     []ScanRequest
	labels   []string
	result   ScanResult
	confined bool
	err      error
}

func withFakeScans(t *testing.T) *fakeScans {
	t.Helper()
	f := &fakeScans{}
	setForTest(t, &scanTree, f.scan)
	return f
}

func (f *fakeScans) scan(_ context.Context, req ScanRequest, label string) (ScanResult, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	f.labels = append(f.labels, label)
	return f.result, f.confined, f.err
}

func (f *fakeScans) calls() ([]ScanRequest, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ScanRequest(nil), f.reqs...), append([]string(nil), f.labels...)
}

// freeScanSlot empties the in-process scan slot for one test and after it.
func freeScanSlot(t *testing.T) {
	t.Helper()
	scanning.Store(0)
	t.Cleanup(func() { scanning.Store(0) })
}

// waitSlotFree waits for a background scan to give the slot back.
func waitSlotFree(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for scanning.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the scan slot was never given back")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func domainScanRequest(id string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/domains/"+id+"/antivirus/scan", nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

var scanSettings = avsettings.Settings{RuleEngine: true, LocationHeuristics: true, CriticalThreshold: 90, Scope: avsettings.ScopeHost}

// scanHandler is a domain scan handler over a tenant home under a temporary
// directory, a scripted database and a fake scan.
type scanHandler struct {
	script   *sqlScript
	h        *Handlers
	home     string
	scans    *fakeScans
	finished chan struct{}
}

func newScanHandler(t *testing.T, settings avsettings.Settings) *scanHandler {
	t.Helper()
	t.Setenv("SERVIKA_CLAMSCAN_BIN", filepath.Join(t.TempDir(), "absent"))
	freeScanSlot(t)
	sh := &scanHandler{script: newScript(), home: t.TempDir(), finished: make(chan struct{})}
	setForTest(t, &tenantHomeBase, sh.home+"/")
	if err := os.MkdirAll(filepath.Join(sh.home, "c_site", "public_html"), 0o700); err != nil {
		t.Fatal(err)
	}
	sh.script.rows[domainUserQuery] = [][]driver.Value{{"c_site"}}
	sh.script.rows[avSettingsQuery] = avSettingsRow(settings)
	sh.script.rows[getLockQuery] = [][]driver.Value{{int64(1)}}
	sh.script.rows[autoFindingQuery] = [][]driver.Value{}
	sh.script.insertID = 9
	var once sync.Once
	sh.script.onExec = func(query string) {
		if strings.Contains(query, "UPDATE av_scans SET status") {
			once.Do(func() { close(sh.finished) })
		}
	}
	sh.h = &Handlers{DB: scriptDB(t, sh.script)}
	sh.scans = withFakeScans(t)
	return sh
}

// run starts a scan of domain 3 and waits for the background scan to close its row.
func (sh *scanHandler) run(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	sh.h.Scan(w, domainScanRequest("3"))
	select {
	case <-sh.finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the background scan never closed its row")
	}
	waitSlotFree(t)
	return w
}

// Every refusal before the scan starts answers its reason, starts nothing and
// leaves the slot free.
func TestScanHandlerRefusals(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(s *sqlScript)
		status  int
		message string
	}{
		{"an unknown domain", func(s *sqlScript) { s.rows[domainUserQuery] = [][]driver.Value{} }, http.StatusNotFound, "domain not found"},
		{"a user outside the tenant prefix", func(s *sqlScript) { s.rows[domainUserQuery] = [][]driver.Value{{"web1"}} }, http.StatusBadRequest, "invalid user"},
		{"no public_html", func(s *sqlScript) { s.rows[domainUserQuery] = [][]driver.Value{{"c_other"}} }, http.StatusBadRequest, "public_html not found"},
		{"settings that cannot be read", func(s *sqlScript) { s.fail[avSettingsQuery] = errScripted }, http.StatusInternalServerError, "the antivirus settings could not be read"},
		{"a slot held elsewhere", func(s *sqlScript) { s.rows[getLockQuery] = [][]driver.Value{{int64(0)}} }, http.StatusConflict, "another server scan is in progress; please wait"},
		{"a scan record that cannot be written", func(s *sqlScript) { s.fail["INSERT INTO av_scans"] = errScripted }, http.StatusInternalServerError, "could not create scan record"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sh := newScanHandler(t, scanSettings)
			c.prepare(sh.script)
			w := httptest.NewRecorder()
			sh.h.Scan(w, domainScanRequest("3"))
			reqs, _ := sh.scans.calls()
			if w.Code != c.status || !strings.Contains(w.Body.String(), c.message) || len(reqs) != 0 || scanning.Load() != 0 {
				t.Fatalf("response %d %s, scans %d, slot %d", w.Code, w.Body.String(), len(reqs), scanning.Load())
			}
		})
	}
}

// A scan that ran records every finding, with the critical default for a
// detector that set no level, and closes its row as finished.
func TestScanHandlerRecordsAFinishedScan(t *testing.T) {
	sh := newScanHandler(t, scanSettings)
	fileA := filepath.Join(sh.home, "c_site", "public_html", "a.php")
	fileB := filepath.Join(sh.home, "c_site", "public_html", "b.php")
	sh.scans.result = ScanResult{Scanned: 5, Findings: []Finding{
		{File: fileA, Signature: "PHP.X", Engine: "heuristic", Score: 100, Level: LevelCritical, Rules: "PHP.X"},
		{File: fileB, Signature: "Y", Engine: "clamav"},
	}}
	sh.scans.confined = true

	w := sh.run(t)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"scan_id":9`) {
		t.Fatalf("response = %d %s", w.Code, w.Body.String())
	}
	reqs, labels := sh.scans.calls()
	root := filepath.Join(sh.home, "c_site", "public_html")
	got := ScanRequest{Roots: reqs[0].Roots, RuleEngine: reqs[0].RuleEngine, LocationHeuristics: reqs[0].LocationHeuristics,
		CriticalThreshold: reqs[0].CriticalThreshold, AutoQuarantine: reqs[0].AutoQuarantine}
	want := ScanRequest{Roots: []string{root}, RuleEngine: true, LocationHeuristics: true, CriticalThreshold: 90}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(labels, []string{"9"}) {
		t.Fatalf("scan request %+v, labels %q", reqs[0], labels)
	}
	assertExecArgs(t, sh.script, "INSERT INTO av_scans", []driver.Value{int64(3), "running", "heuristic", SourceManual})
	assertExecArgs(t, sh.script, "INSERT INTO av_findings",
		[]driver.Value{int64(9), int64(3), fileA, "PHP.X", "heuristic", int64(100), LevelCritical, "PHP.X"},
		[]driver.Value{int64(9), int64(3), fileB, "Y", "clamav", int64(scoreCritical), LevelCritical, ""})
	assertExecArgs(t, sh.script, "UPDATE av_scans SET status=?", []driver.Value{"finished", int64(5), int64(2), true, int64(9)})
	assertExecArgs(t, sh.script, "UPDATE av_scans SET auto_quarantined=?")
}

// A scan that could not run is failed, and automatic containment still runs
// before the status when the switch is on.
func TestScanHandlerFailsAScanThatCouldNotRun(t *testing.T) {
	settings := scanSettings
	settings.AutoQuarantine = true
	sh := newScanHandler(t, settings)
	sh.scans.result = ScanResult{Partial: true}
	sh.scans.err = errScripted

	if w := sh.run(t); w.Code != http.StatusOK {
		t.Fatalf("response = %d %s", w.Code, w.Body.String())
	}
	assertExecArgs(t, sh.script, "UPDATE av_scans SET auto_quarantined=?", []driver.Value{int64(0), int64(0), int64(0), int64(9)})
	assertExecArgs(t, sh.script, "UPDATE av_scans SET status=?", []driver.Value{"failed", int64(0), int64(0), false, int64(9)})
}

// A scan that panics is closed as failed by the job's panic handler, and the
// slot is still given back.
func TestScanHandlerFailsAScanThatPanics(t *testing.T) {
	sh := newScanHandler(t, scanSettings)
	setForTest(t, &scanTree, func(context.Context, ScanRequest, string) (ScanResult, bool, error) { panic("the scan exploded") })

	if w := sh.run(t); w.Code != http.StatusOK {
		t.Fatalf("response = %d %s", w.Code, w.Body.String())
	}
	assertExecArgs(t, sh.script, "UPDATE av_scans SET status='failed'", []driver.Value{int64(9)})
	assertExecArgs(t, sh.script, "UPDATE av_scans SET status=?")
}

const findingQuery = "SELECT file, signature, engine, quarantined FROM av_findings WHERE id=? AND domain_id=?"

// fakeContain stands in for the copy out of the tenant home.
type fakeContain struct {
	calls []string
	size  int64
	err   error
}

func (f *fakeContain) contain(home, rel, systemUser string, rowID int64) (int64, error) {
	f.calls = append(f.calls, fmt.Sprintf("%s %s %s %d", home, rel, systemUser, rowID))
	return f.size, f.err
}

// quarantineScript answers the finding lookup with row and fails the statement
// holding fail, when fail is set.
func quarantineScript(row [][]driver.Value, fail string) *sqlScript {
	s := newScript()
	s.rows[findingQuery] = row
	s.insertID = 55
	if fail != "" {
		s.fail[fail] = errScripted
	}
	return s
}

func findingRow(file, engine string, quarantined int64) [][]driver.Value {
	return [][]driver.Value{{file, "PHP.X", engine, quarantined}}
}

func assertContainment(t *testing.T, s *sqlScript, contain *fakeContain, contained, deleted bool) {
	t.Helper()
	var calls []string
	if contained {
		calls = []string{"/home/c_site public_html/x.php c_site 55"}
	}
	if !reflect.DeepEqual(contain.calls, calls) {
		t.Fatalf("contain calls = %q, want %q", contain.calls, calls)
	}
	var removed [][]driver.Value
	if deleted {
		removed = [][]driver.Value{{int64(55)}}
	}
	assertExecArgs(t, s, "DELETE FROM av_quarantine", removed...)
}

// Every answer quarantineFinding gives, and whether it tried the copy and took
// the record back.
func TestQuarantineFindingReasons(t *testing.T) {
	const file = "/home/c_site/public_html/x.php"
	good := findingRow(file, "heuristic", 0)
	cases := []struct {
		name       string
		row        [][]driver.Value
		fail       string
		containErr error
		want       string
		contained  bool
		deleted    bool
	}{
		{"an unknown finding", [][]driver.Value{}, "", nil, reasonFindingUnknown, false, false},
		{"a finding already contained", findingRow(file, "heuristic", 1), "", nil, "", false, false},
		{"a finding that is not a file", findingRow("wp_options#1", EngineDatabase, 0), "", nil, reasonNotAFile, false, false},
		{"a WordPress core file", findingRow("/home/c_site/public_html/wp-admin/x.php", "heuristic", 0), "", nil, reasonCoreFile, false, false},
		{"a path outside the home", findingRow("/tmp/x.php", "heuristic", 0), "", nil, reasonPathOutsideHome, false, false},
		{"a record that cannot be written", good, "INSERT INTO av_quarantine", nil, reasonQuarantineFail, false, false},
		{"a file too large", good, "", errTooLarge, reasonTooLarge, true, true},
		{"a file already gone", good, "", fmt.Errorf("open: %w", os.ErrNotExist), reasonFileMissing, true, true},
		{"a copy that fails", good, "", errScripted, reasonQuarantineFail, true, true},
		{"a stored name that cannot be recorded", good, "UPDATE av_quarantine SET stored_name", nil, reasonQuarantineFail, true, false},
		{"a contained file", good, "", nil, "", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := quarantineScript(c.row, c.fail)
			contain := &fakeContain{size: 123, err: c.containErr}
			setForTest(t, &containInHome, contain.contain)
			if got := (&Handlers{DB: scriptDB(t, s)}).quarantineFinding(3, "c_site", 7); got != c.want {
				t.Fatalf("quarantineFinding = %q, want %q", got, c.want)
			}
			assertContainment(t, s, contain, c.contained, c.deleted)
		})
	}
}

// A contained file records its stored name and size, then marks the finding.
func TestQuarantineFindingRecordsTheContainment(t *testing.T) {
	s := quarantineScript(findingRow("/home/c_site/public_html/x.php", "heuristic", 0), "")
	contain := &fakeContain{size: 123}
	setForTest(t, &containInHome, contain.contain)
	if got := (&Handlers{DB: scriptDB(t, s)}).quarantineFinding(3, "c_site", 7); got != "" {
		t.Fatalf("quarantineFinding = %q", got)
	}
	assertExecArgs(t, s, "INSERT INTO av_quarantine", []driver.Value{int64(3), int64(7), "c_site", "public_html/x.php", "PHP.X", "heuristic"})
	assertExecArgs(t, s, "UPDATE av_quarantine SET stored_name=?", []driver.Value{storedName(55, "public_html/x.php"), int64(123), int64(55)})
	assertExecArgs(t, s, "UPDATE av_findings SET quarantined=1", []driver.Value{int64(7), int64(3)})
}

var sweepSettings = avsettings.Settings{ScheduledScan: true, ScheduledHour: 3, RuleEngine: true, LocationHeuristics: true, Scope: avsettings.ScopeHost}

func atHour(hour int) func() time.Time {
	return func() time.Time { return time.Date(2026, 9, 11, hour, 30, 0, 0, time.Local) }
}

// sweepScript answers a tick that is due: the settings, no earlier sweep and a
// free slot.
func sweepScript(settings avsettings.Settings) *sqlScript {
	s := newScript()
	s.rows[avSettingsQuery] = avSettingsRow(settings)
	s.rows[lastSweepQuery] = [][]driver.Value{}
	s.rows[getLockQuery] = [][]driver.Value{{int64(1)}}
	s.insertID = 21
	return s
}

// A due tick records a scheduled sweep of the configured roots, runs it and
// closes its row, then gives the slot back.
func TestTickOnceStartsADueSweep(t *testing.T) {
	t.Setenv("SERVIKA_CLAMSCAN_BIN", filepath.Join(t.TempDir(), "absent"))
	freeScanSlot(t)
	scans := withFakeScans(t)
	s := sweepScript(sweepSettings)

	tickOnce(scriptDB(t, s), atHour(3))
	reqs, labels := scans.calls()
	if len(reqs) != 1 || !reflect.DeepEqual(reqs[0].Roots, []string{"/home"}) || !reflect.DeepEqual(labels, []string{"sweep-21"}) {
		t.Fatalf("sweeps = %+v, labels %q", reqs, labels)
	}
	assertExecArgs(t, s, "INSERT INTO av_scans", []driver.Value{avsettings.ScopeHost, "running", "heuristic", SourceScheduled})
	assertExecArgs(t, s, "UPDATE av_scans SET status=?", []driver.Value{"finished", int64(0), int64(0), int64(0), false, int64(21)})
	if scanning.Load() != 0 {
		t.Fatal("the tick kept the scan slot")
	}
}

// Every condition that stops a tick stops it before a sweep starts.
func TestTickOnceStops(t *testing.T) {
	off := sweepSettings
	off.ScheduledScan = false
	noLayers := sweepSettings
	noLayers.RuleEngine, noLayers.LocationHeuristics = false, false
	recent := [][]driver.Value{{atHour(3)().Add(-time.Hour).Unix()}}
	cases := []struct {
		name       string
		settings   avsettings.Settings
		hour       int
		prepare    func(s *sqlScript)
		wantInsert int
	}{
		{"settings that cannot be read", sweepSettings, 3, func(s *sqlScript) { s.fail[avSettingsQuery] = errScripted }, 0},
		{"the sweep switched off", off, 3, func(*sqlScript) {}, 0},
		{"another hour", sweepSettings, 4, func(*sqlScript) {}, 0},
		{"every layer off", noLayers, 3, func(*sqlScript) {}, 0},
		{"a last sweep that cannot be read", sweepSettings, 3, func(s *sqlScript) { s.fail[lastSweepQuery] = errScripted }, 0},
		{"a sweep an hour ago", sweepSettings, 3, func(s *sqlScript) { s.rows[lastSweepQuery] = recent }, 0},
		{"a slot held elsewhere", sweepSettings, 3, func(s *sqlScript) { s.rows[getLockQuery] = [][]driver.Value{{int64(0)}} }, 0},
		{"a sweep record that cannot be written", sweepSettings, 3, func(s *sqlScript) { s.fail["INSERT INTO av_scans"] = errScripted }, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("SERVIKA_CLAMSCAN_BIN", filepath.Join(t.TempDir(), "absent"))
			freeScanSlot(t)
			scans := withFakeScans(t)
			s := sweepScript(c.settings)
			c.prepare(s)
			tickOnce(scriptDB(t, s), atHour(c.hour))
			reqs, _ := scans.calls()
			if n := len(s.execsContaining("INSERT INTO av_scans")); n != c.wantInsert || len(reqs) != 0 || scanning.Load() != 0 {
				t.Fatalf("inserts %d, sweeps %d, slot %d", n, len(reqs), scanning.Load())
			}
		})
	}
}

// openWatchResult is a database open that answers err, or a scripted database.
func openWatchResult(t *testing.T, err error) func(string) (*sql.DB, error) {
	t.Helper()
	if err != nil {
		return func(string) (*sql.DB, error) { return nil, err }
	}
	handle := scriptDB(t, newScript())
	return func(string) (*sql.DB, error) { return handle, nil }
}

// runWatcher ends with nil when watching is off or was stopped, and with the
// error otherwise.
func TestRunWatcherOutcomes(t *testing.T) {
	cases := []struct {
		name     string
		dsn      string
		openErr  error
		rulesErr error
		startErr error
		runErr   error
		want     string
	}{
		{"no database address", "", nil, nil, nil, nil, "SERVIKA_DB_DSN is required"},
		{"a database that cannot be opened", "dsn", errScripted, nil, nil, nil, "database: scripted failure"},
		{"watching off, with unreadable packaged rules", "dsn", nil, errScripted, errWatchDisabled, nil, ""},
		{"a watcher that cannot start", "dsn", nil, nil, errScripted, nil, "scripted failure"},
		{"watching turned off while running", "dsn", nil, nil, nil, errWatchDisabled, ""},
		{"a stop signal", "dsn", nil, nil, nil, context.Canceled, ""},
		{"an event loop that fails", "dsn", nil, nil, nil, errScripted, "scripted failure"},
		{"an event loop that ends", "dsn", nil, nil, nil, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("SERVIKA_DB_DSN", c.dsn)
			setForTest(t, &openWatchDB, openWatchResult(t, c.openErr))
			setForTest(t, &loadPackagedRules, func() error { return c.rulesErr })
			setForTest(t, &startWatcher, func(context.Context, *sql.DB) (*watcher, error) { return &watcher{}, c.startErr })
			setForTest(t, &watchFiles, func(*watcher, context.Context) error { return c.runErr })
			err := runWatcher()
			got := ""
			if err != nil {
				got = err.Error()
			}
			if got != c.want {
				t.Fatalf("runWatcher = %q, want %q", got, c.want)
			}
		})
	}
}
