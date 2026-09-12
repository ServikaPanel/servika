package waf

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Show reports three different things that all read as "the WAF state": the
// domain's own override, the plan default behind it and what the host actually
// enforces. Nothing exercised the endpoint, so a wrong column mapping would
// show an operator protection that is not running. These tests pin each of the
// three.

const qWAF = "FROM domains d LEFT JOIN service_plans p"

// wafScript answers the handler's query.
type wafScript struct {
	mu       sync.Mutex
	row      []driver.Value
	noRows   bool
	queryErr error
}

func (s *wafScript) answer() (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	if s.noRows {
		return &wafRows{}, nil
	}
	return &wafRows{values: [][]driver.Value{s.row}}, nil
}

type wafRows struct {
	values [][]driver.Value
	at     int
}

func (r *wafRows) Columns() []string {
	if len(r.values) == 0 {
		return []string{""}
	}
	return make([]string, len(r.values[0]))
}
func (r *wafRows) Close() error { return nil }
func (r *wafRows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

type wafConn struct{ script *wafScript }

func (c wafConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c wafConn) Driver() driver.Driver                        { return wafDriver{} }
func (c wafConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c wafConn) Close() error                                 { return nil }
func (c wafConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c wafConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(query, qWAF) {
		return nil, errors.New("the test script has no answer for: " + query)
	}
	return c.script.answer()
}

type wafDriver struct{}

func (wafDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// wafRow builds the joined row Show reads: the domain columns first, then the
// plan columns.
func wafRow(domainEnabled, domainMode, domainPL, planEnabled, planMode, planPL, planName any) []driver.Value {
	return []driver.Value{
		"example.com", "c_test",
		domainEnabled, domainMode, domainPL,
		planEnabled, planMode, planPL, planName,
	}
}

// inherited is a domain with no override of its own and no plan.
func inherited() *wafScript {
	return &wafScript{row: wafRow(nil, nil, nil, nil, nil, nil, nil)}
}

// hostWAF answers for the host's live ModSecurity state.
type hostWAF struct {
	active   bool
	engine   string
	paranoia int
	loaded   bool
}

func (s *hostWAF) install(t *testing.T) {
	t.Helper()
	effectiveWas, loadedWas := wafEffective, wafModuleLoaded
	t.Cleanup(func() { wafEffective, wafModuleLoaded = effectiveWas, loadedWas })
	wafEffective = func(*sql.DB, string) (bool, string, int) {
		return s.active, s.engine, s.paranoia
	}
	wafModuleLoaded = func() bool { return s.loaded }
}

// enforcing is a host running the module in blocking mode at level 2.
func enforcing() *hostWAF {
	return &hostWAF{active: true, engine: "On", paranoia: 2, loaded: true}
}

func showWAF(t *testing.T, script *wafScript, host *hostWAF) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	host.install(t)
	db := sql.OpenDB(wafConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	h := &Handlers{DB: db}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/domains/7/waf", nil)
	routes := chi.NewRouteContext()
	routes.URLParams.Add("id", "7")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routes))
	w := httptest.NewRecorder()
	h.Show(w, r)
	var decoded map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &decoded)
	return w, decoded
}

// section reads one object out of the answer.
func section(t *testing.T, body map[string]any, key string) map[string]any {
	t.Helper()
	part, ok := body[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is missing from %v", key, body)
	}
	return part
}

func TestShowAnswersNotFoundForAnUnknownDomain(t *testing.T) {
	script := inherited()
	script.noRows = true
	w, decoded := showWAF(t, script, enforcing())
	if w.Code != http.StatusNotFound || decoded["error"] != "domain not found" {
		t.Fatalf("status = %d error = %v, want 404 domain not found", w.Code, decoded["error"])
	}
}

func TestShowFailsWhenTheSettingsCannotBeRead(t *testing.T) {
	script := inherited()
	script.queryErr = errors.New("connection refused")
	w, decoded := showWAF(t, script, enforcing())
	if w.Code != http.StatusInternalServerError || decoded["error"] != "failed to read WAF settings" {
		t.Fatalf("status = %d error = %v, want 500", w.Code, decoded["error"])
	}
}

// A domain with no override inherits, and inherit is reported as such rather
// than as "off": the two mean different things to the screen.
func TestShowReportsAnUnsetOverrideAsInherit(t *testing.T) {
	w, decoded := showWAF(t, inherited(), enforcing())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	settings := section(t, decoded, "settings")
	if settings["mode"] != "inherit" || settings["paranoia"] != float64(0) {
		t.Fatalf("settings = %v, want inherit at 0", settings)
	}
	if decoded["domain_name"] != "example.com" {
		t.Errorf("domain_name = %v", decoded["domain_name"])
	}
}

// The mode is stored across two columns, so each combination has to map back to
// exactly one API mode.
func TestShowMapsTheStoredOverrideToItsMode(t *testing.T) {
	cases := []struct {
		name    string
		enabled any
		mode    any
		want    string
	}{
		{name: "disabled is off", enabled: int64(0), mode: "off", want: "off"},
		{name: "enabled with detect", enabled: int64(1), mode: "detect", want: "detect"},
		{name: "enabled with on", enabled: int64(1), mode: "on", want: "block"},
		{name: "enabled with no mode", enabled: int64(1), mode: nil, want: "block"},
		{name: "uppercase detect", enabled: int64(1), mode: " DETECT ", want: "detect"},
	}
	for _, test := range cases {
		script := &wafScript{row: wafRow(test.enabled, test.mode, nil, nil, nil, nil, nil)}
		_, decoded := showWAF(t, script, enforcing())
		if got := section(t, decoded, "settings")["mode"]; got != test.want {
			t.Errorf("%s: mode = %v, want %s", test.name, got, test.want)
		}
	}
}

func TestShowReportsTheOverriddenParanoiaLevel(t *testing.T) {
	script := &wafScript{row: wafRow(int64(1), "on", int64(3), nil, nil, nil, nil)}
	_, decoded := showWAF(t, script, enforcing())
	if got := section(t, decoded, "settings")["paranoia"]; got != float64(3) {
		t.Fatalf("paranoia = %v, want 3", got)
	}
}

// A domain on no plan reports the default the resolver falls back to, not an
// empty plan.
func TestShowReportsTheDefaultPlanForADomainWithNoPlan(t *testing.T) {
	_, decoded := showWAF(t, inherited(), enforcing())
	plan := section(t, decoded, "plan")
	if plan["active"] != false || plan["mode"] != "off" || plan["paranoia"] != float64(1) {
		t.Fatalf("plan = %v, want an inactive plan off at level 1", plan)
	}
	if _, named := plan["name"]; named {
		t.Errorf("plan carries a name for a domain with no plan: %v", plan["name"])
	}
}

func TestShowReportsThePlanBehindTheDomain(t *testing.T) {
	script := &wafScript{row: wafRow(nil, nil, nil, int64(1), "detect", int64(4), "Bronze")}
	_, decoded := showWAF(t, script, enforcing())
	plan := section(t, decoded, "plan")
	if plan["active"] != true || plan["mode"] != "detect" {
		t.Fatalf("plan = %v, want an active plan in detect", plan)
	}
	if plan["paranoia"] != float64(4) || plan["name"] != "Bronze" {
		t.Fatalf("plan = %v, want level 4 named Bronze", plan)
	}
}

// A plan that is switched off keeps its name and level but must not read as
// active, or the screen shows protection that is not running.
func TestShowReportsADisabledPlanAsInactive(t *testing.T) {
	script := &wafScript{row: wafRow(nil, nil, nil, int64(0), "on", int64(2), "Bronze")}
	_, decoded := showWAF(t, script, enforcing())
	plan := section(t, decoded, "plan")
	if plan["active"] != false || plan["mode"] != "off" {
		t.Fatalf("plan = %v, want an inactive plan reported off", plan)
	}
	if plan["paranoia"] != float64(2) || plan["name"] != "Bronze" {
		t.Fatalf("plan = %v, want level 2 named Bronze", plan)
	}
}

// The effective block comes from the same resolver the provisioner uses, so the
// screen cannot drift from what the vhost renders.
func TestShowReportsWhatTheHostEnforces(t *testing.T) {
	_, decoded := showWAF(t, inherited(), enforcing())
	effective := section(t, decoded, "effective")
	if effective["active"] != true || effective["engine"] != "On" || effective["paranoia"] != float64(2) {
		t.Fatalf("effective = %v, want the host state", effective)
	}
	if decoded["module_loaded"] != true {
		t.Errorf("module_loaded = %v, want true", decoded["module_loaded"])
	}
}

// A host with no module still answers, with the flag the screen uses to explain
// why nothing is enforced.
func TestShowReportsAHostWithNoModule(t *testing.T) {
	w, decoded := showWAF(t, inherited(), &hostWAF{engine: "Off", paranoia: 1})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if decoded["module_loaded"] != false {
		t.Fatalf("module_loaded = %v, want false", decoded["module_loaded"])
	}
	if section(t, decoded, "effective")["active"] != false {
		t.Fatal("a host with no module reported an active WAF")
	}
}
