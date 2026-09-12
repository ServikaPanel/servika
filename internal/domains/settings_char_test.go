package domains

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"servika/internal/provisioner"
)

// settingsCase is one request to a settings handler for domain 7.
type settingsCase struct {
	name    string
	body    string
	script  func(*sqlScript)
	status  int
	message string
	steps   []string
}

// serveSettings runs one handler against the script, for domain 7.
func serveSettings(t *testing.T, script *sqlScript, handler func(*Handlers) http.HandlerFunc, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler(&Handlers{DB: scriptDB(t, script)})(recorder, requestWithParams(method, body, map[string]string{"id": "7"}))
	return recorder
}

// applyScript runs a case's script change when it has one.
func applyScript(s *sqlScript, change func(*sqlScript)) *sqlScript {
	if change != nil {
		change(s)
	}
	return s
}

// planFakes stands in for the background work a plan change starts.
type planFakes struct {
	hostCalls
	limitsErr error
	wafErr    error
	mailErr   error
	done      chan int64
}

func newPlanFakes(t *testing.T) *planFakes {
	t.Helper()
	f := &planFakes{done: make(chan int64, 1)}
	setForTest(t, &applyResourceLimits, f.limits)
	setForTest(t, &applyWAF, f.waf)
	setForTest(t, &applyMailPlanLimits, f.mail)
	return f
}

func (f *planFakes) limits(_ context.Context, _ *sql.DB, id int64) error {
	f.record("limits %d", id)
	return f.limitsErr
}

func (f *planFakes) waf(_ *sql.DB, id int64) error {
	f.record("waf %d", id)
	return f.wafErr
}

func (f *planFakes) mail(_ context.Context, _ *sql.DB, id int64) (int64, error) {
	f.record("mail limits %d", id)
	f.done <- id
	return 0, f.mailErr
}

func planScript() *sqlScript {
	s := newScript()
	s.rows["SELECT COUNT(*) FROM service_plans WHERE id=?"] = [][]driver.Value{{int64(1)}}
	s.rows["SELECT system_user FROM domains WHERE id=?"] = [][]driver.Value{{"c_example"}}
	return s
}

func TestSetPlanRefusesWhatItCannotAssign(t *testing.T) {
	const body = `{"plan_id":3}`
	cases := []settingsCase{
		{name: "an unreadable body", body: `{`, status: http.StatusBadRequest, message: "invalid request body"},
		{name: "a plan lookup that fails", body: body,
			script: func(s *sqlScript) { s.fail["SELECT COUNT(*) FROM service_plans WHERE id=?"] = errScripted },
			status: http.StatusInternalServerError, message: "database operation failed"},
		{name: "a plan that does not exist", body: body,
			script: func(s *sqlScript) {
				s.rows["SELECT COUNT(*) FROM service_plans WHERE id=?"] = [][]driver.Value{{int64(0)}}
			},
			status: http.StatusBadRequest, message: "plan not found"},
		{name: "a domain that does not exist", body: body,
			script: func(s *sqlScript) { s.rows["SELECT system_user FROM domains WHERE id=?"] = nil },
			status: http.StatusNotFound, message: "domain not found"},
		{name: "a domain that cannot be read", body: body,
			script: func(s *sqlScript) { s.fail["SELECT system_user FROM domains WHERE id=?"] = errScripted },
			status: http.StatusInternalServerError, message: "database operation failed"},
		{name: "an assignment that cannot be written", body: body,
			script: func(s *sqlScript) { s.fail["UPDATE domains SET plan_id=?"] = errScripted },
			status: http.StatusInternalServerError, message: "plan assignment failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakes := newPlanFakes(t)
			recorder := serveSettings(t, applyScript(planScript(), tc.script), planHandler, http.MethodPut, tc.body)
			assertOutcome(t, recorder, tc.status, tc.message)
			assertSteps(t, &fakes.hostCalls)
		})
	}
}

func planHandler(h *Handlers) http.HandlerFunc { return h.SetPlan }

// A plan change is written, answered, and then followed by the resource limits,
// the WAF render and the mail limits, each best-effort.
func TestSetPlanReappliesWhatFollowsThePlan(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		failed bool
		args   []driver.Value
		answer string
	}{
		{name: "a new plan", body: `{"plan_id":3}`, args: []driver.Value{int64(3), int64(7)},
			answer: `{"ok":true,"plan_id":3}`},
		{name: "a removed plan whose follow-ups all fail", body: `{"plan_id":null}`, failed: true,
			args: []driver.Value{nil, int64(7)}, answer: `{"ok":true,"plan_id":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakes := newPlanFakes(t)
			if tc.failed {
				fakes.limitsErr, fakes.wafErr, fakes.mailErr = errScripted, errScripted, errScripted
			}
			script := planScript()
			recorder := serveSettings(t, script, planHandler, http.MethodPut, tc.body)
			waitForID(t, fakes.done, 7)
			assertOutcome(t, recorder, http.StatusOK, "")
			assertJSONBody(t, recorder, tc.answer)
			assertExecArgs(t, script, "UPDATE domains SET plan_id=?", tc.args)
			assertSteps(t, &fakes.hostCalls, "limits 7", "waf 7", "mail limits 7")
		})
	}
}

// assertJSONBody compares a JSON answer with want, ignoring key order.
func assertJSONBody(t *testing.T, recorder *httptest.ResponseRecorder, want string) {
	t.Helper()
	var got, expected any
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode %q: %v", recorder.Body.String(), err)
	}
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("body = %s, want %s", recorder.Body.String(), want)
	}
}

// suspendFakes stands in for the render and the runtime a suspension reaches.
type suspendFakes struct {
	hostCalls
	renderErr error
	appsErr   error
}

func newSuspendFakes(t *testing.T) *suspendFakes {
	t.Helper()
	f := &suspendFakes{}
	setForTest(t, &rerenderVhost, f.render)
	setForTest(t, &suspendUserRuntime, f.runtime)
	setForTest(t, &suspendApps, f.apps)
	return f
}

func (f *suspendFakes) render(_ *sql.DB, id int64) error {
	f.record("render %d", id)
	return f.renderErr
}

func (f *suspendFakes) runtime(user string, suspended bool) {
	f.record("runtime %s %t", user, suspended)
}

func (f *suspendFakes) apps(_ context.Context, _ *sql.DB, user string, suspended bool) error {
	f.record("apps %s %t", user, suspended)
	return f.appsErr
}

func suspendScript() *sqlScript {
	s := newScript()
	s.rows["SELECT domain_name, system_user FROM domains WHERE id=?"] = [][]driver.Value{{"example.com", "c_example"}}
	s.rows["FROM domains WHERE id=? OR parent_domain_id=? ORDER BY id"] = [][]driver.Value{{int64(7), int64(0), "active", int64(0)}}
	return s
}

func TestApplyDomainSuspendReachesEveryDependent(t *testing.T) {
	cases := []struct {
		name      string
		suspended bool
		script    func(*sqlScript)
		fakes     func(*suspendFakes)
		wantName  string
		wantErr   error
		steps     []string
	}{
		{name: "a domain that does not exist", suspended: true,
			script:  func(s *sqlScript) { s.rows["SELECT domain_name, system_user FROM domains WHERE id=?"] = nil },
			wantErr: sql.ErrNoRows},
		{name: "a domain that cannot be read", suspended: true,
			script:  func(s *sqlScript) { s.fail["SELECT domain_name, system_user FROM domains WHERE id=?"] = errScripted },
			wantErr: errScripted},
		{name: "targets that cannot be read", suspended: true,
			script:   func(s *sqlScript) { s.fail["FROM domains WHERE id=? OR parent_domain_id=? ORDER BY id"] = errScripted },
			wantName: "example.com", wantErr: errScripted},
		{name: "a state that cannot be written", suspended: true,
			script: func(s *sqlScript) {
				s.fail["UPDATE domains SET suspended=?, status=?, suspended_by_reseller=0"] = errScripted
			},
			wantName: "example.com", wantErr: errScripted},
		{name: "a render that fails is rolled back", suspended: true,
			fakes:    func(f *suspendFakes) { f.renderErr = errScripted },
			wantName: "example.com", wantErr: errScripted, steps: []string{"render 7", "render 7"}},
		{name: "a suspension", suspended: true, wantName: "example.com",
			steps: []string{"render 7", "runtime c_example true", "apps c_example true"}},
		{name: "a resume whose dependents all fail", wantName: "example.com",
			script: func(s *sqlScript) {
				s.fail["UPDATE ftp_accounts SET status=?"] = errScripted
				s.fail["UPDATE mail_domains SET status=?"] = errScripted
				s.fail["UPDATE mailboxes SET status=?"] = errScripted
			},
			fakes: func(f *suspendFakes) { f.appsErr = errScripted },
			steps: []string{"render 7", "runtime c_example false", "apps c_example false"}},
		{name: "a domain with no system user", suspended: true, wantName: "example.com",
			script: func(s *sqlScript) {
				s.rows["SELECT domain_name, system_user FROM domains WHERE id=?"] = [][]driver.Value{{"example.com", ""}}
			},
			steps: []string{"render 7"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakes := newSuspendFakes(t)
			if tc.fakes != nil {
				tc.fakes(fakes)
			}
			db := scriptDB(t, applyScript(suspendScript(), tc.script))
			name, err := ApplyDomainSuspend(context.Background(), db, 7, tc.suspended)
			if name != tc.wantName || !errors.Is(err, tc.wantErr) {
				t.Errorf("ApplyDomainSuspend() = %q, %v, want %q, %v", name, err, tc.wantName, tc.wantErr)
			}
			assertSteps(t, &fakes.hostCalls, tc.steps...)
		})
	}
}

// Suspending closes the FTP, mail-domain and mailbox rows of the domain and its
// addons; resuming opens them.
func TestTheSuspensionStateReachesFTPAndMail(t *testing.T) {
	const ftpStatement = `UPDATE ftp_accounts SET status=? WHERE ` + ownedByDomainOrItsAddons
	for _, tc := range []struct {
		name      string
		suspended bool
		status    string
	}{
		{name: "suspend", suspended: true, status: "suspended"},
		{name: "resume", status: "active"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newSuspendFakes(t)
			script := suspendScript()
			if _, err := ApplyDomainSuspend(context.Background(), scriptDB(t, script), 7, tc.suspended); err != nil {
				t.Fatal(err)
			}
			bound := []driver.Value{tc.status, int64(7), int64(7)}
			if statements := script.execsContaining("UPDATE ftp_accounts"); len(statements) != 1 || statements[0].query != ftpStatement {
				t.Errorf("FTP statements = %+v, want %q", statements, ftpStatement)
			}
			assertExecArgs(t, script, "UPDATE ftp_accounts", bound)
			assertExecArgs(t, script, "UPDATE mail_domains SET status=?", bound)
			assertExecArgs(t, script, "UPDATE mailboxes SET status=?", bound)
		})
	}
}

// The revocation the suspension documents actually happens, and it happens on
// the ONE column an authentication path reads. The cascade used to bump
// ftp_accounts.token_version, which nothing has read since customer login moved
// off the FTP identity, so the customer's panel session survived the
// suspension: every authenticated route that is not domain-scoped stayed
// reachable.
func TestSuspendingRevokesTheCustomerPanelSession(t *testing.T) {
	newSuspendFakes(t)
	script := suspendScript()

	if _, err := ApplyDomainSuspend(context.Background(), scriptDB(t, script), 7, true); err != nil {
		t.Fatal(err)
	}

	statements := script.execsContaining("UPDATE users")
	if len(statements) != 1 {
		t.Fatalf("the suspension ran %d token_version bumps on users, want 1", len(statements))
	}
	written := statements[0].query
	if !strings.Contains(written, "u.token_version = u.token_version + 1") {
		t.Errorf("the bump does not increment users.token_version:\n%s", written)
	}
	// The CUSTOMER's account, never the reseller who owns them: suspending one
	// domain must not sign a reseller out of the panel.
	if !strings.Contains(written, "c.user_id = u.id") {
		t.Errorf("the bump does not join through customers.user_id:\n%s", written)
	}
	if strings.Contains(written, "owner_user_id") {
		t.Errorf("the bump reaches the reseller's own account:\n%s", written)
	}
	if len(script.execsContaining("ftp_accounts SET status=?, token_version")) != 0 {
		t.Error("the dead ftp_accounts bump is still written")
	}
}

// Resuming revokes nothing: the session was already cut when the suspension
// went in, and signing the customer out again on the way back is not a
// boundary, only an interruption.
func TestResumingDoesNotRevokeAnything(t *testing.T) {
	newSuspendFakes(t)
	script := suspendScript()

	if _, err := ApplyDomainSuspend(context.Background(), scriptDB(t, script), 7, false); err != nil {
		t.Fatal(err)
	}
	if got := len(script.execsContaining("token_version")); got != 0 {
		t.Errorf("a resume ran %d token_version writes, want 0", got)
	}
}

// ipv6Fakes stands in for the address check and the DNS writes an IPv6 change
// makes.
type ipv6Fakes struct {
	hostCalls
	repointErr error
	zoneErr    error
}

func newIPv6Fakes(t *testing.T) *ipv6Fakes {
	t.Helper()
	f := &ipv6Fakes{}
	setForTest(t, &addressIsLocal, f.local)
	setForTest(t, &repointIPv6, f.repoint)
	setForTest(t, &writeDNSZone, f.zone)
	return f
}

func (f *ipv6Fakes) local(value string) bool {
	f.record("local? %s", value)
	return true
}

func (f *ipv6Fakes) repoint(_ context.Context, _ *sql.DB, id int64, name, previous, next string) (int, error) {
	f.record("repoint %d %s %q %q", id, name, previous, next)
	return 2, f.repointErr
}

func (f *ipv6Fakes) zone(_ context.Context, _ *sql.DB, id int64) error {
	f.record("zone %d", id)
	return f.zoneErr
}

func ipv6Script() *sqlScript {
	s := newScript()
	s.rows["SELECT domain_name, COALESCE(ipv6,'') FROM domains"] = [][]driver.Value{{"example.com", "2001:db8::1"}}
	return s
}

func ipv6Handler(h *Handlers) http.HandlerFunc { return h.SetIPv6 }

func TestSetIPv6StoresTheAddressAndRepointsItsRecords(t *testing.T) {
	const body = `{"ipv6":" 2001:DB8:0::5 "}`
	checked := []string{"local? 2001:DB8:0::5"}
	repointed := `repoint 7 example.com "2001:db8::1" "2001:db8::5"`
	cases := []settingsCase{
		{name: "an unreadable body", body: `{`, status: http.StatusBadRequest, message: "invalid request body"},
		{name: "a domain that does not exist", body: body,
			script: func(s *sqlScript) { s.rows["SELECT domain_name, COALESCE(ipv6,'') FROM domains"] = nil },
			status: http.StatusNotFound, message: "domain not found", steps: checked},
		{name: "a domain that cannot be read", body: body,
			script: func(s *sqlScript) { s.fail["SELECT domain_name, COALESCE(ipv6,'') FROM domains"] = errScripted },
			status: http.StatusInternalServerError, message: "database operation failed", steps: checked},
		{name: "an address that cannot be saved", body: body,
			script: func(s *sqlScript) { s.fail["UPDATE domains SET ipv6=?"] = errScripted },
			status: http.StatusInternalServerError, message: "could not save the address", steps: checked},
		{name: "records that cannot be repointed", body: body,
			status: http.StatusInternalServerError, message: "the address was saved but its DNS records could not be updated",
			steps: joinSteps(checked, []string{repointed})},
		{name: "a zone that cannot be written", body: body,
			status: http.StatusInternalServerError, message: "the records were updated but the DNS zone could not be written",
			steps: joinSteps(checked, []string{repointed, "zone 7"})},
		{name: "a stored address in canonical form", body: body, status: http.StatusOK,
			steps: joinSteps(checked, []string{repointed, "zone 7"})},
		{name: "a cleared address", body: `{"ipv6":""}`, status: http.StatusOK,
			steps: []string{`repoint 7 example.com "2001:db8::1" ""`, "zone 7"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakes := newIPv6Fakes(t)
			fakes.repointErr = errorFor(tc.name == "records that cannot be repointed")
			fakes.zoneErr = errorFor(tc.name == "a zone that cannot be written")
			recorder := serveSettings(t, applyScript(ipv6Script(), tc.script), ipv6Handler, http.MethodPut, tc.body)
			assertOutcome(t, recorder, tc.status, tc.message)
			assertSteps(t, &fakes.hostCalls, tc.steps...)
		})
	}
}

// errorFor returns the scripted failure when fail is true.
func errorFor(fail bool) error {
	if fail {
		return errScripted
	}
	return nil
}

func TestSetIPv6AnswersWithTheCanonicalAddress(t *testing.T) {
	newIPv6Fakes(t)
	script := ipv6Script()
	recorder := serveSettings(t, script, ipv6Handler, http.MethodPut, `{"ipv6":"2001:DB8:0::5"}`)
	assertOutcome(t, recorder, http.StatusOK, "")
	assertJSONBody(t, recorder, `{"ok":true,"ipv6":"2001:db8::5","records":2}`)
	assertExecArgs(t, script, "UPDATE domains SET ipv6=?", []driver.Value{"2001:db8::5", int64(7)})
}

// maintenanceFakes stands in for the page file and the render a maintenance
// change makes.
type maintenanceFakes struct {
	hostCalls
	pageErr   error
	renderErr error
	page      provisioner.MaintenancePage
}

func newMaintenanceFakes(t *testing.T) *maintenanceFakes {
	t.Helper()
	f := &maintenanceFakes{}
	setForTest(t, &writeMaintenancePage, f.writePage)
	setForTest(t, &rerenderVhost, f.render)
	return f
}

func (f *maintenanceFakes) writePage(id int64, page provisioner.MaintenancePage) error {
	f.record("page %d", id)
	f.page = page
	return f.pageErr
}

func (f *maintenanceFakes) render(_ *sql.DB, id int64) error {
	f.record("render %d", id)
	return f.renderErr
}

// maintenanceScript answers for a domain that can be put into maintenance, and
// the status read that follows a save.
func maintenanceScript() *sqlScript {
	s := newScript()
	s.rows["SELECT 1 FROM domains WHERE id=?"] = [][]driver.Value{{int64(1)}}
	s.rows["SELECT COALESCE(custom_vhost_enabled,0)"] = [][]driver.Value{{int64(0)}}
	s.rows["SELECT COUNT(*) FROM domain_redirects WHERE domain_id=?"] = [][]driver.Value{{int64(0)}}
	s.rows["SELECT COALESCE(maintenance_enabled,0)"] = [][]driver.Value{{int64(1), nil, "Back soon", "", "", ""}}
	s.rows["FROM domain_maintenance_ips WHERE domain_id=?"] = nil
	return s
}

func maintenanceHandler(h *Handlers) http.HandlerFunc { return h.MaintenanceSave }

func TestMaintenanceSaveRefusesWhatItCannotApply(t *testing.T) {
	const on = `{"enabled":true}`
	cases := []settingsCase{
		{name: "an unreadable body", body: `{`, status: http.StatusBadRequest, message: "invalid request body"},
		{name: "a domain that does not exist", body: on,
			script: func(s *sqlScript) { s.rows["SELECT 1 FROM domains WHERE id=?"] = nil },
			status: http.StatusNotFound, message: "domain not found"},
		{name: "a domain that cannot be read", body: on,
			script: func(s *sqlScript) { s.fail["SELECT 1 FROM domains WHERE id=?"] = errScripted },
			status: http.StatusInternalServerError, message: "database operation failed"},
		{name: "an availability check that fails", body: on,
			script: func(s *sqlScript) { s.fail["SELECT COALESCE(custom_vhost_enabled,0)"] = errScripted },
			status: http.StatusInternalServerError, message: "database operation failed"},
		{name: "a custom vhost", body: on,
			script: func(s *sqlScript) { s.rows["SELECT COALESCE(custom_vhost_enabled,0)"] = [][]driver.Value{{int64(1)}} },
			status: http.StatusConflict, message: maintenanceUnavailableMessage(reasonMaintenanceCustomVhost)},
		{name: "a redirect-only domain", body: on,
			script: func(s *sqlScript) {
				s.rows["SELECT COUNT(*) FROM domain_redirects WHERE domain_id=?"] = [][]driver.Value{{int64(1)}}
			},
			status: http.StatusConflict, message: maintenanceUnavailableMessage(reasonMaintenanceRedirectOnly)},
		{name: "a page that cannot be written", body: on,
			status: http.StatusInternalServerError, message: "the maintenance page could not be written", steps: []string{"page 7"}},
		{name: "settings that cannot be saved", body: on,
			script: func(s *sqlScript) { s.fail["SET maintenance_enabled=1, maintenance_until=NULL"] = errScripted },
			status: http.StatusInternalServerError, message: "the maintenance settings could not be saved", steps: []string{"page 7"}},
		{name: "a render that fails", body: `{"enabled":false}`,
			status: http.StatusInternalServerError, message: "the settings were saved but the web server configuration could not be applied",
			steps: []string{"page 7", "render 7"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakes := newMaintenanceFakes(t)
			fakes.pageErr = errorFor(tc.name == "a page that cannot be written")
			fakes.renderErr = errorFor(tc.name == "a render that fails")
			recorder := serveSettings(t, applyScript(maintenanceScript(), tc.script), maintenanceHandler, http.MethodPut, tc.body)
			assertOutcome(t, recorder, tc.status, tc.message)
			assertSteps(t, &fakes.hostCalls, tc.steps...)
		})
	}
}

// The page fields are cleaned before they are written, and the window is stored
// as a duration the database clock applies, capped at a month.
func TestMaintenanceSaveStoresTheWindow(t *testing.T) {
	const fields = `"title":"  Back soon\n","message":"Line one\r\nLine two","accent":" #ff0000 ","logo_url":" https://example.com/logo.png "`
	page := []driver.Value{"Back soon", "Line one\nLine two", "#ff0000", "https://example.com/logo.png", int64(7)}
	for _, tc := range []struct {
		name     string
		body     string
		fragment string
		args     []driver.Value
	}{
		{name: "switched off", body: `{"enabled":false,` + fields + `}`, fragment: "SET maintenance_enabled=0", args: page},
		{name: "open-ended", body: `{"enabled":true,"duration_minutes":-5,` + fields + `}`,
			fragment: "SET maintenance_enabled=1, maintenance_until=NULL", args: page},
		{name: "for ninety minutes", body: `{"enabled":true,"duration_minutes":90,` + fields + `}`,
			fragment: "INTERVAL ? MINUTE", args: append([]driver.Value{int64(90)}, page...)},
		{name: "for longer than a month", body: `{"enabled":true,"duration_minutes":999999,` + fields + `}`,
			fragment: "INTERVAL ? MINUTE", args: append([]driver.Value{int64(43200)}, page...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakes := newMaintenanceFakes(t)
			script := maintenanceScript()
			recorder := serveSettings(t, script, maintenanceHandler, http.MethodPut, tc.body)
			assertOutcome(t, recorder, http.StatusOK, "")
			assertSteps(t, &fakes.hostCalls, "page 7", "render 7")
			assertExecArgs(t, script, tc.fragment, tc.args)
			want := provisioner.MaintenancePage{Title: "Back soon", Message: "Line one\nLine two",
				Accent: "#ff0000", LogoURL: "https://example.com/logo.png"}
			if fakes.page != want {
				t.Errorf("page = %+v, want %+v", fakes.page, want)
			}
		})
	}
}

// geoFakes stands in for the country database and the render a country policy
// change makes.
type geoFakes struct {
	hostCalls
	available bool
	known     bool
	renderErr error
}

func newGeoFakes(t *testing.T) *geoFakes {
	t.Helper()
	f := &geoFakes{available: true, known: true}
	setForTest(t, &geoDatabaseAvailable, f.databaseAvailable)
	setForTest(t, &geoKnownCountry, f.knownCountry)
	setForTest(t, &rerenderVhost, f.render)
	return f
}

func (f *geoFakes) databaseAvailable() bool {
	f.record("geo database?")
	return f.available
}

func (f *geoFakes) knownCountry(code string) bool {
	f.record("known %s", code)
	return f.known
}

func (f *geoFakes) render(_ *sql.DB, id int64) error {
	f.record("render %d", id)
	return f.renderErr
}

// domainInfoScript answers the system user and PHP version lookup the access
// control and redirect handlers share.
func domainInfoScript() *sqlScript {
	s := newScript()
	s.rows["SELECT system_user, COALESCE(php_version,'8.3') FROM domains WHERE id=?"] = [][]driver.Value{{"c_example", "8.3"}}
	return s
}

func geoHandler(h *Handlers) http.HandlerFunc { return h.SetGeo }

// manyCountries returns n distinct two-letter codes.
func manyCountries(n int) []string {
	var codes []string
	for first := 'A'; len(codes) < n; first++ {
		for second := 'A'; second <= 'Z' && len(codes) < n; second++ {
			codes = append(codes, string([]rune{first, second}))
		}
	}
	return codes
}

func TestSetGeoRefusesAPolicyItCannotEnforce(t *testing.T) {
	const deny = `{"mode":"deny","countries":["de","fr"]}`
	tooMany, _ := json.Marshal(geoSettings{Mode: "deny", Countries: manyCountries(maxDomainCountries + 1)})
	checked := []string{"geo database?", "known DE", "known FR"}
	cases := []settingsCase{
		{name: "a domain that does not exist", body: deny,
			script: func(s *sqlScript) {
				s.rows["SELECT system_user, COALESCE(php_version,'8.3') FROM domains WHERE id=?"] = nil
			},
			status: http.StatusNotFound, message: "domain not found"},
		{name: "a domain that cannot be read", body: deny,
			script: func(s *sqlScript) {
				s.fail["SELECT system_user, COALESCE(php_version,'8.3') FROM domains WHERE id=?"] = errScripted
			},
			status: http.StatusInternalServerError, message: "database read failed"},
		{name: "an unreadable body", body: `{`, status: http.StatusBadRequest, message: "invalid request body"},
		{name: "an unknown mode", body: `{"mode":"block"}`, status: http.StatusBadRequest, message: "mode must be off, allow or deny"},
		{name: "a value that is not a country code", body: `{"mode":"deny","countries":["germany"]}`,
			status: http.StatusBadRequest, message: "that is not a country code"},
		{name: "too many countries", body: string(tooMany), status: http.StatusBadRequest, message: "too many countries"},
		{name: "no country database", body: deny,
			status: http.StatusConflict, message: "no country database has been downloaded", steps: []string{"geo database?"}},
		{name: "a policy with no country", body: `{"mode":"allow","countries":[]}`,
			status: http.StatusBadRequest, message: "select at least one country", steps: []string{"geo database?"}},
		{name: "a country the database does not carry", body: deny,
			status: http.StatusBadRequest, message: "the country database does not carry that country", steps: []string{"geo database?", "known DE"}},
		{name: "a transaction that cannot begin", body: deny,
			script: func(s *sqlScript) { s.beginErr = errScripted },
			status: http.StatusInternalServerError, message: "country rules could not be saved", steps: checked},
		{name: "a mode that cannot be written", body: deny,
			script: func(s *sqlScript) { s.fail["UPDATE domains SET geo_mode=?"] = errScripted },
			status: http.StatusInternalServerError, message: "country rules could not be saved", steps: checked},
		{name: "old rules that cannot be removed", body: deny,
			script: func(s *sqlScript) { s.fail["DELETE FROM domain_geo_rules"] = errScripted },
			status: http.StatusInternalServerError, message: "country rules could not be saved", steps: checked},
		{name: "a rule that cannot be inserted", body: deny,
			script: func(s *sqlScript) { s.fail["INSERT INTO domain_geo_rules"] = errScripted },
			status: http.StatusInternalServerError, message: "country rules could not be saved", steps: checked},
		{name: "a commit that fails", body: deny,
			script: func(s *sqlScript) { s.commitErr = errScripted },
			status: http.StatusInternalServerError, message: "country rules could not be saved", steps: checked},
		{name: "a render that fails", body: deny,
			status: http.StatusInternalServerError, message: "rules saved but virtual host update failed",
			steps: joinSteps(checked, []string{"render 7"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakes := newGeoFakes(t)
			fakes.available = tc.name != "no country database"
			fakes.known = tc.name != "a country the database does not carry"
			fakes.renderErr = errorFor(tc.name == "a render that fails")
			recorder := serveSettings(t, applyScript(domainInfoScript(), tc.script), geoHandler, http.MethodPut, tc.body)
			assertOutcome(t, recorder, tc.status, tc.message)
			assertSteps(t, &fakes.hostCalls, tc.steps...)
		})
	}
}

// A policy replaces the stored one inside one transaction, with each country
// normalised and stored once; switching it off asks nothing of the database.
func TestSetGeoReplacesThePolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		steps   []string
		mode    string
		inserts [][]driver.Value
	}{
		{name: "a deny list", body: `{"mode":"deny","countries":["de"," fr","DE"]}`,
			steps: []string{"geo database?", "known DE", "known FR", "render 7"}, mode: "deny",
			inserts: [][]driver.Value{{int64(7), "DE"}, {int64(7), "FR"}}},
		{name: "switched off", body: `{"mode":"off","countries":[]}`, steps: []string{"render 7"}, mode: "off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakes := newGeoFakes(t)
			script := domainInfoScript()
			recorder := serveSettings(t, script, geoHandler, http.MethodPut, tc.body)
			assertOutcome(t, recorder, http.StatusOK, "")
			assertSteps(t, &fakes.hostCalls, tc.steps...)
			assertExecArgs(t, script, "UPDATE domains SET geo_mode=?", []driver.Value{tc.mode, int64(7)})
			assertExecArgs(t, script, "DELETE FROM domain_geo_rules", []driver.Value{int64(7)})
			assertExecArgs(t, script, "INSERT INTO domain_geo_rules", tc.inserts...)
			if steps := script.stepsSnapshot(); steps[1] != "BEGIN" || steps[len(steps)-1] != "COMMIT" {
				t.Errorf("the writes did not run inside one transaction: %q", steps)
			}
		})
	}
}

// wwwFakes stands in for the DNS and certificate checks and the render a
// canonical hostname change makes.
type wwwFakes struct {
	hostCalls
	resolves  bool
	covers    bool
	socketErr error
	vhostErr  error
}

func newWWWFakes(t *testing.T) *wwwFakes {
	t.Helper()
	f := &wwwFakes{resolves: true, covers: true}
	setForTest(t, &wwwResolvesToApex, f.resolvesToApex)
	setForTest(t, &certificateCoversHost, f.coversHost)
	setForTest(t, &phpSocketFor, f.socket)
	setForTest(t, &applyVhostForDomain, f.vhost)
	return f
}

func (f *wwwFakes) resolvesToApex(domain string) bool {
	f.record("www resolves? %s", domain)
	return f.resolves
}

func (f *wwwFakes) coversHost(cert, key, host string) bool {
	f.record("covers %s %s %s", cert, key, host)
	return f.covers
}

func (f *wwwFakes) socket(user, php string) (string, error) {
	f.record("socket %s %s", user, php)
	return "/run/php-fpm/c_example-83.sock", f.socketErr
}

func (f *wwwFakes) vhost(_ *sql.DB, id int64, socket, php string) error {
	f.record("vhost %d %s %s", id, socket, php)
	return f.vhostErr
}

// wwwScript answers for a root domain with an installed certificate.
func wwwScript() *sqlScript {
	s := domainInfoScript()
	s.rows["SELECT domain_name, COALESCE(cert_path,'')"] = [][]driver.Value{{"example.com", "/etc/ssl/e.crt", "/etc/ssl/e.key", nil}}
	return s
}

func wwwHandler(h *Handlers) http.HandlerFunc { return h.SetWWWRedirect }

func TestSetWWWRedirectRefusesARedirectThatWouldBreakTheSite(t *testing.T) {
	const toWWW = `{"mode":"to_www"}`
	render := []string{"www resolves? example.com", "covers /etc/ssl/e.crt /etc/ssl/e.key www.example.com",
		"socket c_example 8.3", "vhost 7 /run/php-fpm/c_example-83.sock 8.3"}
	cases := []settingsCase{
		{name: "a domain that does not exist", body: toWWW,
			script: func(s *sqlScript) {
				s.rows["SELECT system_user, COALESCE(php_version,'8.3') FROM domains WHERE id=?"] = nil
			},
			status: http.StatusNotFound, message: "domain not found"},
		{name: "an unreadable body", body: `{`, status: http.StatusBadRequest, message: "invalid request body"},
		{name: "an unknown mode", body: `{"mode":"both"}`, status: http.StatusBadRequest, message: "mode must be off, to_www or to_apex"},
		{name: "a certificate row that cannot be read", body: toWWW,
			script: func(s *sqlScript) { s.fail["SELECT domain_name, COALESCE(cert_path,'')"] = errScripted },
			status: http.StatusInternalServerError, message: "database read failed"},
		{name: "an addon domain", body: toWWW,
			script: func(s *sqlScript) {
				s.rows["SELECT domain_name, COALESCE(cert_path,'')"] = [][]driver.Value{{"addon.example", "", "", int64(1)}}
			},
			status: http.StatusBadRequest, message: "only a root domain has a canonical hostname setting"},
		{name: "a domain that is already a www hostname", body: `{"mode":"to_apex"}`,
			script: func(s *sqlScript) {
				s.rows["SELECT domain_name, COALESCE(cert_path,'')"] = [][]driver.Value{{"WWW.example.com", "", "", nil}}
			},
			status: http.StatusBadRequest, message: "the domain is already a www hostname"},
		{name: "a www name that does not resolve here", body: toWWW,
			status: http.StatusBadRequest, message: "www.example.com does not resolve to this server; point it here first",
			steps: []string{"www resolves? example.com"}},
		{name: "a certificate that does not cover the target", body: `{"mode":"to_apex"}`,
			status: http.StatusBadRequest, message: "the installed certificate does not cover example.com; reissue it first",
			steps: []string{"covers /etc/ssl/e.crt /etc/ssl/e.key example.com"}},
		{name: "a setting that cannot be saved", body: toWWW,
			script: func(s *sqlScript) { s.fail["UPDATE domains SET www_redirect=?"] = errScripted },
			status: http.StatusInternalServerError, message: "redirect settings could not be saved", steps: render[:2]},
		{name: "a render that fails and a rollback that fails", body: toWWW,
			script: func(s *sqlScript) { s.fail["UPDATE domains SET www_redirect='off'"] = errScripted },
			status: http.StatusInternalServerError, message: "virtual host update failed", steps: render},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakes := newWWWFakes(t)
			fakes.resolves = tc.name != "a www name that does not resolve here"
			fakes.covers = tc.name != "a certificate that does not cover the target"
			fakes.vhostErr = errorFor(tc.name == "a render that fails and a rollback that fails")
			recorder := serveSettings(t, applyScript(wwwScript(), tc.script), wwwHandler, http.MethodPut, tc.body)
			assertOutcome(t, recorder, tc.status, tc.message)
			assertSteps(t, &fakes.hostCalls, tc.steps...)
		})
	}
}

// A redirect that renders is stored; one that does not is put back to off.
func TestSetWWWRedirectStoresOnlyWhatRendered(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		fakes   func(*wwwFakes)
		status  int
		steps   []string
		written [][]driver.Value
	}{
		{name: "switched off", body: `{"mode":"off"}`, status: http.StatusOK,
			steps:   []string{"socket c_example 8.3", "vhost 7 /run/php-fpm/c_example-83.sock 8.3"},
			written: [][]driver.Value{{"off", int64(7)}}},
		{name: "a socket that cannot be found falls back to the pool path", body: `{"mode":"to_www"}`, status: http.StatusOK,
			fakes: func(f *wwwFakes) { f.socketErr = errScripted },
			steps: []string{"www resolves? example.com", "covers /etc/ssl/e.crt /etc/ssl/e.key www.example.com",
				"socket c_example 8.3", "vhost 7 /run/php-fpm/c_example.sock 8.3"},
			written: [][]driver.Value{{"to_www", int64(7)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakes := newWWWFakes(t)
			if tc.fakes != nil {
				tc.fakes(fakes)
			}
			script := wwwScript()
			recorder := serveSettings(t, script, wwwHandler, http.MethodPut, tc.body)
			assertOutcome(t, recorder, tc.status, "")
			assertSteps(t, &fakes.hostCalls, tc.steps...)
			assertExecArgs(t, script, "UPDATE domains SET www_redirect=?", tc.written...)
			assertExecArgs(t, script, "UPDATE domains SET www_redirect='off'")
		})
	}
}

// A failed render puts the stored value back to off.
func TestSetWWWRedirectRollsBackAFailedRender(t *testing.T) {
	fakes := newWWWFakes(t)
	fakes.vhostErr = errScripted
	script := wwwScript()
	recorder := serveSettings(t, script, wwwHandler, http.MethodPut, `{"mode":"to_apex"}`)
	assertOutcome(t, recorder, http.StatusInternalServerError, "virtual host update failed")
	assertExecArgs(t, script, "UPDATE domains SET www_redirect='off'", []driver.Value{int64(7)})
}

func TestBulkOwnerRefusesAnUnusableRequest(t *testing.T) {
	for _, tc := range []settingsCase{
		{name: "an unreadable body", body: `{`, status: http.StatusBadRequest, message: "invalid request body"},
		{name: "no domain ids", body: `{"ids":[],"customer_id":5}`, status: http.StatusBadRequest, message: "at least one domain ID is required"},
		{name: "a customer that does not exist", body: `{"ids":[1],"customer_id":5}`,
			status: http.StatusBadRequest, message: "customer not found"},
		{name: "an update that fails", body: `{"ids":[1],"customer_id":null}`,
			script: func(s *sqlScript) { s.fail["UPDATE domains d SET d.customer_id=?"] = errScripted },
			status: http.StatusInternalServerError, message: "bulk update failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := newScript()
			script.rows["SELECT COUNT(*) FROM customers WHERE id=?"] = [][]driver.Value{{int64(0)}}
			recorder := httptest.NewRecorder()
			(&Handlers{DB: scriptDB(t, applyScript(script, tc.script))}).BulkOwner(recorder, ownerRequest(adminActor, tc.body))
			assertOutcome(t, recorder, tc.status, tc.message)
		})
	}
}
