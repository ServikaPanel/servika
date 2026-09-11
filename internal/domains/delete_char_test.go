package domains

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// deleteFakes stands in for everything Delete reaches outside its database.
type deleteFakes struct {
	hostCalls
	addonErr       error
	childErr       error
	pageErr        error
	siblings       []int64
	siblingErr     error
	dropErr        error
	deprovisionErr error
	sliceErr       error
	storeErr       error
	forgetErr      error
	closeErr       error
	renderErr      error
	zoneErr        error
}

func newDeleteFakes(t *testing.T) *deleteFakes {
	t.Helper()
	f := &deleteFakes{}
	setForTest(t, &cleanupAddonDomain, f.cleanup)
	setForTest(t, &teardownApps, f.apps)
	setForTest(t, &teardownLaravel, f.laravel)
	setForTest(t, &removeMaintenancePage, f.page)
	setForTest(t, &otherTopLevelDomainsUsing, f.others)
	setForTest(t, &mysqlDropAllForDomain, f.drop)
	setForTest(t, &deprovisionTenant, f.deprovision)
	setForTest(t, &deleteSystemdSlice, f.slice)
	setForTest(t, &removeQuarantineStore, f.store)
	setForTest(t, &forgetRedisDomain, f.forget)
	setForTest(t, &closeRedisDomain, f.closeRedis)
	setForTest(t, &cleanupMailDomain, f.mail)
	setForTest(t, &rerenderVhost, f.render)
	setForTest(t, &deleteDNSZone, f.zone)
	return f
}

// cleanup answers for the domain under test (7) as an addon, and for any other
// id as one of its children.
func (f *deleteFakes) cleanup(_ context.Context, _ *sql.DB, id int64) (string, error) {
	f.record("addon cleanup %d", id)
	if id == 7 {
		return "addon.example", f.addonErr
	}
	return "child.example", f.childErr
}

func (f *deleteFakes) apps(_ context.Context, _ *sql.DB, id int64)    { f.record("apps %d", id) }
func (f *deleteFakes) laravel(_ context.Context, _ *sql.DB, id int64) { f.record("laravel %d", id) }

func (f *deleteFakes) page(id int64) error {
	f.record("maintenance page %d", id)
	return f.pageErr
}

func (f *deleteFakes) others(systemUser, name string) ([]int64, error) {
	f.record("others %s %s", systemUser, name)
	return f.siblings, f.siblingErr
}

func (f *deleteFakes) drop(_ *sql.DB, id int64) error {
	f.record("mysql drop %d", id)
	return f.dropErr
}

func (f *deleteFakes) deprovision(name, systemUser string) error {
	f.record("deprovision %s %s", name, systemUser)
	return f.deprovisionErr
}

func (f *deleteFakes) slice(systemUser string) error {
	f.record("slice %s", systemUser)
	return f.sliceErr
}

func (f *deleteFakes) store(systemUser string) error {
	f.record("quarantine store %s", systemUser)
	return f.storeErr
}

func (f *deleteFakes) forget(_ *sql.DB, id int64) error {
	f.record("redis forget %d", id)
	return f.forgetErr
}

func (f *deleteFakes) closeRedis(_ *sql.DB, id int64, systemUser string) error {
	f.record("redis close %d %s", id, systemUser)
	return f.closeErr
}

func (f *deleteFakes) mail(_ *sql.DB, id int64, systemUser string) {
	f.record("mail %d %s", id, systemUser)
}

func (f *deleteFakes) render(_ *sql.DB, id int64) error {
	f.record("render %d", id)
	return f.renderErr
}

func (f *deleteFakes) zone(_ context.Context, _ *sql.DB, name string) error {
	f.record("dns delete %s", name)
	return f.zoneErr
}

type deleteCase struct {
	name    string
	script  func(*sqlScript)
	fakes   func(*deleteFakes)
	status  int
	message string
	steps   []string
}

// deleteScript answers for a top-level domain 7 with no addon children.
func deleteScript() *sqlScript {
	s := newScript()
	s.rows["SELECT domain_name, system_user, parent_domain_id FROM domains WHERE id=?"] = [][]driver.Value{{"example.com", "c_example", nil}}
	s.rows["SELECT id FROM domains WHERE parent_domain_id=?"] = nil
	return s
}

func runDelete(t *testing.T, tc deleteCase) (*httptest.ResponseRecorder, *sqlScript, *deleteFakes) {
	t.Helper()
	script := deleteScript()
	fakes := newDeleteFakes(t)
	if tc.script != nil {
		tc.script(script)
	}
	if tc.fakes != nil {
		tc.fakes(fakes)
	}
	recorder := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, script)}).Delete(recorder, requestWithParams(http.MethodDelete, "", map[string]string{"id": "7"}))
	return recorder, script, fakes
}

// joinSteps concatenates step lists into a new slice.
func joinSteps(parts ...[]string) []string {
	var out []string
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

var (
	deleteTeardown = []string{"apps 7", "laravel 7", "maintenance page 7", "others c_example example.com",
		"mysql drop 7", "deprovision example.com c_example"}
	deleteOwnUser    = []string{"slice c_example", "quarantine store c_example", "redis close 7 c_example", "mail 7 c_example"}
	deleteSharedUser = []string{"redis forget 7", "mail 7 c_example"}
)

func TestDeleteTearsTheTenantDown(t *testing.T) {
	cases := []deleteCase{
		{name: "a domain that does not exist",
			script: func(s *sqlScript) {
				s.rows["SELECT domain_name, system_user, parent_domain_id FROM domains WHERE id=?"] = nil
			},
			status: http.StatusNotFound, message: "domain not found"},
		{name: "a domain that cannot be read",
			script: func(s *sqlScript) {
				s.fail["SELECT domain_name, system_user, parent_domain_id FROM domains WHERE id=?"] = errScripted
			},
			status: http.StatusInternalServerError, message: "database read failed"},
		{name: "an addon whose cleanup fails",
			script: addonDomainRow, fakes: func(f *deleteFakes) { f.addonErr = errScripted },
			status: http.StatusInternalServerError, message: "addon domain deletion failed", steps: []string{"addon cleanup 7"}},
		{name: "an addon", script: addonDomainRow,
			status: http.StatusOK, steps: []string{"addon cleanup 7"}},
		{name: "a domain with an addon child",
			script: func(s *sqlScript) {
				s.rows["SELECT id FROM domains WHERE parent_domain_id=?"] = [][]driver.Value{{int64(8)}}
			},
			status: http.StatusOK,
			steps:  joinSteps([]string{"addon cleanup 8"}, deleteTeardown, deleteOwnUser, []string{"dns delete example.com"})},
		{name: "children that cannot all be read or cleaned",
			script: func(s *sqlScript) {
				s.rows["SELECT id FROM domains WHERE parent_domain_id=?"] = [][]driver.Value{{"not an id"}, {int64(8)}}
				s.endWith["SELECT id FROM domains WHERE parent_domain_id=?"] = errScripted
			},
			fakes:  func(f *deleteFakes) { f.childErr = errScripted },
			status: http.StatusOK,
			steps:  joinSteps([]string{"addon cleanup 8"}, deleteTeardown, deleteOwnUser, []string{"dns delete example.com"})},
		{name: "a child list that cannot be queried and teardowns that all fail",
			script: func(s *sqlScript) {
				s.fail["SELECT id FROM domains WHERE parent_domain_id=?"] = errScripted
				s.fail["DELETE FROM domain_traffic WHERE"] = errScripted
				s.fail["DELETE FROM domain_traffic_cursor"] = errScripted
				s.fail["DELETE FROM protected_directories"] = errScripted
				s.fail["DELETE FROM av_findings"] = errScripted
				s.fail["DELETE FROM av_scans"] = errScripted
				s.fail["DELETE FROM subdomains"] = errScripted
			},
			fakes: func(f *deleteFakes) {
				f.pageErr, f.dropErr, f.deprovisionErr = errScripted, errScripted, errScripted
				f.sliceErr, f.storeErr, f.closeErr, f.zoneErr = errScripted, errScripted, errScripted, errScripted
			},
			status: http.StatusOK,
			steps:  joinSteps(deleteTeardown, deleteOwnUser, []string{"dns delete example.com"})},
		{name: "a sibling lookup that fails counts as shared",
			fakes:  func(f *deleteFakes) { f.siblingErr, f.forgetErr = errScripted, errScripted },
			status: http.StatusOK,
			steps:  joinSteps(deleteTeardown, deleteSharedUser, []string{"dns delete example.com"})},
		{name: "a shared system user re-renders the survivors",
			fakes:  func(f *deleteFakes) { f.siblings, f.renderErr = []int64{9, 10}, errScripted },
			status: http.StatusOK,
			steps:  joinSteps(deleteTeardown, deleteSharedUser, []string{"render 9", "render 10", "dns delete example.com"})},
		{name: "a row that cannot be deleted",
			script: func(s *sqlScript) { s.fail["DELETE FROM domains WHERE id=?"] = errScripted },
			fakes:  func(f *deleteFakes) { f.siblings = []int64{9} },
			status: http.StatusInternalServerError, message: "domain deletion failed",
			steps: joinSteps(deleteTeardown, deleteSharedUser)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder, _, fakes := runDelete(t, tc)
			assertOutcome(t, recorder, tc.status, tc.message)
			assertSteps(t, &fakes.hostCalls, tc.steps...)
		})
	}
}

// addonDomainRow makes domain 7 an addon of domain 1.
func addonDomainRow(s *sqlScript) {
	s.rows["SELECT domain_name, system_user, parent_domain_id FROM domains WHERE id=?"] = [][]driver.Value{{"addon.example", "c_example", int64(1)}}
}

// The rows removed by hand go in a fixed order, each bound to the domain id,
// and the answer names what was deleted.
func TestDeleteRemovesTheRowsWithNoCascade(t *testing.T) {
	recorder, script, _ := runDelete(t, deleteCase{})
	assertOutcome(t, recorder, http.StatusOK, "")
	assertDeleteStatements(t, script)
	assertDeletedAnswer(t, recorder)
}

// assertDeleteStatements checks the statements Delete ran, in order, each bound
// to the domain id alone.
func assertDeleteStatements(t *testing.T, script *sqlScript) {
	t.Helper()
	var steps []string
	for _, statement := range script.execs {
		steps = append(steps, statement.query)
		if len(statement.args) != 1 || statement.args[0] != int64(7) {
			t.Errorf("%q ran with %v, want the domain id alone", statement.query, statement.args)
		}
	}
	want := []string{
		"DELETE FROM domain_traffic WHERE domain_id=?",
		"DELETE FROM domain_traffic_cursor WHERE domain_id=?",
		"DELETE FROM protected_directories WHERE domain_id=?",
		"DELETE FROM av_findings WHERE domain_id=?",
		"DELETE FROM av_scans WHERE domain_id=?",
		"DELETE FROM subdomains WHERE domain_id=?",
		"DELETE FROM domains WHERE id=?",
	}
	if !reflect.DeepEqual(steps, want) {
		t.Errorf("statements =\n%q\nwant\n%q", steps, want)
	}
}

// assertDeletedAnswer checks that the answer names the deleted domain.
func assertDeletedAnswer(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	var body struct {
		OK      bool              `json:"ok"`
		Deleted map[string]string `json:"deleted"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.OK || body.Deleted["domain_name"] != "example.com" || body.Deleted["system_user"] != "c_example" {
		t.Errorf("body = %+v", body)
	}
}

// An addon answers with the name its own cleanup reports.
func TestDeletingAnAddonAnswersWithItsCleanedName(t *testing.T) {
	recorder, script, _ := runDelete(t, deleteCase{script: addonDomainRow})
	assertOutcome(t, recorder, http.StatusOK, "")
	if len(script.execs) != 0 {
		t.Errorf("the addon path ran statements of its own: %v", script.execs)
	}
	if got := recorder.Body.String(); got != `{"deleted":{"domain_name":"addon.example","system_user":"c_example"},"ok":true}`+"\n" {
		t.Errorf("body = %s", got)
	}
}
