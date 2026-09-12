package users

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"servika/internal/auth"
	"servika/internal/middleware"
)

// The query fragments the scripted database answers.
const (
	resellerOfUser = "SELECT reseller_id FROM users WHERE id=?"
	adminCount     = "SELECT COUNT(*) FROM users WHERE role='admin'"
	roleOfUser     = "SELECT role FROM users WHERE id=?"
	scopeOfUser    = "SELECT role, reseller_id FROM users WHERE id=?"
	auditInsert    = "INSERT INTO audit_log"
)

// actorAdmin and actorReseller are the two callers these handlers distinguish.
func actorAdmin() *auth.Claims {
	return &auth.Claims{UserID: 1, Username: "admin", Role: middleware.RoleAdmin}
}

func actorReseller() *auth.Claims {
	return &auth.Claims{UserID: 9, Username: "reseller", Role: middleware.RoleReseller}
}

// userRequest builds a request whose chi route carries the target account id
// and whose context carries the caller.
func userRequest(method, body string, actor *auth.Claims, id string) *http.Request {
	r := httptest.NewRequest(method, "/users/"+id, strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", id)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routeCtx))
	if actor == nil {
		return r
	}
	return r.WithContext(auth.WithClaims(r.Context(), actor))
}

// userScript answers the reads every handler makes about the target account.
func userScript() *sqlScript {
	s := newScript()
	s.rows[resellerOfUser] = [][]driver.Value{{int64(9)}}
	s.rows[adminCount] = [][]driver.Value{{int64(3)}}
	s.rows[roleOfUser] = [][]driver.Value{{middleware.RoleReseller}}
	s.rows[scopeOfUser] = [][]driver.Value{{middleware.RoleUser, int64(9)}}
	return s
}

// handlersFor opens a scripted database for one test.
func handlersFor(t *testing.T, s *sqlScript) *Handlers {
	t.Helper()
	return &Handlers{DB: scriptDB(t, s)}
}

func assertResponse(t *testing.T, recorder *httptest.ResponseRecorder, status int, fragment string) {
	t.Helper()
	if recorder.Code != status {
		t.Errorf("status = %d, want %d (body %s)", recorder.Code, status, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), fragment) {
		t.Errorf("body = %s, want it to hold %q", recorder.Body.String(), fragment)
	}
}

// statementsMatching returns the arguments of every statement holding fragment.
func statementsMatching(s *sqlScript, fragment string) [][]driver.Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	var found [][]driver.Value
	for _, exec := range s.execs {
		if strings.Contains(exec.query, fragment) {
			found = append(found, exec.args)
		}
	}
	return found
}

// ranStatement reports whether any statement held fragment.
func ranStatement(s *sqlScript, fragment string) bool {
	return len(statementsMatching(s, fragment)) > 0
}

// noHostingCascade replaces the hosting cascade for one test and records what
// it was asked to do.
type cascadeCall struct {
	resellerID int64
	suspend    bool
}

func recordCascade(t *testing.T, err error) *[]cascadeCall {
	t.Helper()
	var calls []cascadeCall
	setForTest(t, &suspendResellerDomains,
		func(_ context.Context, _ *sql.DB, resellerID int64, suspend bool) (int, int, error) {
			calls = append(calls, cascadeCall{resellerID: resellerID, suspend: suspend})
			return 2, 1, err
		})
	return &calls
}

// ---------- Create ----------

func TestCreateRefusesARequestItCannotAct(t *testing.T) {
	const strong = `"password":"Str0ng-Passw0rd!"`
	refusals := []struct {
		name     string
		actor    *auth.Claims
		body     string
		status   int
		fragment string
	}{
		{"no session", nil, `{"username":"cust1",` + strong + `,"role":"user"}`,
			http.StatusUnauthorized, "no active session"},
		{"a body that is not JSON", actorAdmin(), "{", http.StatusBadRequest, "invalid request body"},
		{"a username starting with a digit", actorAdmin(), `{"username":"1abc",` + strong + `,"role":"user"}`,
			http.StatusBadRequest, "username: 3-32 chars"},
		{"a username of two characters", actorAdmin(), `{"username":"ab",` + strong + `,"role":"user"}`,
			http.StatusBadRequest, "username: 3-32 chars"},
		{"the reserved root name", actorAdmin(), `{"username":"root",` + strong + `,"role":"user"}`,
			http.StatusBadRequest, "this username is reserved"},
		{"a role the panel does not have", actorAdmin(), `{"username":"cust1",` + strong + `,"role":"superuser"}`,
			http.StatusBadRequest, "invalid role"},
		{"a reseller opening a second reseller", actorReseller(),
			`{"username":"cust1",` + strong + `,"role":"reseller"}`,
			http.StatusForbidden, "a reseller may only create customer accounts"},
		{"a customer opening an account", &auth.Claims{UserID: 4, Username: "c", Role: middleware.RoleUser},
			`{"username":"cust1",` + strong + `,"role":"user"}`,
			http.StatusForbidden, "insufficient permissions"},
		{"a password the policy refuses", actorAdmin(), `{"username":"cust1","password":"short","role":"user"}`,
			http.StatusBadRequest, "password"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			s := userScript()
			recorder := httptest.NewRecorder()
			handlersFor(t, s).Create(recorder, userRequest(http.MethodPost, tc.body, tc.actor, "0"))

			assertResponse(t, recorder, tc.status, tc.fragment)
			if ranStatement(s, "INSERT INTO users") {
				t.Error("a refused request still created the account")
			}
		})
	}
}

// The reseller customer quota is enforced on the path that creates a customer
// account, because that account is what the quota counts.
func TestCreateEnforcesTheResellerCustomerQuota(t *testing.T) {
	s := userScript()
	s.rows["SELECT max_customer"] = [][]driver.Value{{int64(2)}}
	s.rows["SELECT COUNT(*) FROM customers WHERE owner_user_id=?"] = [][]driver.Value{{int64(2)}}
	recorder := httptest.NewRecorder()

	handlersFor(t, s).Create(recorder, userRequest(http.MethodPost,
		`{"username":"cust1","password":"Str0ng-Passw0rd!","role":"user"}`, actorReseller(), "0"))

	assertResponse(t, recorder, http.StatusForbidden, "at most 2 customers")
	if ranStatement(s, "INSERT INTO users") {
		t.Error("the account was created past the reseller quota")
	}
}

// A quota read that fails must not open the gate.
func TestCreateRefusesAResellerQuotaItCouldNotRead(t *testing.T) {
	s := userScript()
	s.fail["SELECT max_customer"] = errors.New("read failed")
	recorder := httptest.NewRecorder()

	handlersFor(t, s).Create(recorder, userRequest(http.MethodPost,
		`{"username":"cust1","password":"Str0ng-Passw0rd!","role":"user"}`, actorReseller(), "0"))

	assertResponse(t, recorder, http.StatusInternalServerError, "could not verify reseller limit")
	if ranStatement(s, "INSERT INTO users") {
		t.Error("the account was created without a quota decision")
	}
}

func TestCreateReportsAUsernameAlreadyTaken(t *testing.T) {
	s := userScript()
	s.fail["INSERT INTO users"] = errors.New("Error 1062: Duplicate entry 'cust1' for key 'username'")
	recorder := httptest.NewRecorder()

	handlersFor(t, s).Create(recorder, userRequest(http.MethodPost,
		`{"username":"cust1","password":"Str0ng-Passw0rd!","role":"user"}`, actorAdmin(), "0"))

	assertResponse(t, recorder, http.StatusConflict, "this username is already in use")
}

func TestCreateReportsAnAccountItCouldNotWrite(t *testing.T) {
	s := userScript()
	s.fail["INSERT INTO users"] = errors.New("connection lost")
	recorder := httptest.NewRecorder()

	handlersFor(t, s).Create(recorder, userRequest(http.MethodPost,
		`{"username":"cust1","password":"Str0ng-Passw0rd!","role":"user"}`, actorAdmin(), "0"))

	assertResponse(t, recorder, http.StatusInternalServerError, "could not create account")
}

// A customers row that cannot be written is logged, not reported: the login
// already exists.
func TestCreateStillReportsSuccessWhenTheCustomerRowFails(t *testing.T) {
	s := userScript()
	s.fail["INSERT INTO customers"] = errors.New("table is full")
	recorder := httptest.NewRecorder()

	handlersFor(t, s).Create(recorder, userRequest(http.MethodPost,
		`{"username":"cust1","password":"Str0ng-Passw0rd!","role":"user"}`, actorAdmin(), "0"))

	assertResponse(t, recorder, http.StatusCreated, `"id":`)
}

// The display name of an auto-created customer falls back to the username.
func TestCreateNamesTheCustomerAfterTheAccountWhenNoNameIsGiven(t *testing.T) {
	s := userScript()
	recorder := httptest.NewRecorder()

	handlersFor(t, s).Create(recorder, userRequest(http.MethodPost,
		`{"username":"cust1","password":"Str0ng-Passw0rd!","role":"user","email":" a@b.co "}`, actorAdmin(), "0"))

	assertResponse(t, recorder, http.StatusCreated, `"id":`)
	rows := statementsMatching(s, "INSERT INTO customers")
	if len(rows) != 1 {
		t.Fatalf("customers INSERT ran %d times, want once", len(rows))
	}
	if rows[0][0] != "cust1" || rows[0][1] != "a@b.co" {
		t.Errorf("customers row = %v, want the username as the name and the trimmed address", rows[0])
	}
}

// ---------- Update ----------

func TestUpdateRefusesARequestItCannotAct(t *testing.T) {
	refusals := []struct {
		name     string
		actor    *auth.Claims
		id       string
		body     string
		status   int
		fragment string
	}{
		{"no session", nil, "7", `{"email":"a@b.co"}`, http.StatusForbidden, "insufficient permissions"},
		{"a body that is not JSON", actorAdmin(), "7", "{", http.StatusBadRequest, "invalid request body"},
		{"the root role", actorAdmin(), "1", `{"role":"user"}`, http.StatusForbidden,
			"the root account's role cannot be changed"},
		{"a reseller changing a role", actorReseller(), "7", `{"role":"user"}`, http.StatusForbidden,
			"only an administrator may change roles"},
		{"a role the panel does not have", actorAdmin(), "7", `{"role":"superuser"}`,
			http.StatusBadRequest, "invalid role"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			s := userScript()
			recorder := httptest.NewRecorder()
			handlersFor(t, s).Update(recorder, userRequest(http.MethodPut, tc.body, tc.actor, tc.id))

			assertResponse(t, recorder, tc.status, tc.fragment)
			if ranStatement(s, "UPDATE users SET") {
				t.Error("a refused request still wrote the account")
			}
		})
	}
}

// A reseller may only act on the accounts bound to it.
func TestUpdateRefusesAnAccountOutsideTheResellersOwnList(t *testing.T) {
	s := userScript()
	s.rows[resellerOfUser] = [][]driver.Value{{int64(4)}}
	recorder := httptest.NewRecorder()

	handlersFor(t, s).Update(recorder, userRequest(http.MethodPut, `{"email":"a@b.co"}`, actorReseller(), "7"))

	assertResponse(t, recorder, http.StatusForbidden, "insufficient permissions")
}

func TestUpdateKeepsTheLastAdministratorInItsRole(t *testing.T) {
	cases := []struct {
		name string
		rows [][]driver.Value
		fail error
	}{
		{"no other active administrator", [][]driver.Value{{int64(0)}}, nil},
		{"the count could not be read", nil, errors.New("read failed")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := userScript()
			if tc.fail != nil {
				s.fail[adminCount] = tc.fail
			} else {
				s.rows[adminCount] = tc.rows
			}
			recorder := httptest.NewRecorder()

			handlersFor(t, s).Update(recorder, userRequest(http.MethodPut, `{"role":"user"}`, actorAdmin(), "7"))

			assertResponse(t, recorder, http.StatusForbidden, "the last administrator account cannot be changed")
			if ranStatement(s, "UPDATE users SET role=") {
				t.Error("the last administrator was demoted")
			}
		})
	}
}

// A role change revokes every session the old role issued.
func TestUpdateWritesOnlyTheFieldsItWasGiven(t *testing.T) {
	s := userScript()
	recorder := httptest.NewRecorder()

	handlersFor(t, s).Update(recorder, userRequest(http.MethodPut,
		`{"email":" a@b.co ","full_name":" Full Name ","role":"reseller"}`, actorAdmin(), "7"))

	assertResponse(t, recorder, http.StatusOK, `"ok":true`)
	email := statementsMatching(s, "UPDATE users SET email=")
	if len(email) != 1 || email[0][0] != "a@b.co" || email[0][1] != int64(7) {
		t.Errorf("email update = %v, want the trimmed address bound to the account", email)
	}
	name := statementsMatching(s, "UPDATE users SET full_name=")
	if len(name) != 1 || name[0][0] != "Full Name" {
		t.Errorf("full name update = %v, want the trimmed name", name)
	}
	role := statementsMatching(s, "UPDATE users SET role=")
	if len(role) != 1 || role[0][0] != middleware.RoleReseller {
		t.Errorf("role update = %v, want the new role", role)
	}
	if !strings.Contains(strings.Join(queriesOf(s), " "), "token_version=token_version+1") {
		t.Error("a role change did not revoke the sessions the old role issued")
	}
}

func TestUpdateTouchesNothingWhenTheBodyNamesNoField(t *testing.T) {
	s := userScript()
	recorder := httptest.NewRecorder()

	handlersFor(t, s).Update(recorder, userRequest(http.MethodPut, `{}`, actorAdmin(), "7"))

	assertResponse(t, recorder, http.StatusOK, `"ok":true`)
	if ranStatement(s, "UPDATE users SET") {
		t.Error("an empty request wrote the account")
	}
	if !ranStatement(s, auditInsert) {
		t.Error("the change was not audited")
	}
}

func TestUpdateReportsAFieldItCouldNotWrite(t *testing.T) {
	fields := []struct {
		name     string
		body     string
		fragment string
	}{
		{"the address", `{"email":"a@b.co"}`, "UPDATE users SET email="},
		{"the full name", `{"full_name":"Name"}`, "UPDATE users SET full_name="},
		{"the role", `{"role":"user"}`, "UPDATE users SET role="},
	}
	for _, tc := range fields {
		t.Run(tc.name, func(t *testing.T) {
			s := userScript()
			s.fail[tc.fragment] = errors.New("write failed")
			recorder := httptest.NewRecorder()

			handlersFor(t, s).Update(recorder, userRequest(http.MethodPut, tc.body, actorAdmin(), "7"))

			assertResponse(t, recorder, http.StatusInternalServerError, "could not update")
			if ranStatement(s, auditInsert) {
				t.Error("a failed update was audited as done")
			}
		})
	}
}

// ---------- SetStatus ----------

func TestSetStatusRefusesARequestItCannotAct(t *testing.T) {
	refusals := []struct {
		name     string
		actor    *auth.Claims
		id       string
		body     string
		status   int
		fragment string
	}{
		{"no session", nil, "7", `{"status":"suspended"}`, http.StatusForbidden, "insufficient permissions"},
		{"the root account", actorAdmin(), "1", `{"status":"suspended"}`, http.StatusForbidden,
			"the root account cannot be suspended"},
		{"the caller's own account", actorAdmin(), "1000", `{"status":"suspended"}`, http.StatusForbidden,
			"you cannot suspend your own account"},
		{"a body that is not JSON", actorAdmin(), "7", "{", http.StatusBadRequest,
			"status must be 'active' or 'suspended'"},
		{"a status the panel does not have", actorAdmin(), "7", `{"status":"paused"}`, http.StatusBadRequest,
			"status must be 'active' or 'suspended'"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			actor := tc.actor
			if tc.id == "1000" {
				actor = &auth.Claims{UserID: 1000, Username: "admin2", Role: middleware.RoleAdmin}
			}
			s := userScript()
			recordCascade(t, nil)
			recorder := httptest.NewRecorder()
			handlersFor(t, s).SetStatus(recorder, userRequest(http.MethodPost, tc.body, actor, tc.id))

			assertResponse(t, recorder, tc.status, tc.fragment)
			if ranStatement(s, "UPDATE users SET status=") {
				t.Error("a refused request still changed the status")
			}
		})
	}
}

func TestSetStatusKeepsTheLastAdministratorActive(t *testing.T) {
	s := userScript()
	s.rows[adminCount] = [][]driver.Value{{int64(0)}}
	recordCascade(t, nil)
	recorder := httptest.NewRecorder()

	handlersFor(t, s).SetStatus(recorder, userRequest(http.MethodPost, `{"status":"suspended"}`, actorAdmin(), "7"))

	assertResponse(t, recorder, http.StatusForbidden, "the last administrator cannot be suspended")
}

func TestSetStatusSuspendsTheAccountItsSubAccountsAndItsHosting(t *testing.T) {
	s := userScript()
	calls := recordCascade(t, nil)
	recorder := httptest.NewRecorder()

	handlersFor(t, s).SetStatus(recorder, userRequest(http.MethodPost, `{"status":"suspended"}`, actorAdmin(), "7"))

	assertResponse(t, recorder, http.StatusOK, `"ok":true`)
	primary := statementsMatching(s, "UPDATE users SET status=")
	if len(primary) != 1 || primary[0][0] != "suspended" || primary[0][1] != int64(7) {
		t.Errorf("status update = %v, want the new status bound to the account", primary)
	}
	if !ranStatement(s, "suspended_by_reseller = IF(status='suspended'") {
		t.Error("the sub-account cascade did not run")
	}
	if len(*calls) != 1 || (*calls)[0] != (cascadeCall{resellerID: 7, suspend: true}) {
		t.Errorf("hosting cascade = %v, want one suspend for account 7", *calls)
	}
}

func TestSetStatusResumesWithTheCascadeThatOnlyOpensWhatItClosed(t *testing.T) {
	s := userScript()
	calls := recordCascade(t, nil)
	recorder := httptest.NewRecorder()

	handlersFor(t, s).SetStatus(recorder, userRequest(http.MethodPost, `{"status":"active"}`, actorAdmin(), "7"))

	assertResponse(t, recorder, http.StatusOK, `"ok":true`)
	if !ranStatement(s, "COALESCE(suspended_by_reseller,0)=1") {
		t.Error("the resume cascade did not run, or was not narrowed to the rows it closed")
	}
	if len(*calls) != 1 || (*calls)[0].suspend {
		t.Errorf("hosting cascade = %v, want one resume", *calls)
	}
}

// The status change already succeeded, so neither cascade may turn the answer
// into a failure.
func TestSetStatusReportsSuccessWhenACascadeFails(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*sqlScript) error
	}{
		{"the sub-account cascade fails", func(s *sqlScript) error {
			s.fail["suspended_by_reseller = IF(status='suspended'"] = errors.New("write failed")
			return nil
		}},
		{"the hosting cascade fails", func(*sqlScript) error { return errors.New("nginx reload failed") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := userScript()
			recordCascade(t, tc.setup(s))
			recorder := httptest.NewRecorder()

			handlersFor(t, s).SetStatus(recorder, userRequest(http.MethodPost,
				`{"status":"suspended"}`, actorAdmin(), "7"))

			assertResponse(t, recorder, http.StatusOK, `"ok":true`)
		})
	}
}

func TestSetStatusReportsAStatusItCouldNotWrite(t *testing.T) {
	s := userScript()
	s.fail["UPDATE users SET status=?"] = errors.New("write failed")
	recordCascade(t, nil)
	recorder := httptest.NewRecorder()

	handlersFor(t, s).SetStatus(recorder, userRequest(http.MethodPost, `{"status":"suspended"}`, actorAdmin(), "7"))

	assertResponse(t, recorder, http.StatusInternalServerError, "could not change status")
	if ranStatement(s, auditInsert) {
		t.Error("a failed status change was audited as done")
	}
}

// ---------- SaveLimits ----------

func TestSaveLimitsRefusesARequestItCannotAct(t *testing.T) {
	refusals := []struct {
		name     string
		role     string
		readFail bool
		body     string
		status   int
		fragment string
	}{
		{"an account that does not exist", "", true, `{"max_customer":1}`, http.StatusNotFound, "account not found"},
		{"an account that is not a reseller", middleware.RoleUser, false, `{"max_customer":1}`,
			http.StatusBadRequest, "limits can only be defined for reseller accounts"},
		{"a body that is not JSON", middleware.RoleReseller, false, "{", http.StatusBadRequest, "invalid request body"},
		{"a negative limit", middleware.RoleReseller, false, `{"max_domain":-1}`, http.StatusBadRequest,
			"limits cannot be negative"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			s := userScript()
			if tc.readFail {
				s.fail[roleOfUser] = errors.New("no such row")
			} else {
				s.rows[roleOfUser] = [][]driver.Value{{tc.role}}
			}
			recorder := httptest.NewRecorder()

			handlersFor(t, s).SaveLimits(recorder, userRequest(http.MethodPut, tc.body, actorAdmin(), "7"))

			assertResponse(t, recorder, tc.status, tc.fragment)
			if ranStatement(s, "reseller_limits") {
				t.Error("a refused request still touched the limit row")
			}
		})
	}
}

// Unlimited has one representation: no row.
func TestSaveLimitsRemovesTheRowWhenEveryLimitIsZero(t *testing.T) {
	s := userScript()
	recorder := httptest.NewRecorder()

	handlersFor(t, s).SaveLimits(recorder, userRequest(http.MethodPut,
		`{"max_customer":0,"max_domain":0,"disk_quota_mb":0,"traffic_quota_mb":0}`, actorAdmin(), "7"))

	assertResponse(t, recorder, http.StatusOK, `"ok":true`)
	if !ranStatement(s, "DELETE FROM reseller_limits") {
		t.Error("the row was kept, so unlimited has two representations")
	}
	if ranStatement(s, "INSERT INTO reseller_limits") {
		t.Error("a zero-valued row was written")
	}
}

func TestSaveLimitsWritesTheRowItWasGiven(t *testing.T) {
	s := userScript()
	recorder := httptest.NewRecorder()

	handlersFor(t, s).SaveLimits(recorder, userRequest(http.MethodPut,
		`{"max_customer":5,"max_domain":10,"disk_quota_mb":2048,"traffic_quota_mb":4096}`, actorAdmin(), "7"))

	assertResponse(t, recorder, http.StatusOK, `"ok":true`)
	rows := statementsMatching(s, "INSERT INTO reseller_limits")
	if len(rows) != 1 {
		t.Fatalf("the limit row was written %d times, want once", len(rows))
	}
	want := []driver.Value{int64(7), int64(5), int64(10), int64(2048), int64(4096)}
	for i, value := range want {
		if rows[0][i] != value {
			t.Errorf("limit argument %d = %v, want %v", i, rows[0][i], value)
		}
	}
}

func TestSaveLimitsReportsARowItCouldNotWrite(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		fragment string
		message  string
	}{
		{"the removal fails", `{"max_customer":0,"max_domain":0}`, "DELETE FROM reseller_limits",
			"could not remove limits"},
		{"the write fails", `{"max_customer":5}`, "INSERT INTO reseller_limits", "could not save limits"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := userScript()
			s.fail[tc.fragment] = errors.New("write failed")
			recorder := httptest.NewRecorder()

			handlersFor(t, s).SaveLimits(recorder, userRequest(http.MethodPut, tc.body, actorAdmin(), "7"))

			assertResponse(t, recorder, http.StatusInternalServerError, tc.message)
		})
	}
}

// ---------- Delete ----------

func TestDeleteRefusesARequestItCannotAct(t *testing.T) {
	refusals := []struct {
		name     string
		actor    *auth.Claims
		id       string
		status   int
		fragment string
	}{
		{"no session", nil, "7", http.StatusForbidden, "insufficient permissions"},
		{"the root account", actorAdmin(), "1", http.StatusForbidden, "the root account cannot be deleted"},
		{"the caller's own account", actorAdmin(), "1000", http.StatusForbidden, "you cannot delete your own account"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			actor := tc.actor
			if tc.id == "1000" {
				actor = &auth.Claims{UserID: 1000, Username: "admin2", Role: middleware.RoleAdmin}
			}
			s := userScript()
			recorder := httptest.NewRecorder()
			handlersFor(t, s).Delete(recorder, userRequest(http.MethodDelete, "", actor, tc.id))

			assertResponse(t, recorder, tc.status, tc.fragment)
			if ranStatement(s, "DELETE FROM users") {
				t.Error("a refused request still deleted the account")
			}
		})
	}
}

func TestDeleteKeepsTheLastAdministrator(t *testing.T) {
	s := userScript()
	s.rows[adminCount] = [][]driver.Value{{int64(0)}}
	recorder := httptest.NewRecorder()

	handlersFor(t, s).Delete(recorder, userRequest(http.MethodDelete, "", actorAdmin(), "7"))

	assertResponse(t, recorder, http.StatusForbidden, "the last administrator cannot be deleted")
	if ranStatement(s, "DELETE FROM users") {
		t.Error("the last administrator was deleted")
	}
}

// Deleting a reseller keeps its accounts and cuts the link, so no data is lost.
func TestDeleteCutsTheLinkBeforeItRemovesTheAccount(t *testing.T) {
	s := userScript()
	recorder := httptest.NewRecorder()

	handlersFor(t, s).Delete(recorder, userRequest(http.MethodDelete, "", actorAdmin(), "7"))

	assertResponse(t, recorder, http.StatusOK, `"ok":true`)
	order := queriesOf(s)
	reassign, deletion := indexOfQuery(order, "SET reseller_id=NULL"), indexOfQuery(order, "DELETE FROM users")
	if reassign < 0 || deletion < 0 || reassign > deletion {
		t.Fatalf("the link was not cut before the deletion: %v", order)
	}
	if !ranStatement(s, "UPDATE audit_log SET reseller_id=0") {
		t.Error("the deleted account's audit scope was left for a future account with the same id")
	}
}

func TestDeleteReportsAStepItCouldNotFinish(t *testing.T) {
	cases := []struct {
		name     string
		fragment string
		message  string
	}{
		{"the linked accounts cannot be reassigned", "SET reseller_id=NULL", "could not reassign linked accounts"},
		{"the account cannot be removed", "DELETE FROM users", "could not delete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := userScript()
			s.fail[tc.fragment] = errors.New("write failed")
			recorder := httptest.NewRecorder()

			handlersFor(t, s).Delete(recorder, userRequest(http.MethodDelete, "", actorAdmin(), "7"))

			assertResponse(t, recorder, http.StatusInternalServerError, tc.message)
			if ranStatement(s, auditInsert) {
				t.Error("a failed deletion was audited as done")
			}
		})
	}
}

// An audit scope cleanup that fails is logged, not reported: the account is
// already gone.
func TestDeleteReportsSuccessWhenTheScopeCleanupFails(t *testing.T) {
	s := userScript()
	s.fail["UPDATE audit_log SET reseller_id=0"] = errors.New("write failed")
	recorder := httptest.NewRecorder()

	handlersFor(t, s).Delete(recorder, userRequest(http.MethodDelete, "", actorAdmin(), "7"))

	assertResponse(t, recorder, http.StatusOK, `"ok":true`)
}

// queriesOf returns every statement the script saw, in order.
func queriesOf(s *sqlScript) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.steps...)
}

// indexOfQuery returns where a statement holding fragment first ran.
func indexOfQuery(queries []string, fragment string) int {
	for i, query := range queries {
		if strings.Contains(query, fragment) {
			return i
		}
	}
	return -1
}
