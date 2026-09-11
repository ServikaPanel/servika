package mail

import (
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"servika/internal/middleware"
)

const (
	planLimitsRead = "FROM domains d LEFT JOIN service_plans p ON p.id = d.plan_id"
	sendLimitsSave = "SET send_limit_hour=?,send_limit_day=?,send_limits_manual=?"
)

func sendLimitsScript() *sqlScript {
	s := handlerScript()
	s.rows[planLimitsRead] = [][]driver.Value{{int64(0), int64(100), int64(1000)}}
	return s
}

func putSendLimits(t *testing.T, s *sqlScript, role, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := mailRequest(http.MethodPut, "/domains/1/mail/2/send-limits", body, role,
		map[string]string{"id": "1", "mid": "2"})
	(&Handlers{DB: scriptDB(t, s)}).SendLimitsPut(recorder, request)
	return recorder
}

func noSetup(*sqlScript) {}

// Every refusal SendLimitsPut gives, with the status and the text a caller sees.
func TestSendLimitsPutRefusals(t *testing.T) {
	const bounds = "limits must be 0-100000; the hourly limit may not exceed the daily limit"
	const fine = `{"hour_limit":1,"day_limit":10}`
	cases := []struct {
		name, role, body string
		setup            func(*sqlScript)
		status           int
		text             string
	}{
		{"an unknown domain", middleware.RoleAdmin, fine, func(s *sqlScript) { s.rows[domainLookup] = nil }, http.StatusNotFound, "domain not found"},
		{"a body that is not JSON", middleware.RoleAdmin, `{`, noSetup, http.StatusBadRequest, bounds},
		{"a negative hourly limit", middleware.RoleAdmin, `{"hour_limit":-1,"day_limit":10}`, noSetup, http.StatusBadRequest, bounds},
		{"an hourly limit past the bound", middleware.RoleAdmin, `{"hour_limit":100001,"day_limit":0}`, noSetup, http.StatusBadRequest, bounds},
		{"a negative daily limit", middleware.RoleAdmin, `{"hour_limit":1,"day_limit":-1}`, noSetup, http.StatusBadRequest, bounds},
		{"a daily limit past the bound", middleware.RoleAdmin, `{"hour_limit":1,"day_limit":100001}`, noSetup, http.StatusBadRequest, bounds},
		{"an hourly limit above the daily one", middleware.RoleAdmin, `{"hour_limit":20,"day_limit":10}`, noSetup, http.StatusBadRequest, bounds},
		{"a mailbox of another domain", middleware.RoleAdmin, fine, func(s *sqlScript) { s.rows[mailboxOwned] = [][]driver.Value{{int64(0)}} }, http.StatusNotFound, "mailbox not found"},
		{"a plan that cannot be read", middleware.RoleUser, fine, func(s *sqlScript) { s.fail[planLimitsRead] = errScripted }, http.StatusInternalServerError, "could not read the plan's mail limits"},
		{"a customer above the plan", middleware.RoleUser, `{"hour_limit":200,"day_limit":500}`, noSetup, http.StatusForbidden, "the hourly send limit exceeds the plan's ceiling"},
		{"a save that fails", middleware.RoleAdmin, fine, func(s *sqlScript) { s.fail[sendLimitsSave] = errScripted }, http.StatusInternalServerError, "could not save send limits"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			script := sendLimitsScript()
			c.setup(script)
			assertAnswer(t, putSendLimits(t, script, c.role, c.body), c.status, c.text)
		})
	}
}

// An operator's value is marked as set by hand, so the next plan change keeps it;
// a customer's is not.
func TestSendLimitsPutMarksOnlyAnOperatorsValueAsManual(t *testing.T) {
	for role, manual := range map[string]int64{middleware.RoleAdmin: 1, middleware.RoleUser: 0} {
		t.Run(role, func(t *testing.T) {
			script := sendLimitsScript()
			assertAnswer(t, putSendLimits(t, script, role, `{"hour_limit":50,"day_limit":500}`), http.StatusOK, `"ok":true`)
			want := []driver.Value{int64(50), int64(500), manual, int64(2), int64(1)}
			if saved := script.onlyExec(t, sendLimitsSave); !slices.Equal(saved.args, want) {
				t.Fatalf("saved %#v, want %#v", saved.args, want)
			}
			if actions := auditActions(script); !slices.Equal(actions, []string{"mail.send_limits.update"}) {
				t.Fatalf("audit actions = %v", actions)
			}
		})
	}
}
