package mail

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"

	"servika/internal/middleware"
)

const (
	forwardingClear = "DELETE FROM mail_forwarding WHERE mailbox_id=?"
	forwardingSave  = "INSERT INTO mail_forwarding (mailbox_id, destinations, keep_copy)"
	mailboxEmail    = "SELECT email FROM mailboxes WHERE id=?"
)

func forwardingScript() *sqlScript {
	s := withSieveAnswers(handlerScript())
	s.rows[mailboxEmail] = [][]driver.Value{{"info@example.com"}}
	return s
}

func putForwarding(t *testing.T, s *sqlScript, role, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := mailRequest(http.MethodPut, "/domains/1/mail/2/forwarding", body, role,
		map[string]string{"id": "1", "mid": "2"})
	(&Handlers{DB: scriptDB(t, s)}).ForwardingPut(recorder, request)
	return recorder
}

func quoteJSON(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func itoa(value int) string { return strconv.Itoa(value) }

// Every refusal ForwardingPut gives, with the status and the text or reason a
// caller sees.
func TestForwardingPutRefusals(t *testing.T) {
	const unsaved = "could not save the forwarding"
	const forward = `{"enabled":true,"destinations":["a@b.test"]}`
	cases := []struct {
		name, role, body string
		setup            func(*sqlScript)
		status           int
		text             string
	}{
		{"an unknown domain", middleware.RoleAdmin, forward, func(s *sqlScript) { s.rows[domainLookup] = nil }, http.StatusNotFound, "domain not found"},
		{"a caller without a session", "", forward, noSetup, http.StatusUnauthorized, "authorization required"},
		{"a mailbox of another domain", middleware.RoleAdmin, forward, func(s *sqlScript) { s.rows[mailboxOwned] = [][]driver.Value{{int64(0)}} }, http.StatusNotFound, "mailbox not found"},
		{"a body that is not JSON", middleware.RoleAdmin, `{`, noSetup, http.StatusBadRequest, "invalid request"},
		{"a clear that fails", middleware.RoleAdmin, `{"enabled":false}`, func(s *sqlScript) { s.fail[forwardingClear] = errScripted }, http.StatusInternalServerError, unsaved},
		{"an unusable destination", middleware.RoleAdmin, `{"enabled":true,"destinations":["not an address"]}`, noSetup, http.StatusBadRequest, `"reason":"invalid_destination"`},
		{"a mailbox address that cannot be read", middleware.RoleAdmin, forward, func(s *sqlScript) { s.fail[mailboxEmail] = errScripted }, http.StatusInternalServerError, unsaved},
		{"a forward to itself", middleware.RoleAdmin, `{"enabled":true,"destinations":["INFO@example.com"]}`, noSetup, http.StatusBadRequest, `"reason":"forwarding_loop"`},
		{"a save that fails", middleware.RoleAdmin, forward, func(s *sqlScript) { s.fail[forwardingSave] = errScripted }, http.StatusInternalServerError, unsaved},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withLookPath(t)
			script := forwardingScript()
			c.setup(script)
			assertAnswer(t, putForwarding(t, script, c.role, c.body), c.status, c.text)
		})
	}
}

// Turning forwarding off, or sending no destination, removes the row; the answer
// says the rules were not applied when the compiler is missing.
func TestForwardingPutClearsTheRow(t *testing.T) {
	withLookPath(t)
	script := forwardingScript()

	recorder := putForwarding(t, script, middleware.RoleAdmin, `{"enabled":true,"destinations":[]}`)
	assertAnswer(t, recorder, http.StatusOK, `"reason":"sieve_not_applied"`)
	if body := jsonBody(t, recorder); body["applied"] != false || body["enabled"] != false {
		t.Fatalf("answer = %v", body)
	}
	if clear := script.onlyExec(t, forwardingClear); !slices.Equal(clear.args, []driver.Value{int64(2)}) {
		t.Fatalf("cleared %#v", clear.args)
	}
	if actions := auditActions(script); !slices.Equal(actions, []string{"mail.forwarding.clear"}) {
		t.Fatalf("audit actions = %v", actions)
	}
}

// A usable list is normalised, saved, compiled and audited.
func TestForwardingPutSavesAndApplies(t *testing.T) {
	withLookPath(t, "sievec")
	capture := captureSieve(t, nil)
	script := forwardingScript()

	recorder := putForwarding(t, script, middleware.RoleAdmin,
		`{"enabled":true,"destinations":["A@b.test","c@d.test"],"keep_copy":true}`)
	assertAnswer(t, recorder, http.StatusOK, `"applied":true`)
	if body := jsonBody(t, recorder); body["keep_copy"] != true || len(body["destinations"].([]any)) != 2 {
		t.Fatalf("answer = %v", body)
	}
	want := []driver.Value{int64(2), "a@b.test,c@d.test", int64(1)}
	if save := script.onlyExec(t, forwardingSave); !slices.Equal(save.args, want) {
		t.Fatalf("saved %#v, want %#v", save.args, want)
	}
	if capture.calls != 1 || !slices.Equal(auditActions(script), []string{"mail.forwarding.set"}) {
		t.Fatalf("compiled %d times, audit %v", capture.calls, auditActions(script))
	}
}
