package mail

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"servika/internal/middleware"
)

// The refusals SetStatus gives before the containment guard is ever reached.
func TestSetStatusRefusalsBeforeTheGuard(t *testing.T) {
	cases := []struct {
		name, body string
		setup      func(*sqlScript)
		status     int
		text       string
	}{
		{"an unknown domain", `{"status":"active"}`, func(s *sqlScript) { s.rows[domainLookup] = nil }, http.StatusNotFound, "domain not found"},
		{"a body that is not JSON", `{`, noSetup, http.StatusBadRequest, "invalid status"},
		{"a status that does not exist", `{"status":"deleted"}`, noSetup, http.StatusBadRequest, "invalid status"},
		{"an update that fails", `{"status":"suspended"}`, func(s *sqlScript) { s.fail["UPDATE mailboxes SET status=?"] = errScripted }, http.StatusInternalServerError, "could not update mailbox"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			script := handlerScript()
			c.setup(script)
			recorder := httptest.NewRecorder()
			request := mailRequest(http.MethodPost, "/domains/1/mail/2/status", c.body, middleware.RoleAdmin,
				map[string]string{"id": "1", "mid": "2"})
			(&Handlers{DB: scriptDB(t, script)}).SetStatus(recorder, request)
			assertAnswer(t, recorder, c.status, c.text)
		})
	}
}
