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
	aliasDomainRead = "SELECT domain_name FROM mail_domains WHERE domain_id=? AND status='active'"
	aliasInsert     = "INSERT INTO mail_aliases(domain_id, source, destination)"
)

func aliasScript() *sqlScript {
	s := handlerScript()
	s.rows[aliasDomainRead] = [][]driver.Value{{"example.com"}}
	s.insertID = 9
	return s
}

func createAlias(t *testing.T, s *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := mailRequest(http.MethodPost, "/domains/1/mail/aliases", body, middleware.RoleUser,
		map[string]string{"id": "1"})
	(&Handlers{DB: scriptDB(t, s)}).CreateAlias(recorder, request)
	return recorder
}

// Every refusal CreateAlias gives, with the status and the text a caller sees.
func TestCreateAliasRefusals(t *testing.T) {
	const fine = `{"local_part":"info","destination":"a@b.test"}`
	cases := []struct {
		name, body string
		setup      func(*sqlScript)
		status     int
		text       string
	}{
		{"an unknown domain", fine, func(s *sqlScript) { s.rows[domainLookup] = nil }, http.StatusNotFound, "domain not found"},
		{"a body that is not JSON", `{`, noSetup, http.StatusBadRequest, "invalid request body"},
		{"a domain without mail", fine, func(s *sqlScript) { s.rows[aliasDomainRead] = nil }, http.StatusBadRequest, "enable mail for this domain first"},
		{"a mail domain that cannot be read", fine, func(s *sqlScript) { s.fail[aliasDomainRead] = errScripted }, http.StatusInternalServerError, "could not read mail domain"},
		{"an alias name that is not a local part", `{"local_part":"no spaces","destination":"a@b.test"}`, noSetup, http.StatusBadRequest, "invalid alias name"},
		{"a destination that is not an address", `{"local_part":"info","destination":"nope"}`, noSetup, http.StatusBadRequest, "invalid destination email address"},
		{"no destination at all", `{"local_part":"info","destination":" , "}`, noSetup, http.StatusBadRequest, "enter at least one destination email address"},
		{"the source as its own destination", `{"local_part":"info","destination":"INFO@example.com"}`, noSetup, http.StatusBadRequest, "destination cannot match the source address"},
		{"an insert that fails", fine, func(s *sqlScript) { s.fail[aliasInsert] = errScripted }, http.StatusConflict, "mail alias already exists or could not be created"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			script := aliasScript()
			c.setup(script)
			assertAnswer(t, createAlias(t, script, c.body), c.status, c.text)
		})
	}
}

// An empty local part is the catch-all; a named one is lower-cased, and a
// destination list loses its duplicates.
func TestCreateAliasWritesACatchAllAndANamedAlias(t *testing.T) {
	cases := []struct {
		body, source, destination string
		catchAll                  bool
	}{
		{`{"local_part":"","destination":"a@b.test"}`, "@example.com", "a@b.test", true},
		{`{"local_part":" Sales ","destination":"X@y.test, x@y.test"}`, "sales@example.com", "x@y.test", false},
	}
	for _, c := range cases {
		t.Run(c.source, func(t *testing.T) {
			script := aliasScript()
			recorder := createAlias(t, script, c.body)
			if recorder.Code != http.StatusCreated {
				t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
			}
			assertAliasCreated(t, script, jsonBody(t, recorder), c.source, c.destination, c.catchAll)
		})
	}
}

func assertAliasCreated(t *testing.T, s *sqlScript, body map[string]any, source, destination string, catchAll bool) {
	t.Helper()
	if body["source"] != source || body["destination"] != destination || body["catch_all"] != catchAll || body["id"] != float64(9) {
		t.Fatalf("answer = %v", body)
	}
	if insert := s.onlyExec(t, aliasInsert); !slices.Equal(insert.args, []driver.Value{int64(1), source, destination}) {
		t.Fatalf("insert = %#v", insert.args)
	}
	if actions := auditActions(s); !slices.Equal(actions, []string{"mail.alias.create"}) {
		t.Fatalf("audit actions = %v", actions)
	}
}
