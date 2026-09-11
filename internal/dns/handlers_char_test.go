package dns

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

const (
	domainLookup = "SELECT domain_name FROM domains WHERE id=?"
	recordInsert = "INSERT INTO dns_records(domain_id, name, type, value, ttl, priority, enabled)"
	savedRecord  = "FROM dns_records WHERE id=?"
)

// dnsRequest builds a request whose chi route carries the domain id.
func dnsRequest(method, target, body, id string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routeCtx))
}

// zoneWriteReturns replaces the zone writer for one test, so no handler test
// touches the real zone directory.
func zoneWriteReturns(t *testing.T, err error) {
	t.Helper()
	setForTest(t, &writeZone, func(context.Context, *sql.DB, int64) error { return err })
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

// createScript answers a record create for domain 7, example.com.
func createScript() *sqlScript {
	s := newScript()
	s.rows[domainLookup] = [][]driver.Value{{"example.com"}}
	s.rows[savedRecord] = [][]driver.Value{
		{int64(42), int64(7), "www", "A", "192.0.2.10", int64(3600), int64(0), int64(1), "2026-09-12 10:00"},
	}
	s.insertID = 42
	return s
}

// handlerCase is one HTTP request against a scripted database.
type handlerCase struct {
	name    string
	body    string
	script  func(s *sqlScript)
	zoneErr error
	status  int
	want    string
	writes  []sqlScriptExec
}

func TestCreateRecordRefusesWhatItCannotStore(t *testing.T) {
	const good = `{"name":"www","type":"A","value":"192.0.2.10","active":true}`
	goodWrite := sqlScriptExec{query: recordInsert, args: []driver.Value{
		int64(7), "www", "A", "192.0.2.10", int64(3600), int64(0), int64(1),
	}}
	cases := []handlerCase{
		{name: "a domain that is not there", body: good, status: http.StatusNotFound, want: "domain not found",
			script: func(s *sqlScript) { s.rows[domainLookup] = nil }},
		{name: "a body that is not JSON", body: "{", status: http.StatusBadRequest, want: "invalid request body"},
		{name: "a type the panel does not store", body: `{"name":"www","type":"FOO","value":"x"}`,
			status: http.StatusBadRequest, want: "invalid DNS record type"},
		{name: "a record with no value", body: `{"name":"www","type":"A","value":""}`,
			status: http.StatusBadRequest, want: "invalid DNS record"},
		{name: "an insert the database refuses", body: good,
			script: func(s *sqlScript) { s.fail[recordInsert] = errScripted },
			status: http.StatusInternalServerError, want: "internal server error", writes: []sqlScriptExec{goodWrite}},
		{name: "a zone that cannot be written", body: good, zoneErr: errScripted,
			status: http.StatusInternalServerError, want: "record saved but DNS zone could not be updated",
			writes: []sqlScriptExec{goodWrite}},
		{name: "a record with no name and no TTL", body: `{"type":"A","value":"192.0.2.10","active":true}`,
			status: http.StatusCreated, want: `"id":42`,
			writes: []sqlScriptExec{{query: recordInsert, args: []driver.Value{
				int64(7), "@", "A", "192.0.2.10", int64(3600), int64(0), int64(1)}}}},
		{name: "an MX that keeps its priority", body: `{"name":"@","type":"MX","value":"mail.example.com","ttl":60,"priority":10}`,
			status: http.StatusCreated, want: `"id":42`,
			writes: []sqlScriptExec{{query: recordInsert, args: []driver.Value{
				int64(7), "@", "MX", "mail.example.com", int64(60), int64(10), int64(0)}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := createScript()
			if tc.script != nil {
				tc.script(script)
			}
			zoneWriteReturns(t, tc.zoneErr)
			handlers := &Handlers{DB: scriptDB(t, script)}
			recorder := httptest.NewRecorder()
			handlers.Create(recorder, dnsRequest(http.MethodPost, "/api/v1/domains/7/dns", tc.body, "7"))
			assertResponse(t, recorder, tc.status, tc.want)
			assertWrites(t, script, tc.writes)
		})
	}
}

// soaScript answers an SOA save for domain 7 with the panel-wide pair.
func soaScript() *sqlScript {
	s := newScript()
	s.rows[domainLookup] = [][]driver.Value{{"example.com"}}
	s.rows[resellerNSQuery] = nil
	s.rows[panelNSQuery] = [][]driver.Value{{"ns1.host.example", "ns2.host.example"}}
	s.rows["FROM dns_soa WHERE domain_id=?"] = nil
	return s
}

func TestPutSOAFillsEveryFieldItWasNotGiven(t *testing.T) {
	defaults := []driver.Value{
		int64(7), "ns1.host.example", "admin@example.com",
		int64(3600), int64(900), int64(1209600), int64(3600), int64(3600),
	}
	cases := []handlerCase{
		{name: "a domain that is not there", body: "{}", status: http.StatusNotFound, want: "domain not found",
			script: func(s *sqlScript) { s.rows[domainLookup] = nil }},
		{name: "a body that is not JSON", body: "{", status: http.StatusBadRequest, want: "invalid request body"},
		{name: "an empty body", body: "{}", status: http.StatusOK, want: `"primary_ns":"ns1.host.example"`,
			writes: []sqlScriptExec{{query: soaInsert, args: defaults}}},
		{name: "values that are all out of range",
			body:   `{"primary_ns":"  ","hostmaster":" ","refresh":0,"retry":-1,"expire":0,"minimum":0,"ttl":-5}`,
			status: http.StatusOK, want: `"hostmaster":"admin@example.com"`,
			writes: []sqlScriptExec{{query: soaInsert, args: defaults}}},
		{name: "values the operator chose",
			body:   `{"primary_ns":"ns9.other.example","hostmaster":"dns@example.com","refresh":60,"retry":30,"expire":90,"minimum":15,"ttl":45}`,
			status: http.StatusOK, want: `"primary_ns":"ns9.other.example"`,
			writes: []sqlScriptExec{{query: soaInsert, args: []driver.Value{
				int64(7), "ns9.other.example", "dns@example.com",
				int64(60), int64(30), int64(90), int64(15), int64(45)}}}},
		{name: "a save the database refuses", body: "{}",
			script: func(s *sqlScript) { s.fail[soaInsert] = errScripted },
			status: http.StatusInternalServerError, want: "could not save SOA settings",
			writes: []sqlScriptExec{{query: soaInsert, args: defaults}}},
		{name: "a zone that cannot be written", body: "{}", zoneErr: errScripted,
			status: http.StatusOK, want: `"ttl":3600`,
			writes: []sqlScriptExec{{query: soaInsert, args: defaults}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := soaScript()
			if tc.script != nil {
				tc.script(script)
			}
			zoneWriteReturns(t, tc.zoneErr)
			handlers := &Handlers{DB: scriptDB(t, script)}
			recorder := httptest.NewRecorder()
			handlers.PutSOA(recorder, dnsRequest(http.MethodPut, "/api/v1/domains/7/dns/soa", tc.body, "7"))
			assertResponse(t, recorder, tc.status, tc.want)
			assertWrites(t, script, tc.writes)
		})
	}
}
