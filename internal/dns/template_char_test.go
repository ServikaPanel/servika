package dns

import (
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	templateClear      = "DELETE FROM dns_template"
	templateRowInsert  = discoveryInsert
	templateMetaUpsert = "INSERT INTO dns_template_meta"
	templateEndpoint   = "/api/v1/dns/template"
)

// defaultMetaWrite is the metadata row a save writes when the request carries
// no SOA value of its own.
var defaultMetaWrite = sqlScriptExec{query: templateMetaUpsert, args: []driver.Value{
	int64(3600), int64(900), int64(1209600), int64(3600), int64(3600), "default", int64(0),
}}

func TestPutTemplateReplacesTheWholeTemplateAtOnce(t *testing.T) {
	const oneRecord = `{"records":[{"name":"","type":"a","value":"192.0.2.10","priority":5,"enabled":true}],"meta":{"dkim_selector":"default"}}`
	clear := sqlScriptExec{query: templateClear, args: []driver.Value{}}
	rowWrite := sqlScriptExec{query: templateRowInsert, args: []driver.Value{
		"@", "A", "192.0.2.10", int64(3600), int64(0), int64(10), int64(1),
	}}
	cases := []handlerCase{
		{name: "a body that is not JSON", body: "{", status: http.StatusBadRequest, want: "invalid request body"},
		{name: "a DKIM selector with a space", body: `{"records":[],"meta":{"dkim_selector":"bad selector"}}`,
			status: http.StatusBadRequest, want: "invalid DKIM selector"},
		{name: "a record type the panel does not store",
			body:   `{"records":[{"name":"@","type":"FOO","value":"x"}],"meta":{"dkim_selector":"default"}}`,
			status: http.StatusBadRequest, want: "invalid DNS template record"},
		{name: "a record with no value",
			body:   `{"records":[{"name":"@","type":"A","value":""}],"meta":{"dkim_selector":"default"}}`,
			status: http.StatusBadRequest, want: "invalid DNS template record"},
		{name: "a transaction that cannot start", body: oneRecord,
			script: func(s *sqlScript) { s.beginErr = errScripted },
			status: http.StatusInternalServerError, want: "could not update DNS template"},
		{name: "a clear that fails", body: oneRecord,
			script: func(s *sqlScript) { s.fail[templateClear] = errScripted },
			status: http.StatusInternalServerError, want: "could not update DNS template",
			writes: []sqlScriptExec{clear}},
		{name: "a row the database refuses", body: oneRecord,
			script: func(s *sqlScript) { s.fail[templateRowInsert] = errScripted },
			status: http.StatusInternalServerError, want: "could not update DNS template",
			writes: []sqlScriptExec{clear, rowWrite}},
		{name: "metadata the database refuses", body: oneRecord,
			script: func(s *sqlScript) { s.fail[templateMetaUpsert] = errScripted },
			status: http.StatusInternalServerError, want: "could not update DNS template",
			writes: []sqlScriptExec{clear, rowWrite, defaultMetaWrite}},
		{name: "a commit that fails", body: oneRecord,
			script: func(s *sqlScript) { s.commitErr = errScripted },
			status: http.StatusInternalServerError, want: "could not update DNS template",
			writes: []sqlScriptExec{clear, rowWrite, defaultMetaWrite}},
		{name: "a record that takes the defaults", body: oneRecord,
			status: http.StatusOK, want: `"ok":true`,
			writes: []sqlScriptExec{clear, rowWrite, defaultMetaWrite}},
		{name: "an MX that keeps its priority and order",
			body:   `{"records":[{"name":"@","type":"mx","value":"mail.example.com","ttl":60,"priority":10,"sort_order":99}],"meta":{"dkim_selector":"default"}}`,
			status: http.StatusOK, want: `"ok":true`,
			writes: []sqlScriptExec{clear, {query: templateRowInsert, args: []driver.Value{
				"@", "MX", "mail.example.com", int64(60), int64(10), int64(99), int64(0)}}, defaultMetaWrite}},
		{name: "metadata the operator chose",
			body: `{"records":[],"meta":{"soa_refresh":60,"soa_retry":30,"soa_expire":90,"soa_minimum":15,"soa_ttl":45,` +
				`"dkim_selector":"sel","dkim_enabled":true}}`,
			status: http.StatusOK, want: `"ok":true`,
			writes: []sqlScriptExec{clear, {query: templateMetaUpsert, args: []driver.Value{
				int64(60), int64(30), int64(90), int64(15), int64(45), "sel", int64(1)}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := newScript()
			if tc.script != nil {
				tc.script(script)
			}
			handlers := &Handlers{DB: scriptDB(t, script)}
			recorder := httptest.NewRecorder()
			handlers.PutTemplate(recorder, dnsRequest(http.MethodPut, templateEndpoint, tc.body, ""))
			assertResponse(t, recorder, tc.status, tc.want)
			assertWrites(t, script, tc.writes)
		})
	}
}
