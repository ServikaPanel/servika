package dns

import (
	"bytes"
	"database/sql/driver"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	importInsert   = "VALUES(?,?,?,?,?,?, 1)"
	importDelete   = "DELETE FROM dns_records WHERE domain_id=?"
	importEndpoint = "/api/v1/domains/7/dns/import"
)

// importScript answers an import for domain 7 whose zone holds no record yet.
func importScript() *sqlScript {
	s := newScript()
	s.rows[domainLookup] = [][]driver.Value{{"example.com"}}
	s.rows[seedCountQuery] = [][]driver.Value{{int64(0)}}
	return s
}

// multipartZone builds an upload whose form carries the zone in one field.
func multipartZone(t *testing.T, field, zone string) (body, contentType string) {
	t.Helper()
	var buffer bytes.Buffer
	form := multipart.NewWriter(&buffer)
	part, err := form.CreateFormFile(field, "zone.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(zone)); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.String(), form.FormDataContentType()
}

type importCase struct {
	name        string
	body        string
	contentType string
	target      string
	script      func(s *sqlScript)
	zoneErr     error
	status      int
	want        string
	writes      []sqlScriptExec
}

func TestImportMergesOrReplacesAZoneFile(t *testing.T) {
	const oneRecord = "@\tIN\tA\t192.0.2.10\n"
	insert := sqlScriptExec{query: importInsert, args: []driver.Value{
		int64(7), "@", "A", "192.0.2.10", int64(3600), int64(0),
	}}
	upload, uploadType := multipartZone(t, "file", oneRecord)
	wrongField, wrongFieldType := multipartZone(t, "zone", oneRecord)
	cases := []importCase{
		{name: "a domain that is not there", body: oneRecord, status: http.StatusNotFound, want: "domain not found",
			script: func(s *sqlScript) { s.rows[domainLookup] = nil }},
		{name: "an empty upload", body: "   \n", status: http.StatusBadRequest, want: "empty zone content"},
		{name: "a file with no usable record", body: "$TTL 60\n",
			status: http.StatusBadRequest, want: "no valid DNS record found"},
		{name: "an upload that cannot be parsed", body: "x", contentType: "multipart/form-data",
			status: http.StatusBadRequest, want: "could not read the upload"},
		{name: "an upload under the wrong field name", body: wrongField, contentType: wrongFieldType,
			status: http.StatusBadRequest, want: "file field not found"},
		{name: "an upload under the file field", body: upload, contentType: uploadType,
			status: http.StatusOK, want: `"added":1`, writes: []sqlScriptExec{insert}},
		{name: "a transaction that cannot start", body: oneRecord,
			script: func(s *sqlScript) { s.beginErr = errScripted },
			status: http.StatusInternalServerError, want: "internal server error"},
		{name: "a replace whose delete fails", body: oneRecord, target: importEndpoint + "?mode=replace",
			script: func(s *sqlScript) { s.fail[importDelete] = errScripted },
			status: http.StatusInternalServerError, want: "could not remove the existing records",
			writes: []sqlScriptExec{{query: importDelete, args: []driver.Value{int64(7)}}}},
		{name: "a record the zone already holds", body: oneRecord,
			script: func(s *sqlScript) { s.rows[seedCountQuery] = [][]driver.Value{{int64(1)}} },
			status: http.StatusOK, want: `"skipped":1`},
		{name: "a record the database refuses", body: oneRecord,
			script: func(s *sqlScript) { s.fail[importInsert] = errScripted },
			status: http.StatusInternalServerError, want: "could not add a record", writes: []sqlScriptExec{insert}},
		{name: "a commit that fails", body: oneRecord,
			script: func(s *sqlScript) { s.commitErr = errScripted },
			status: http.StatusInternalServerError, want: "internal server error", writes: []sqlScriptExec{insert}},
		{name: "a merge that adds the record", body: oneRecord,
			status: http.StatusOK, want: `"mode":"merge"`, writes: []sqlScriptExec{insert}},
		{name: "a replace that clears the zone first", body: oneRecord, target: importEndpoint + "?mode=replace",
			status: http.StatusOK, want: `"mode":"replace"`,
			writes: []sqlScriptExec{{query: importDelete, args: []driver.Value{int64(7)}}, insert}},
		{name: "a zone that cannot be written", body: oneRecord, zoneErr: errScripted,
			status: http.StatusOK, want: `"warning":"records saved but zone validation warned: scripted failure"`,
			writes: []sqlScriptExec{insert}},
		{name: "a file carrying an SOA",
			body:   "@\tIN\tSOA\tns1.example.com. admin.example.com. 2026010101 3600 900 1209600 3600\n" + oneRecord,
			status: http.StatusOK, want: `"added":1`,
			writes: []sqlScriptExec{insert, {query: soaInsert, args: []driver.Value{
				int64(7), "ns1.example.com", "admin@example.com",
				int64(3600), int64(900), int64(1209600), int64(3600), int64(3600)}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runImport(t, tc)
		})
	}
}

func runImport(t *testing.T, tc importCase) {
	t.Helper()
	script := importScript()
	if tc.script != nil {
		tc.script(script)
	}
	zoneWriteReturns(t, tc.zoneErr)
	target := tc.target
	if target == "" {
		target = importEndpoint
	}
	request := dnsRequest(http.MethodPost, target, tc.body, "7")
	if tc.contentType != "" {
		request.Header.Set("Content-Type", tc.contentType)
	}
	handlers := &Handlers{DB: scriptDB(t, script)}
	recorder := httptest.NewRecorder()
	handlers.Import(recorder, request)
	assertResponse(t, recorder, tc.status, tc.want)
	assertWrites(t, script, tc.writes)
}
