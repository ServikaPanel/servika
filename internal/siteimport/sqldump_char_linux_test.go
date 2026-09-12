package siteimport

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// UploadSQL spools the dump, resolves the database against this domain's own
// records, and applies it through an account granted on that one schema. The
// import itself is a seam here: there is no MariaDB in a test.

// ownedDatabase scripts the db_accounts row that proves ownership.
func ownedDatabase(script *sqlScript, user, password string) {
	script.rows["FROM db_accounts WHERE domain_id=? AND db_name=?"] = [][]driver.Value{
		{user, password, "localhost"},
	}
}

// importedDump is what the importer was handed.
type importedDump struct {
	dbName    string
	body      string
	truncated []string
}

// recordImport installs the dump seams and returns what they were handed.
func recordImport(t *testing.T, failWith error) *importedDump {
	t.Helper()
	recorded := &importedDump{}
	setForTest(t, &truncateDatabase, func(_ context.Context, dbName string) error {
		recorded.truncated = append(recorded.truncated, dbName)
		return nil
	})
	setForTest(t, &importDump, func(_ context.Context, dbName string, source io.Reader) error {
		body, err := io.ReadAll(source)
		if err != nil {
			t.Fatalf("read the dump the importer was handed: %v", err)
		}
		recorded.dbName, recorded.body = dbName, string(body)
		return failWith
	})
	return recorded
}

// uploadSQL posts a multipart dump to the handler.
func uploadSQL(t *testing.T, handlers *Handlers, pairs ...string) *httptest.ResponseRecorder {
	t.Helper()
	contentType, body := multipartBody(t, pairs...)
	recorder := httptest.NewRecorder()
	handlers.UploadSQL(recorder, importRequest(t, http.MethodPost, contentType, body))
	return recorder
}

const oneStatement = "CREATE TABLE t (id INT);\n"

func TestADumpReachesTheDatabaseItNames(t *testing.T) {
	script := newScript()
	ownedDomain(script, "c_acme")
	ownedDatabase(script, "c_acme_wp", "secret")
	handlers := &Handlers{DB: scriptDB(t, script)}
	recorded := recordImport(t, nil)

	recorder := uploadSQL(t, handlers,
		"db_name", "c_acme_wp", "dump:site.sql", oneStatement)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	var answer sqlResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	if answer.DBName != "c_acme_wp" || answer.Bytes != int64(len(oneStatement)) {
		t.Errorf("answer = %+v", answer)
	}
	if answer.Truncated {
		t.Error("the database was reported as emptied without being asked")
	}
	if recorded.dbName != "c_acme_wp" || recorded.body != oneStatement {
		t.Errorf("the importer was handed %q for %q", recorded.body, recorded.dbName)
	}
	if len(recorded.truncated) != 0 {
		t.Errorf("truncated = %v, want none", recorded.truncated)
	}
}

// The magic bytes decide, not the name: people routinely upload a gzip named
// .sql, and feeding compressed bytes to the client fails with an unreadable
// syntax error.
func TestAGzippedDumpIsDecompressedWhateverItIsNamed(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(oneStatement)); err != nil {
		t.Fatalf("compress the dump: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close the gzip writer: %v", err)
	}

	script := newScript()
	ownedDomain(script, "c_acme")
	ownedDatabase(script, "c_acme_wp", "secret")
	handlers := &Handlers{DB: scriptDB(t, script)}
	recorded := recordImport(t, nil)

	recorder := uploadSQL(t, handlers,
		"db_name", "c_acme_wp", "dump:site.sql", compressed.String())

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	if recorded.body != oneStatement {
		t.Errorf("the importer was handed %q, want the decompressed dump", recorded.body)
	}
}

// Emptying first is what "truncate" means, and it happens before the import so
// the dump lands in a schema with nothing left of the previous site.
func TestATruncatingImportEmptiesTheSchemaFirst(t *testing.T) {
	script := newScript()
	ownedDomain(script, "c_acme")
	ownedDatabase(script, "c_acme_wp", "secret")
	handlers := &Handlers{DB: scriptDB(t, script)}
	recorded := recordImport(t, nil)

	recorder := uploadSQL(t, handlers,
		"db_name", "c_acme_wp", "truncate", "1", "dump:site.sql", oneStatement)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	if len(recorded.truncated) != 1 || recorded.truncated[0] != "c_acme_wp" {
		t.Errorf("truncated = %v, want the one database", recorded.truncated)
	}
	var answer sqlResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	if !answer.Truncated {
		t.Error("truncated = false in the answer")
	}
}

// The client's own failure text is the useful part of a failed import: it
// describes the caller's dump going into the caller's database.
func TestAFailedImportReportsWhatTheClientSaid(t *testing.T) {
	script := newScript()
	ownedDomain(script, "c_acme")
	ownedDatabase(script, "c_acme_wp", "secret")
	handlers := &Handlers{DB: scriptDB(t, script)}
	recordImport(t, errors.New("ERROR 1064 (42000) at line 3: You have an error in your SQL syntax"))

	recorder := uploadSQL(t, handlers, "db_name", "c_acme_wp", "dump:site.sql", oneStatement)

	assertRefusal(t, recorder, http.StatusBadRequest, "ERROR 1064")
}

// A long failure is bounded, or a dump that fails on its thousandth statement
// returns a response the size of the dump.
func TestALongImportFailureIsBounded(t *testing.T) {
	script := newScript()
	ownedDomain(script, "c_acme")
	ownedDatabase(script, "c_acme_wp", "secret")
	handlers := &Handlers{DB: scriptDB(t, script)}
	recordImport(t, errors.New(strings.Repeat("x", 5000)))

	recorder := uploadSQL(t, handlers, "db_name", "c_acme_wp", "dump:site.sql", oneStatement)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if recorder.Body.Len() > 1000 {
		t.Errorf("the answer is %d bytes, want the failure bounded", recorder.Body.Len())
	}
}

// A dump that starts with the gzip magic and is not gzip is refused with the
// reason, rather than being handed to the client as compressed bytes.
func TestADumpThatClaimsToBeGzipAndIsNotIsRefused(t *testing.T) {
	script := newScript()
	ownedDomain(script, "c_acme")
	ownedDatabase(script, "c_acme_wp", "secret")
	handlers := &Handlers{DB: scriptDB(t, script)}
	recorded := recordImport(t, nil)

	recorder := uploadSQL(t, handlers,
		"db_name", "c_acme_wp", "dump:site.sql.gz", "\x1f\x8bnot really compressed")

	assertRefusal(t, recorder, http.StatusBadRequest, "the dump is not a readable gzip file")
	if recorded.dbName != "" {
		t.Errorf("the importer was handed a dump it cannot read: %q", recorded.dbName)
	}
}

// A schema that cannot be emptied stops the import: applying a dump over the
// previous site's tables is not what "truncate" was asked for.
func TestAnImportStopsWhenTheSchemaCannotBeEmptied(t *testing.T) {
	script := newScript()
	ownedDomain(script, "c_acme")
	ownedDatabase(script, "c_acme_wp", "secret")
	handlers := &Handlers{DB: scriptDB(t, script)}
	recorded := recordImport(t, nil)
	setForTest(t, &truncateDatabase, func(context.Context, string) error {
		return errors.New("access denied")
	})

	recorder := uploadSQL(t, handlers,
		"db_name", "c_acme_wp", "truncate", "true", "dump:site.sql", oneStatement)

	assertRefusal(t, recorder, http.StatusInternalServerError, "the database could not be emptied")
	if recorded.dbName != "" {
		t.Errorf("the dump was applied over the previous site: %q", recorded.dbName)
	}
}

func TestADumpRefusesADatabaseItMustNotTouch(t *testing.T) {
	cases := []struct {
		name    string
		script  func(*sqlScript)
		pairs   []string
		status  int
		message string
	}{
		{
			name: "a database of another domain",
			script: func(s *sqlScript) {
				ownedDomain(s, "c_acme")
				s.rows["FROM db_accounts WHERE domain_id=? AND db_name=?"] = nil
			},
			pairs:   []string{"db_name", "c_other_wp", "dump:site.sql", oneStatement},
			status:  http.StatusForbidden,
			message: "that database does not belong to this domain",
		},
		{
			name:    "no database at all",
			script:  func(s *sqlScript) { ownedDomain(s, "c_acme") },
			pairs:   []string{"dump:site.sql", oneStatement},
			status:  http.StatusForbidden,
			message: "the db_name field is required",
		},
		{
			name:    "a name that is not an identifier",
			script:  func(s *sqlScript) { ownedDomain(s, "c_acme") },
			pairs:   []string{"db_name", "wp; DROP SCHEMA mysql", "dump:site.sql", oneStatement},
			status:  http.StatusForbidden,
			message: "invalid database name",
		},
		{
			name:    "no dump",
			script:  func(s *sqlScript) { ownedDomain(s, "c_acme") },
			pairs:   []string{"db_name", "c_acme_wp"},
			status:  http.StatusBadRequest,
			message: "the dump field is required",
		},
		{
			name:    "a domain that is not there",
			script:  func(s *sqlScript) { s.rows["SELECT system_user FROM domains WHERE id=?"] = nil },
			pairs:   []string{"db_name", "c_acme_wp", "dump:site.sql", oneStatement},
			status:  http.StatusNotFound,
			message: "domain not found",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			script := newScript()
			testCase.script(script)
			handlers := &Handlers{DB: scriptDB(t, script)}
			recorded := recordImport(t, nil)

			assertRefusal(t, uploadSQL(t, handlers, testCase.pairs...), testCase.status, testCase.message)
			if recorded.dbName != "" {
				t.Errorf("a refused upload still reached %q", recorded.dbName)
			}
		})
	}
}

// A request that is not multipart at all is refused before anything is spooled.
func TestASQLUploadWithoutAMultipartBodyIsRefused(t *testing.T) {
	script := newScript()
	ownedDomain(script, "c_acme")
	handlers := &Handlers{DB: scriptDB(t, script)}

	recorder := httptest.NewRecorder()
	handlers.UploadSQL(recorder, importRequest(t, http.MethodPost, "application/json", []byte(`{}`)))

	assertRefusal(t, recorder, http.StatusBadRequest, "a multipart body is required")
}
