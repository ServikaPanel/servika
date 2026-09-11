package mail

import (
	"archive/tar"
	"bytes"
	"database/sql/driver"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"servika/internal/middleware"
)

const (
	migrationBusy = "COUNT(*) FROM mail_migration_jobs"
	layoutRead    = "SELECT m.maildir, d.system_user"
	localPartRead = "SELECT local_part FROM mailboxes WHERE id=?"
	// mailboxRoot is the Maildir relative to the tenant home, with the trailing
	// slash the stored column carries.
	mailboxRoot = "mail/example.com/info/"
)

func importScript() *sqlScript {
	s := handlerScript()
	s.rows[migrationBusy] = [][]driver.Value{{int64(0)}}
	s.rows[layoutRead] = [][]driver.Value{{"/home/c_tenant/mail/example.com/info/", "c_tenant"}}
	s.rows[localPartRead] = [][]driver.Value{{"info"}}
	return s
}

// member is one entry of a tar a test builds. A declared size stops the archive
// right after that header, so no body has to be produced for it.
type member struct {
	name, body string
	size       int64
}

func tarOf(t *testing.T, members ...member) []byte {
	t.Helper()
	var buf bytes.Buffer
	archive := tar.NewWriter(&buf)
	for _, m := range members {
		size := max(m.size, int64(len(m.body)))
		if err := archive.WriteHeader(&tar.Header{Name: m.name, Mode: 0o600, Size: size, Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("write header %s: %v", m.name, err)
		}
		if m.size > 0 {
			return buf.Bytes()
		}
		if _, err := archive.Write([]byte(m.body)); err != nil {
			t.Fatalf("write body %s: %v", m.name, err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("close the archive: %v", err)
	}
	return buf.Bytes()
}

// uploadRequest builds a multipart import with a form field ahead of the file,
// which the handler has to skip.
func uploadRequest(t *testing.T, role, field, name string, content []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	if err := writer.WriteField("note", "ignored"); err != nil {
		t.Fatalf("write the field: %v", err)
	}
	part, err := writer.CreateFormFile(field, name)
	if err != nil {
		t.Fatalf("create the file part: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write the file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close the body: %v", err)
	}
	request := mailRequest(http.MethodPost, "/domains/1/mail/2/import", buf.String(), role,
		map[string]string{"id": "1", "mid": "2"})
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

func runImport(t *testing.T, s *sqlScript, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	(&Handlers{DB: scriptDB(t, s)}).Import(recorder, request)
	return recorder
}

func tarUpload(t *testing.T) *http.Request {
	return uploadRequest(t, middleware.RoleAdmin, "file", "export.tar", tarOf(t, member{name: "cur/1.abc", body: "x"}))
}

// Every refusal Import gives before a message is written.
func TestImportRefusals(t *testing.T) {
	cases := []struct {
		name    string
		request func(*testing.T) *http.Request
		setup   func(*sqlScript)
		status  int
		text    string
	}{
		{"an unknown domain", tarUpload, func(s *sqlScript) { s.rows[domainLookup] = nil }, http.StatusNotFound, "domain not found"},
		{"a caller without a session", func(t *testing.T) *http.Request {
			return uploadRequest(t, "", "file", "export.tar", nil)
		}, noSetup, http.StatusUnauthorized, "authorization required"},
		{"a mailbox of another domain", tarUpload, func(s *sqlScript) { s.rows[mailboxOwned] = [][]driver.Value{{int64(0)}} }, http.StatusNotFound, "mailbox not found"},
		{"a migration check that fails", tarUpload, func(s *sqlScript) { s.fail[migrationBusy] = errScripted }, http.StatusInternalServerError, "the mailbox state could not be read"},
		{"a migration in flight", tarUpload, func(s *sqlScript) { s.rows[migrationBusy] = [][]driver.Value{{int64(1)}} }, http.StatusConflict, `"reason":"migration_already_running"`},
		{"a mailbox that cannot be located", tarUpload, func(s *sqlScript) { s.fail[layoutRead] = errScripted }, http.StatusInternalServerError, "the mailbox could not be located on disk"},
		{"a body that is not multipart", func(*testing.T) *http.Request {
			return mailRequest(http.MethodPost, "/domains/1/mail/2/import", "x", middleware.RoleAdmin, map[string]string{"id": "1", "mid": "2"})
		}, noSetup, http.StatusBadRequest, "a multipart body is required"},
		{"a body without a file field", func(t *testing.T) *http.Request {
			return uploadRequest(t, middleware.RoleAdmin, "attachment", "export.tar", nil)
		}, noSetup, http.StatusBadRequest, "a file is required in the file field"},
		{"an Outlook export without readpst", func(t *testing.T) *http.Request {
			t.Setenv("SERVIKA_READPST_BIN", filepath.Join(t.TempDir(), "readpst"))
			return uploadRequest(t, middleware.RoleAdmin, "file", "Outlook.PST", []byte("!BDN"))
		}, noSetup, http.StatusBadRequest, `"reason":"pst_not_supported"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withMaildirFake(t)
			script := importScript()
			c.setup(script)
			assertAnswer(t, runImport(t, script, c.request(t)), c.status, c.text)
		})
	}
}

// A Maildir tar lands message by message in the folder its path names, keeping
// its flags, under a name the import builds.
func TestImportWritesATarIntoTheMailbox(t *testing.T) {
	fake := withMaildirFake(t)
	script := importScript()
	one, two := "Subject: one\n\nbody\n", "Subject: two\n"
	archive := tarOf(t, member{name: "cur/1.abc:2,S", body: one}, member{name: ".Sent/new/2.def", body: two})

	recorder := runImport(t, script, uploadRequest(t, middleware.RoleAdmin, "file", "export.tar", archive))
	assertAnswer(t, recorder, http.StatusOK, `"ok":true`)
	body := jsonBody(t, recorder)
	if body["messages"] != float64(2) || body["bytes"] != float64(len(one)+len(two)) || body["folders"] != float64(2) {
		t.Fatalf("answer = %v", body)
	}
	assertStreamed(t, fake, mailboxRoot+"/cur/", ":2,S", one)
	assertStreamed(t, fake, mailboxRoot+"/.Sent/cur/", ":2,", two)
	if actions := auditActions(script); !slices.Equal(actions, []string{"mail.import"}) {
		t.Fatalf("audit actions = %v", actions)
	}
}

// Anything that is not a tar or a .pst is read as an mbox into the inbox.
func TestImportSplitsAnMboxIntoTheInbox(t *testing.T) {
	fake := withMaildirFake(t)
	mbox := "From a@b Mon Jan  1 00:00:00 2024\nSubject: one\n\nFrom b@c Mon Jan  1 00:00:01 2024\nSubject: two\n"

	recorder := runImport(t, importScript(), uploadRequest(t, middleware.RoleAdmin, "file", "Inbox.mbox", []byte(mbox)))
	assertAnswer(t, recorder, http.StatusOK, `"messages":2`)
	if written := fake.streamedUnder(mailboxRoot + "/cur/"); len(written) != 2 {
		t.Fatalf("written = %v", written)
	}
}

// A failed import takes out what it wrote, and says so; a removal that fails is
// reported, because a retry will then duplicate.
func TestAFailedImportRollsBackWhatItWroteThroughTheSeam(t *testing.T) {
	cases := []struct {
		name       string
		failRemove error
		removed    float64
		incomplete bool
	}{
		{"everything written is removed", nil, 1, false},
		{"a removal that fails is reported", errScripted, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := withMaildirFake(t)
			fake.failRemove = c.failRemove
			archive := tarOf(t, member{name: "cur/1.abc", body: "Subject: one\n"}, member{name: "cur/2.def", size: maxImportMessageBytes + 1})

			recorder := runImport(t, importScript(), uploadRequest(t, middleware.RoleAdmin, "file", "export.tgz", archive))
			assertAnswer(t, recorder, http.StatusBadRequest, `"reason":"message_too_large"`)
			if body := jsonBody(t, recorder); body["removed"] != c.removed || body["rollback_incomplete"] != c.incomplete {
				t.Fatalf("answer = %v", body)
			}
		})
	}
}

func assertStreamed(t *testing.T, fake *maildirFake, prefix, suffix, body string) {
	t.Helper()
	written := fake.streamedUnder(prefix)
	if len(written) != 1 {
		t.Fatalf("%d messages under %s: %v", len(written), prefix, written)
	}
	for name, got := range written {
		if !strings.HasPrefix(name, "1000000000.import-") || !strings.HasSuffix(name, suffix) || got != body {
			t.Fatalf("wrote %q = %q under %s", name, got, prefix)
		}
	}
}
