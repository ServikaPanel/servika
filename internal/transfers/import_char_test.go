package transfers

import (
	"archive/tar"
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"servika/internal/cron"
	"servika/internal/domains"
	"servika/internal/mail"
)

// formPart is one part of a multipart body; a part with a file name is a file.
type formPart struct {
	field, fileName string
	body            []byte
}

func multipartRequest(t *testing.T, target string, parts ...formPart) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		writeFormPart(t, mw, p)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, target, &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

func writeFormPart(t *testing.T, mw *multipart.Writer, p formPart) {
	t.Helper()
	var w io.Writer
	var err error
	if p.fileName != "" {
		w, err = mw.CreateFormFile(p.field, p.fileName)
	} else {
		w, err = mw.CreateFormField(p.field)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(p.body); err != nil {
		t.Fatal(err)
	}
}

// rawRequest builds a request with a body sent as it is, under contentType.
func rawRequest(contentType, body string) func(*testing.T) *http.Request {
	return func(*testing.T) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/transfers", strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		return r
	}
}

func assertResponse(t *testing.T, w *httptest.ResponseRecorder, status int, fragment string) {
	t.Helper()
	if w.Code != status || !strings.Contains(w.Body.String(), fragment) {
		t.Fatalf("response = %d %s, want %d holding %q", w.Code, w.Body.String(), status, fragment)
	}
}

// Analyze streams the upload: every refusal names its reason, an oversized
// archive is 413, and a cPanel archive answers its inventory.
func TestAnalyzeHandler(t *testing.T) {
	inventory := archiveBytes(t, testEntry{name: "backup-demo/cp/userdata/demo/main", body: "main_domain: example.com\n"})
	huge := rawArchiveBytes(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "backup-demo/homedir/big", Mode: 0o600, Size: maxExpandedBytes + 1, Typeflag: tar.TypeReg})
	})
	archivePart := func(name string, body []byte) func(*testing.T) *http.Request {
		return func(t *testing.T) *http.Request {
			return multipartRequest(t, "/transfers/analyze",
				formPart{field: "note", body: []byte("x")}, formPart{field: "archive", fileName: name, body: body})
		}
	}
	cases := []struct {
		name     string
		request  func(*testing.T) *http.Request
		status   int
		fragment string
	}{
		{"a body that is not multipart", rawRequest("text/plain", "x"), http.StatusBadRequest, "a multipart body is required"},
		{"a multipart body that breaks", rawRequest("multipart/form-data; boundary=xyz", "garbage"), http.StatusBadRequest, "could not read the upload or the size limit was exceeded"},
		{"no archive part", func(t *testing.T) *http.Request {
			return multipartRequest(t, "/transfers/analyze", formPart{field: "note", body: []byte("x")})
		}, http.StatusBadRequest, "a cPanel .tar.gz backup is required in the archive field"},
		{"an archive that is not tar.gz", archivePart("backup.zip", inventory), http.StatusBadRequest, "the first release only supports cPanel .tar.gz/.tgz full backups"},
		{"an archive past the inventory limit", archivePart("backup.tar.gz", huge), http.StatusRequestEntityTooLarge, ErrArchiveTooLarge.Error()},
		{"an archive that is not cPanel", archivePart("backup.tgz", archiveBytes(t, testEntry{name: "backup-demo/other", body: "x"})), http.StatusBadRequest, ErrNotCPanel.Error()},
		{"a cPanel archive", archivePart("Backup.TGZ", inventory), http.StatusOK, `"primary_domain":"example.com"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			(&Handlers{}).Analyze(w, c.request(t))
			assertResponse(t, w, c.status, c.fragment)
		})
	}
}

// answerWith is an in-process handler that answers status and body whatever it
// is asked.
func answerWith[H any](status int, body string) func(*H, http.ResponseWriter, *http.Request) {
	return func(_ *H, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

// mailboxAnswer creates the mailbox the request names and answers its fresh
// credentials.
func mailboxAnswer(_ *mail.Handlers, w http.ResponseWriter, r *http.Request) {
	var in struct {
		LocalPart string `json:"local_part"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	w.WriteHeader(http.StatusCreated)
	_, _ = fmt.Fprintf(w, `{"email":"%s@example.com","password":"pw-%s"}`, in.LocalPart, in.LocalPart)
}

func importedSSL(string, []byte, []byte) (string, string, time.Time, error) {
	return "/ssl/imported.crt", "/ssl/imported.key", time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC), nil
}

func failingSSL(string, []byte, []byte) (string, string, time.Time, error) {
	return "", "", time.Time{}, errScripted
}

func enabledMail(context.Context, *sql.DB, int64) error { return nil }

func failingMail(context.Context, *sql.DB, int64) error { return errScripted }

const createdExample = `{"id":9,"domain_name":"example.com","system_user":"c_example_com","db_name":"c_example_com_main","db_user":"c_example_com_db"}`

// importHarness fakes every provider the cPanel import drives; each one answers
// with success until a test replaces it.
type importHarness struct {
	t       *testing.T
	tmp     string
	h       *Handlers
	script  *sqlScript
	creates *dbCreates
	imports *sqlImports
	deleted []string
	crons   []string
}

func newImportHarness(t *testing.T) *importHarness {
	t.Helper()
	hs := &importHarness{t: t, tmp: t.TempDir(), script: newScript()}
	hs.h = &Handlers{DB: scriptDB(t, hs.script), Domains: &domains.Handlers{}, Mail: &mail.Handlers{}, Cron: &cron.Handlers{}}
	withCommands(t)
	hs.creates = withDBCreates(t)
	hs.imports = withSQLImports(t, nil)
	setForTest(t, &createDomain, answerWith[domains.Handlers](http.StatusCreated, createdExample))
	setForTest(t, &deleteDomain, hs.deleteDomain)
	setForTest(t, &enableMailDomain, enabledMail)
	setForTest(t, &createMailbox, mailboxAnswer)
	setForTest(t, &createMailAlias, answerWith[mail.Handlers](http.StatusCreated, `{}`))
	setForTest(t, &createCronJob, hs.createCron)
	setForTest(t, &installImportedSSL, importedSSL)
	setForTest(t, &rerenderVhost, func(*sql.DB, int64) error { return nil })
	return hs
}

func (hs *importHarness) deleteDomain(_ *domains.Handlers, _ http.ResponseWriter, r *http.Request) {
	hs.deleted = append(hs.deleted, chi.URLParam(r, "id"))
}

func (hs *importHarness) createCron(_ *cron.Handlers, w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	hs.crons = append(hs.crons, chi.URLParam(r, "id")+" "+string(body))
	w.WriteHeader(http.StatusCreated)
}

// cpanelEntries is a full cPanel account: web files, two databases, a mailbox
// with messages, a forwarder, a cron job and a certificate with its key.
func cpanelEntries() []testEntry {
	return []testEntry{
		{name: "backup-demo/cp/userdata/demo/main", body: "main_domain: example.com\n"},
		{name: "backup-demo/homedir/public_html/index.php", body: "<?php"},
		{name: "backup-demo/mysql/demo_wp.sql", body: "wp dump"},
		{name: "backup-demo/mysql/demo_shop.sql", body: "shop dump"},
		{name: "backup-demo/homedir/etc/example.com/shadow", body: "info:$6$x:1::::\n"},
		{name: "backup-demo/homedir/mail/example.com/info/cur/1", body: "mail"},
		{name: "backup-demo/va/example.com", body: "sales: out@example.net\n"},
		{name: "backup-demo/cron", body: "0 2 * * * /home/demo/run.sh\n"},
		{name: "backup-demo/sslcerts/example.com.crt", body: "CERT"},
		{name: "backup-demo/sslkeys/example.com.key", body: "KEY"},
	}
}

func importRequest(t *testing.T, entries ...testEntry) *http.Request {
	t.Helper()
	return multipartRequest(t, "/transfers/import",
		formPart{field: "customer_id", body: []byte("3")},
		formPart{field: "archive", fileName: "backup.tar.gz", body: archiveBytes(t, entries...)})
}

func fullImport(t *testing.T) *http.Request { return importRequest(t, cpanelEntries()...) }

func decodeImport(t *testing.T, w *httptest.ResponseRecorder) importResponse {
	t.Helper()
	var got importResponse
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// A full cPanel account becomes a domain with its web files, both databases,
// its mailbox and forwarder, its cron job and its certificate.
func TestImportRestoresTheWholeAccount(t *testing.T) {
	hs := newImportHarness(t)
	w := httptest.NewRecorder()
	hs.h.Import(w, fullImport(t))
	got := decodeImport(t, w)

	want := importResponse{
		OK: true, DomainID: 9, Domain: "example.com", SystemUser: "c_example_com", WebFiles: 1,
		Databases: []DBMap{
			{Source: "demo_shop", Target: "c_example_com_main", User: "c_example_com_db"},
			{Source: "demo_wp", Target: "c_example_com_demo_wp", User: "c_example_com_db"},
		},
		Mailboxes: []MailCredential{{Email: "info@example.com", Password: "pw-info"}},
		Aliases:   1, CronJobs: 1, SSLImported: true, SSLExpires: "2027-01-02", Skipped: []string{},
		Source: got.Source,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("response =\n%+v\nwant\n%+v", got, want)
	}
	if !reflect.DeepEqual(hs.creates.calls, []string{"attach 9 c_example_com_demo_wp c_example_com_db"}) ||
		!reflect.DeepEqual(hs.imports.targets, []string{"c_example_com_demo_wp", "c_example_com_main"}) {
		t.Fatalf("creates %q, imports %q", hs.creates.calls, hs.imports.targets)
	}
	wantCron := `9 {"command":"/home/c_example_com/run.sh","comment":"","day":"*","hour":"2","minute":"0","month":"*","week":"*"}`
	if !reflect.DeepEqual(hs.crons, []string{wantCron}) || len(hs.deleted) != 0 {
		t.Fatalf("crons %q, deleted %q", hs.crons, hs.deleted)
	}
	assertExecArgs(t, hs.script, "ssl_source='imported'",
		[]driver.Value{"/ssl/imported.crt", "/ssl/imported.key", time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC), int64(9)})
}

// A certificate without its key is skipped with a warning, and the import still
// succeeds.
func TestImportSkipsACertificateWithoutItsKey(t *testing.T) {
	hs := newImportHarness(t)
	entries := slices.DeleteFunc(cpanelEntries(), func(e testEntry) bool { return strings.HasPrefix(e.name, "backup-demo/sslkeys/") })
	w := httptest.NewRecorder()
	hs.h.Import(w, importRequest(t, entries...))
	got := decodeImport(t, w)
	want := []string{"No matching private key was found for the source SSL certificate; SSL was not transferred."}
	if got.SSLImported || !reflect.DeepEqual(got.Skipped, want) || len(hs.deleted) != 0 {
		t.Fatalf("response = %+v, deleted %q", got, hs.deleted)
	}
}

func assertRollback(t *testing.T, hs *importHarness, rollback bool) {
	t.Helper()
	var want []string
	if rollback {
		want = []string{"9"}
	}
	if !reflect.DeepEqual(hs.deleted, want) {
		t.Fatalf("deleted domains = %q, want %q", hs.deleted, want)
	}
}

// Every step that fails answers its own message, and a failure after the domain
// exists deletes the domain again.
func TestImportRefusals(t *testing.T) {
	bigAlias := append(cpanelEntries(), testEntry{name: "backup-demo/va/example.com", body: strings.Repeat("a", 2<<20+1)})
	cases := []struct {
		name     string
		breaks   func(hs *importHarness)
		request  func(*testing.T) *http.Request
		status   int
		fragment string
		rollback bool
	}{
		{"no domain provider", func(hs *importHarness) { hs.h.Domains = nil }, fullImport, http.StatusInternalServerError, "domain provider is not ready", false},
		{"a body that is not multipart", func(*importHarness) {}, rawRequest("text/plain", "x"), http.StatusBadRequest, "could not read the upload or the size limit was exceeded", false},
		{"no archive field", func(*importHarness) {}, func(t *testing.T) *http.Request {
			return multipartRequest(t, "/transfers/import", formPart{field: "customer_id", body: []byte("3")})
		}, http.StatusBadRequest, "the archive field is required", false},
		{"no temporary directory", func(hs *importHarness) { hs.t.Setenv("TMPDIR", filepath.Join(hs.tmp, "absent")) }, fullImport, http.StatusInternalServerError, "could not create a temporary archive", false},
		{"an archive that is not cPanel", func(*importHarness) {}, func(t *testing.T) *http.Request {
			return importRequest(t, testEntry{name: "backup-demo/other", body: "x"})
		}, http.StatusBadRequest, ErrNotCPanel.Error(), false},
		{"a domain the provider refuses", func(hs *importHarness) {
			setForTest(hs.t, &createDomain, answerWith[domains.Handlers](http.StatusConflict, `{"error":"domain exists"}`))
		}, fullImport, http.StatusConflict, `{"error":"domain exists"}`, false},
		{"a created domain that cannot be read", func(hs *importHarness) {
			setForTest(hs.t, &createDomain, answerWith[domains.Handlers](http.StatusCreated, "not json"))
		}, fullImport, http.StatusInternalServerError, "could not read the created domain response", false},
		{"a helper file past the metadata limit", func(*importHarness) {}, func(t *testing.T) *http.Request {
			return importRequest(t, bigAlias...)
		}, http.StatusInternalServerError, "could not read archive helper files", true},
		{"web files the host refuses", func(hs *importHarness) { withCommands(hs.t, []string{"find"}) }, fullImport, http.StatusInternalServerError, "could not transfer web files", true},
		{"an additional database the server refuses", func(hs *importHarness) { hs.creates.fail["c_example_com_demo_wp"] = true }, fullImport, http.StatusInternalServerError, "could not create the additional database", true},
		{"a dump the server refuses", func(hs *importHarness) { hs.imports.fail = errScripted }, fullImport, http.StatusInternalServerError, "could not transfer the database", true},
		{"mail the server refuses", func(hs *importHarness) { setForTest(hs.t, &enableMailDomain, failingMail) }, fullImport, http.StatusInternalServerError, "could not transfer email", true},
		{"no cron provider", func(hs *importHarness) { hs.h.Cron = nil }, fullImport, http.StatusInternalServerError, "could not transfer cron jobs", true},
		{"a certificate the server refuses", func(hs *importHarness) { setForTest(hs.t, &installImportedSSL, failingSSL) }, fullImport, http.StatusInternalServerError, "could not transfer the SSL certificate", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hs := newImportHarness(t)
			request := c.request(t)
			c.breaks(hs)
			w := httptest.NewRecorder()
			hs.h.Import(w, request)
			assertResponse(t, w, c.status, c.fragment)
			assertRollback(t, hs, c.rollback)
		})
	}
}

// The step name is all a screen needs. The underlying error carries host paths,
// rsync output and driver text, so it belongs in the log only.
func TestAFailedImportStepDoesNotSurfaceTheUnderlyingError(t *testing.T) {
	hs := newImportHarness(t)
	request := fullImport(t)
	hs.imports.fail = errScripted

	w := httptest.NewRecorder()
	hs.h.Import(w, request)

	assertResponse(t, w, http.StatusInternalServerError, "could not transfer the database")
	if strings.Contains(w.Body.String(), errScripted.Error()) {
		t.Errorf("the response carries the underlying error: %s", w.Body)
	}
}

func mailInventory() Inventory {
	return Inventory{ArchiveRoot: "backup-demo", PrimaryDomain: "example.com", Mailboxes: []string{"info"}, AliasCount: 1, MailFiles: 1}
}

func mailExtras() archiveExtras {
	return archiveExtras{
		aliasMember: "backup-demo/va/example.com",
		members:     map[string][]byte{"backup-demo/va/example.com": []byte("sales: out@example.net\n")},
	}
}

// Each mailbox comes back with a fresh password, its messages are extracted in
// one tar call, and each forwarder is recreated.
func TestImportMailRecreatesMailboxesAndForwarders(t *testing.T) {
	hs := newImportHarness(t)
	commands := withCommands(t)
	archivePath := archiveFile(t, cpanelEntries()...)
	r := httptest.NewRequest(http.MethodPost, "/transfers/import", nil)

	creds, aliases, err := hs.h.importMail(r, archivePath, mailExtras(), mailInventory(), 9, "example.com", "c_example_com")
	assertErrText(t, err, "")
	if !reflect.DeepEqual(creds, []MailCredential{{Email: "info@example.com", Password: "pw-info"}}) || aliases != 1 {
		t.Fatalf("creds %+v, aliases %d", creds, aliases)
	}
	wantTar := []string{"tar", "-xz", "-f", "-", "-C", "/home/c_example_com/mail", "--strip-components=4", "backup-demo/homedir/mail/example.com/info"}
	if !commands.ran(wantTar...) || !commands.ran("chown", "-R", "c_example_com:c_example_com", "/home/c_example_com/mail") {
		t.Fatalf("commands = %q", commands.argvs())
	}
}

// An account with nothing to import makes no mail, and one without a primary
// domain creates its mailboxes but restores no messages and no forwarder.
func TestImportMailWithoutMailOrPrimaryDomain(t *testing.T) {
	hs := newImportHarness(t)
	commands := withCommands(t)
	r := httptest.NewRequest(http.MethodPost, "/transfers/import", nil)

	creds, aliases, err := hs.h.importMail(r, "", archiveExtras{}, Inventory{}, 9, "example.com", "c_example_com")
	if err != nil || !reflect.DeepEqual(creds, []MailCredential{}) || aliases != 0 {
		t.Fatalf("nothing to import = %+v, %d, %v", creds, aliases, err)
	}

	inv := mailInventory()
	inv.PrimaryDomain = ""
	creds, aliases, err = hs.h.importMail(r, "", mailExtras(), inv, 9, "example.com", "c_example_com")
	if err != nil || len(creds) != 1 || aliases != 0 || len(commands.argvs()) != 0 {
		t.Fatalf("no primary domain = %+v, %d, %v, commands %q", creds, aliases, err, commands.argvs())
	}
}

// Every mail step that fails is returned with the name it failed on.
func TestImportMailRefusals(t *testing.T) {
	cases := []struct {
		name   string
		breaks func(hs *importHarness)
		sk     string
		want   string
	}{
		{"no mail provider", func(hs *importHarness) { hs.h.Mail = nil }, "c_example_com", "mail provider is not ready"},
		{"a mail domain the server refuses", func(hs *importHarness) { setForTest(hs.t, &enableMailDomain, failingMail) }, "c_example_com", "scripted failure"},
		{"a mailbox the provider refuses", func(hs *importHarness) {
			setForTest(hs.t, &createMailbox, answerWith[mail.Handlers](http.StatusConflict, `{"error":"exists"}`))
		}, "c_example_com", `mailbox info: {"error":"exists"}`},
		{"a mailbox answer that is not JSON", func(hs *importHarness) {
			setForTest(hs.t, &createMailbox, answerWith[mail.Handlers](http.StatusCreated, "oops"))
		}, "c_example_com", "invalid character 'o' looking for beginning of value"},
		{"messages that cannot be restored", func(*importHarness) {}, "bad_user", "mailbox messages: unsafe target"},
		{"a forwarder the provider refuses", func(hs *importHarness) {
			setForTest(hs.t, &createMailAlias, answerWith[mail.Handlers](http.StatusBadRequest, "bad alias"))
		}, "c_example_com", "alias sales: bad alias"},
	}
	archivePath := archiveFile(t, cpanelEntries()...)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hs := newImportHarness(t)
			c.breaks(hs)
			r := httptest.NewRequest(http.MethodPost, "/transfers/import", nil)
			creds, aliases, err := hs.h.importMail(r, archivePath, mailExtras(), mailInventory(), 9, "example.com", c.sk)
			assertErrText(t, err, c.want)
			if creds != nil || aliases != 0 {
				t.Fatalf("a failed import returned %+v, %d", creds, aliases)
			}
		})
	}
}
