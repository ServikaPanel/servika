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
	activeMailDomain = "SELECT id, domain_name, maildir_root, system_user FROM mail_domains WHERE domain_id=? AND status='active'"
	customerOfDomain = "SELECT customer_id FROM domains WHERE id=?"
	planOfCustomer   = "SELECT plan_id FROM customers WHERE id=?"
	planMaxEmail     = "SELECT max_email FROM service_plans WHERE id=?"
	customerBoxCount = "SELECT COUNT(*) FROM mailboxes m JOIN domains d"
	mailboxInsert    = "INSERT INTO mailboxes(domain_id, mail_domain_id, local_part"
)

// createScript answers every read Create makes for a domain whose customer is two
// mailboxes into a plan of ten, with the plan's mail limits set.
func createScript() *sqlScript {
	s := handlerScript()
	s.rows[activeMailDomain] = [][]driver.Value{{int64(4), "example.com", "/home/c_tenant/mail", "c_tenant"}}
	s.rows[customerOfDomain] = [][]driver.Value{{int64(11)}}
	s.rows[planOfCustomer] = [][]driver.Value{{int64(21)}}
	s.rows[planMaxEmail] = [][]driver.Value{{int64(10)}}
	s.rows[customerBoxCount] = [][]driver.Value{{int64(2)}}
	s.rows[planLimitsRead] = [][]driver.Value{{int64(50), int64(100), int64(1000)}}
	s.insertID = 31
	return s
}

// withOpenSSL answers the password hash with a fixed SHA512-CRYPT value, or with
// a failure.
func withOpenSSL(t *testing.T, exitCode int) *commandRecorder {
	t.Helper()
	return withCommandScript(t, func([]string) (string, int) { return "$6$salt$hash\n", exitCode })
}

func createMailbox(t *testing.T, s *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := mailRequest(http.MethodPost, "/domains/1/mail", body, middleware.RoleUser, map[string]string{"id": "1"})
	(&Handlers{DB: scriptDB(t, s)}).Create(recorder, request)
	return recorder
}

// Every refusal Create gives, with the status and the text a caller sees.
func TestCreateMailboxRefusals(t *testing.T) {
	const fine = `{"local_part":"info","password":"secret-pass"}`
	cases := []struct {
		name, body string
		setup      func(*sqlScript, *maildirFake)
		exitCode   int
		status     int
		text       string
	}{
		{"an unknown domain", fine, func(s *sqlScript, _ *maildirFake) { s.rows[domainLookup] = nil }, 0, http.StatusNotFound, "domain not found"},
		{"a body that is not JSON", `{`, noCreateSetup, 0, http.StatusBadRequest, "invalid request body"},
		{"a name that is not a local part", `{"local_part":"-bad"}`, noCreateSetup, 0, http.StatusBadRequest, "invalid mailbox name"},
		{"a password with a line break", `{"local_part":"info","password":"a\nb"}`, noCreateSetup, 0, http.StatusBadRequest, "password contains invalid characters"},
		{"a domain without mail", fine, func(s *sqlScript, _ *maildirFake) { s.rows[activeMailDomain] = nil }, 0, http.StatusBadRequest, "enable mail for this domain first"},
		{"a mail domain that cannot be read", fine, func(s *sqlScript, _ *maildirFake) { s.fail[activeMailDomain] = errScripted }, 0, http.StatusInternalServerError, "could not read mail domain"},
		{"a plan that is full", fine, func(s *sqlScript, _ *maildirFake) { s.rows[customerBoxCount] = [][]driver.Value{{int64(10)}} }, 0, http.StatusForbidden, "plan limit exceeded: maximum 10 mailboxes"},
		{"a plan that cannot be read", fine, func(s *sqlScript, _ *maildirFake) { s.fail[planOfCustomer] = errScripted }, 0, http.StatusInternalServerError, "could not verify plan limit"},
		{"a hash that fails", fine, noCreateSetup, 1, http.StatusInternalServerError, "could not prepare mailbox password"},
		{"storage that cannot be created", fine, func(_ *sqlScript, f *maildirFake) { f.failMkdir = errScripted }, 0, http.StatusInternalServerError, "could not create mailbox storage"},
		{"an insert that fails", fine, func(s *sqlScript, _ *maildirFake) { s.fail[mailboxInsert] = errScripted }, 0, http.StatusConflict, "mailbox already exists or could not be created"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withOpenSSL(t, c.exitCode)
			fake := withMaildirFake(t)
			script := createScript()
			c.setup(script, fake)
			assertAnswer(t, createMailbox(t, script, c.body), c.status, c.text)
		})
	}
}

func noCreateSetup(*sqlScript, *maildirFake) {}

// A created mailbox gets its Maildir inside the tenant home, the hash openssl
// produced, and the plan's quota and send limits on its row.
func TestCreateMailboxWritesTheStoreAndTheRow(t *testing.T) {
	commands := withOpenSSL(t, 0)
	fake := withMaildirFake(t)
	script := createScript()

	recorder := createMailbox(t, script, `{"local_part":" Info ","password":"secret-pass"}`)
	assertAnswer(t, recorder, http.StatusCreated, `"email":"info@example.com"`)
	if body := jsonBody(t, recorder); body["id"] != float64(31) || body["password"] != "secret-pass" {
		t.Fatalf("answer = %v", body)
	}
	want := []driver.Value{int64(1), int64(4), "info", "info@example.com", "$6$salt$hash",
		"/home/c_tenant/mail/example.com/info/", int64(52428800), int64(100), int64(100), int64(1000), int64(1000)}
	if insert := script.onlyExec(t, mailboxInsert); !slices.Equal(insert.args, want) {
		t.Fatalf("inserted %#v, want %#v", insert.args, want)
	}
	wantStore := []string{
		"mkdir /home/c_tenant mail/example.com/info c_tenant",
		"chmod /home/c_tenant mail/example.com/info 700",
		"restorecon /home/c_tenant mail/example.com/info",
	}
	if !slices.Equal(fake.recorded(), wantStore) {
		t.Fatalf("store calls = %q, want %q", fake.recorded(), wantStore)
	}
	if argv := commands.argvs(); len(argv) != 1 || !slices.Equal(argv[0], []string{opensslBin, "passwd", "-6", "-stdin"}) {
		t.Fatalf("commands = %q", argv)
	}
}

// An empty password is replaced with a generated one, which the answer carries.
func TestCreateMailboxGeneratesAPassword(t *testing.T) {
	withOpenSSL(t, 0)
	withMaildirFake(t)
	recorder := createMailbox(t, createScript(), `{"local_part":"info"}`)
	assertAnswer(t, recorder, http.StatusCreated, `"password":"`)
	if password, _ := jsonBody(t, recorder)["password"].(string); len(password) != 20 {
		t.Fatalf("generated password %q is not 20 characters", password)
	}
}
