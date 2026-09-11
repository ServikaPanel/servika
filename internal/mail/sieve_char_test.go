package mail

import (
	"context"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"servika/internal/middleware"
)

const (
	sieveMailboxRead   = "FROM mailboxes m JOIN mail_domains md ON md.id=m.mail_domain_id"
	sieveFiltersRead   = "FROM mail_filters WHERE mailbox_id=? AND enabled=1"
	forwardingRead     = "SELECT destinations, keep_copy FROM mail_forwarding WHERE mailbox_id=?"
	sieveResponderRead = "SELECT enabled, subject_text, body_text, interval_days"
)

// withSieveAnswers answers the reads ApplyMailboxSieve makes for mailbox 2 with
// no filters, no forwarding and no responder.
func withSieveAnswers(s *sqlScript) *sqlScript {
	s.rows[sieveMailboxRead] = [][]driver.Value{{"/home/c_tenant/mail/example.com/info", "info@example.com", "c_tenant"}}
	s.rows[sieveFiltersRead] = nil
	s.rows[forwardingRead] = nil
	s.rows[sieveResponderRead] = nil
	return s
}

// sieveCapture records what ApplyMailboxSieve handed to the compile step.
type sieveCapture struct {
	home, rel, systemUser, script string
	calls                         int
}

func captureSieve(t *testing.T, result error) *sieveCapture {
	t.Helper()
	capture := &sieveCapture{}
	setForTest(t, &compileMailboxSieve, func(_ context.Context, home, rel string, script []byte, systemUser string) error {
		capture.home, capture.rel, capture.script, capture.systemUser = home, rel, string(script), systemUser
		capture.calls++
		return result
	})
	return capture
}

// The generated script, in full: the Junk rule, each filter in priority order,
// forwarding that keeps no copy, and the responder with its dot-stuffed body.
func TestApplyMailboxSieveGeneratesTheWholeScript(t *testing.T) {
	withLookPath(t, "sievec")
	capture := captureSieve(t, nil)
	script := withSieveAnswers(newScript())
	script.rows[sieveFiltersRead] = [][]driver.Value{
		{"from", "boss@example.com", "move", "Work"},
		{"subject", `sale "now"`, "redirect", "keep@example.net"},
		{"to", "old@", "discard", ""},
	}
	script.rows[forwardingRead] = [][]driver.Value{{"a@b.test,c@d.test", int64(0)}}
	script.rows[sieveResponderRead] = [][]driver.Value{{int64(1), "Away", "Back soon\n.line", int64(7)}}

	if err := ApplyMailboxSieve(context.Background(), scriptDB(t, script), 2); err != nil {
		t.Fatalf("ApplyMailboxSieve: %v", err)
	}
	want := `require ["fileinto", "vacation", "mailbox"];

# Move mail flagged by Rspamd into Junk.
if header :contains "X-Spam" "Yes" {
  fileinto :create "Junk";
  stop;
}

if header :contains "From" "boss@example.com" {
  fileinto :create "Work";
  stop;
}

if header :contains "Subject" "sale \"now\"" {
  redirect "keep@example.net";
  stop;
}

if header :contains "To" "old@" {
  discard;
  stop;
}

# Forwarding.
redirect "a@b.test";
redirect "c@d.test";
discard;

vacation :days 7 :subject "Away" text:
Back soon
..line
.
;
`
	if capture.script != want {
		t.Fatalf("script =\n%s\nwant\n%s", capture.script, want)
	}
	if capture.home != "/home/c_tenant" || capture.rel != "mail/example.com/info" || capture.systemUser != "c_tenant" {
		t.Fatalf("compiled into %q %q as %q", capture.home, capture.rel, capture.systemUser)
	}
}

// Forwarding that keeps a copy adds no discard, and a mailbox with nothing set
// gets only the Junk rule.
func TestApplyMailboxSieveLeavesOutWhatIsNotSet(t *testing.T) {
	cases := map[string]struct {
		setup   func(*sqlScript)
		has     []string
		hasNone []string
	}{
		"forwarding that keeps a copy": {func(s *sqlScript) { s.rows[forwardingRead] = [][]driver.Value{{"a@b.test", int64(1)}} },
			[]string{"redirect \"a@b.test\";\n"}, []string{"discard;", "vacation :days"}},
		"a disabled responder": {func(s *sqlScript) { s.rows[sieveResponderRead] = [][]driver.Value{{int64(0), "Away", "x", int64(7)}} },
			[]string{"stop;\n}\n"}, []string{"vacation :days", "# Forwarding."}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			withLookPath(t, "sievec")
			capture := captureSieve(t, nil)
			script := withSieveAnswers(newScript())
			c.setup(script)
			if err := ApplyMailboxSieve(context.Background(), scriptDB(t, script), 2); err != nil {
				t.Fatalf("ApplyMailboxSieve: %v", err)
			}
			assertScriptParts(t, capture.script, c.has, c.hasNone)
		})
	}
}

func assertScriptParts(t *testing.T, script string, has, hasNone []string) {
	t.Helper()
	for _, part := range has {
		if !strings.Contains(script, part) {
			t.Errorf("the script lacks %q:\n%s", part, script)
		}
	}
	for _, part := range hasNone {
		if strings.Contains(script, part) {
			t.Errorf("the script holds %q:\n%s", part, script)
		}
	}
}

// Every failure is returned before anything is compiled, and a compile failure
// is returned as it is.
func TestApplyMailboxSieveFailures(t *testing.T) {
	cases := map[string]func(*sqlScript){
		"the mailbox cannot be read": func(s *sqlScript) { s.fail[sieveMailboxRead] = errScripted },
		"the mailbox is outside its home": func(s *sqlScript) {
			s.rows[sieveMailboxRead] = [][]driver.Value{{"/var/vmail/info", "info@example.com", "c_tenant"}}
		},
		"the filters cannot be read":    func(s *sqlScript) { s.fail[sieveFiltersRead] = errScripted },
		"a filter row does not scan":    func(s *sqlScript) { s.rows[sieveFiltersRead] = [][]driver.Value{{"from", "x", "move"}} },
		"the filter read ends early":    func(s *sqlScript) { s.endWith[sieveFiltersRead] = errScripted },
		"the forwarding cannot be read": func(s *sqlScript) { s.fail[forwardingRead] = errScripted },
		"the responder cannot be read":  func(s *sqlScript) { s.fail[sieveResponderRead] = errScripted },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			withLookPath(t, "sievec")
			capture := captureSieve(t, nil)
			script := withSieveAnswers(newScript())
			setup(script)
			if err := ApplyMailboxSieve(context.Background(), scriptDB(t, script), 2); err == nil {
				t.Fatal("the failure was not returned")
			}
			if capture.calls != 0 {
				t.Fatal("a script was compiled after a failed read")
			}
		})
	}
}

// Without sievec nothing is read, and the sentinel the caller may show is
// returned; a compile failure comes back unchanged.
func TestApplyMailboxSieveWithoutACompilerAndWithAFailingOne(t *testing.T) {
	withLookPath(t)
	script := withSieveAnswers(newScript())
	if err := ApplyMailboxSieve(context.Background(), scriptDB(t, script), 2); !errors.Is(err, ErrSieveUnavailable) {
		t.Fatalf("err = %v, want ErrSieveUnavailable", err)
	}
	if script.stepIndex("SELECT") >= 0 {
		t.Fatal("a read ran without a compiler")
	}

	withLookPath(t, "sievec")
	captureSieve(t, errScripted)
	if err := ApplyMailboxSieve(context.Background(), scriptDB(t, withSieveAnswers(newScript())), 2); !errors.Is(err, errScripted) {
		t.Fatalf("err = %v, want the compile failure", err)
	}
}

const (
	responderOldRead = "SELECT enabled,subject_text,body_text,interval_days"
	responderSave    = "INSERT INTO mail_autoresponders(mailbox_id, domain_id, enabled, subject_text, body_text, interval_days)"
	responderRestore = "UPDATE mail_autoresponders SET enabled=?,subject_text=?,body_text=?,"
	responderRemove  = "DELETE FROM mail_autoresponders WHERE mailbox_id=?"
)

func responderScript() *sqlScript {
	s := withSieveAnswers(handlerScript())
	s.rows[responderOldRead] = [][]driver.Value{{int64(1), "Old", "Old body", int64(3)}}
	return s
}

func putResponder(t *testing.T, s *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := mailRequest(http.MethodPut, "/domains/1/mail/2/autoresponder", body, middleware.RoleUser,
		map[string]string{"id": "1", "mid": "2"})
	(&Handlers{DB: scriptDB(t, s)}).AutoresponderPut(recorder, request)
	return recorder
}

// Every refusal AutoresponderPut gives before the rules are applied.
func TestAutoresponderPutRefusals(t *testing.T) {
	const required = "subject and a message up to 10,000 characters are required"
	const interval = "reply interval must be 1-30 days"
	cases := []struct {
		name, body string
		setup      func(*sqlScript)
		status     int
		text       string
	}{
		{"an unknown domain", responderBody("Away", "x", 7), func(s *sqlScript) { s.rows[domainLookup] = nil }, http.StatusNotFound, "domain not found"},
		{"a body that is not JSON", `{`, noSetup, http.StatusBadRequest, "invalid request body"},
		{"a blank subject", responderBody(" ", "x", 7), noSetup, http.StatusBadRequest, required},
		{"a blank message", responderBody("Away", " ", 7), noSetup, http.StatusBadRequest, required},
		{"a subject past 255", responderBody(strings.Repeat("s", 256), "x", 7), noSetup, http.StatusBadRequest, required},
		{"a message past 10,000", responderBody("Away", strings.Repeat("b", 10001), 7), noSetup, http.StatusBadRequest, required},
		{"a zero interval", responderBody("Away", "x", 0), noSetup, http.StatusBadRequest, interval},
		{"an interval past 30", responderBody("Away", "x", 31), noSetup, http.StatusBadRequest, interval},
		{"a mailbox of another domain", responderBody("Away", "x", 7), func(s *sqlScript) { s.rows[mailboxOwned] = [][]driver.Value{{int64(0)}} }, http.StatusNotFound, "mailbox not found"},
		{"a save that fails", responderBody("Away", "x", 7), func(s *sqlScript) { s.fail[responderSave] = errScripted }, http.StatusInternalServerError, "could not save autoresponder"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withLookPath(t, "sievec")
			captureSieve(t, nil)
			script := responderScript()
			c.setup(script)
			assertAnswer(t, putResponder(t, script, c.body), c.status, c.text)
		})
	}
}

func responderBody(subject, body string, days int) string {
	return `{"enabled":true,"subject":` + quoteJSON(subject) + `,"body":` + quoteJSON(body) + `,"interval_days":` + itoa(days) + `}`
}

// A rule set that cannot be applied puts the previous responder back, or removes
// the new one when there was none, and says only what the caller may see.
func TestAutoresponderPutUndoesTheSaveWhenTheRulesCannotApply(t *testing.T) {
	t.Run("a previous responder is restored", func(t *testing.T) {
		withLookPath(t)
		script := responderScript()
		assertAnswer(t, putResponder(t, script, responderBody("Away", "Back soon", 7)), http.StatusServiceUnavailable, ErrSieveUnavailable.Error())
		want := []driver.Value{int64(1), "Old", "Old body", int64(3), int64(2)}
		if restore := script.onlyExec(t, responderRestore); !slices.Equal(restore.args, want) {
			t.Fatalf("restored %#v, want %#v", restore.args, want)
		}
	})
	t.Run("a new responder is removed", func(t *testing.T) {
		withLookPath(t)
		script := responderScript()
		script.rows[responderOldRead] = nil
		putResponder(t, script, responderBody("Away", "Back soon", 7))
		if remove := script.onlyExec(t, responderRemove); !slices.Equal(remove.args, []driver.Value{int64(2)}) {
			t.Fatalf("removed %#v", remove.args)
		}
	})
}

// A saved responder is written trimmed, compiled, and audited.
func TestAutoresponderPutSavesAndApplies(t *testing.T) {
	withLookPath(t, "sievec")
	capture := captureSieve(t, nil)
	script := responderScript()

	assertAnswer(t, putResponder(t, script, responderBody(" Away ", " Back soon ", 7)), http.StatusOK, `"ok":true`)
	want := []driver.Value{int64(2), int64(1), true, "Away", "Back soon", int64(7)}
	if save := script.onlyExec(t, responderSave); !slices.Equal(save.args, want) {
		t.Fatalf("saved %#v, want %#v", save.args, want)
	}
	if capture.calls != 1 || !slices.Equal(auditActions(script), []string{"mail.autoresponder.update"}) {
		t.Fatalf("compiled %d times, audit %v", capture.calls, auditActions(script))
	}
}
