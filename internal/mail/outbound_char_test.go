package mail

import (
	"context"
	"database/sql/driver"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"servika/internal/middleware"
)

const (
	poolEntryRead   = "SELECT enabled FROM mail_ip_pool WHERE ip=?"
	outboundSave    = "UPDATE mail_domains SET outbound_ip=? WHERE domain_id=?"
	mailDomainCount = "SELECT COUNT(*) FROM mail_domains WHERE domain_id=?"
	enabledPoolRead = "SELECT ip FROM mail_ip_pool WHERE enabled=1 ORDER BY ip"
	assignedRead    = "SELECT domain_name, outbound_ip FROM mail_domains"
)

func outboundScript() *sqlScript {
	s := handlerScript()
	s.rows[poolEntryRead] = [][]driver.Value{{int64(1)}}
	s.rows[mailDomainCount] = [][]driver.Value{{int64(1)}}
	return s
}

func putOutbound(t *testing.T, s *sqlScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := mailRequest(http.MethodPut, "/domains/1/mail/outbound-ip", body, middleware.RoleAdmin,
		map[string]string{"id": "1"})
	(&Handlers{DB: scriptDB(t, s)}).DomainOutboundPut(recorder, request)
	return recorder
}

// Every refusal DomainOutboundPut gives. Postfix is absent throughout, so a
// request that gets as far as the routing apply is refused there.
func TestDomainOutboundPutRefusals(t *testing.T) {
	const routing = "postfix rejected the routing and it was rolled back"
	const unsaved = "could not save the outbound address"
	const pooled = `{"ip":"203.0.113.5"}`
	cases := []struct {
		name, body string
		setup      func(*sqlScript)
		status     int
		text       string
	}{
		{"an unknown domain", pooled, func(s *sqlScript) { s.rows[domainLookup] = nil }, http.StatusNotFound, "domain not found"},
		{"a body that is not JSON", `{`, noSetup, http.StatusBadRequest, "invalid request body"},
		{"an address outside the pool", pooled, func(s *sqlScript) { s.rows[poolEntryRead] = nil }, http.StatusBadRequest, "that address is not in the pool"},
		{"a disabled address", pooled, func(s *sqlScript) { s.rows[poolEntryRead] = [][]driver.Value{{int64(0)}} }, http.StatusBadRequest, "that address is disabled"},
		{"a save that fails", pooled, func(s *sqlScript) { s.fail[outboundSave] = errScripted }, http.StatusInternalServerError, unsaved},
		{"a changed-row count that cannot be read", pooled, func(s *sqlScript) { s.affectedFail[outboundSave] = errScripted }, http.StatusInternalServerError, unsaved},
		{"a domain without mail", pooled, func(s *sqlScript) {
			s.affected[outboundSave] = 0
			s.rows[mailDomainCount] = [][]driver.Value{{int64(0)}}
		}, http.StatusBadRequest, "enable mail for this domain first"},
		{"an unchanged address still applies", pooled, func(s *sqlScript) { s.affected[outboundSave] = 0 }, http.StatusInternalServerError, routing},
		{"the server default skips the pool", `{"ip":" "}`, func(s *sqlScript) { s.rows[poolEntryRead] = nil }, http.StatusInternalServerError, routing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withLookPath(t)
			script := outboundScript()
			c.setup(script)
			assertAnswer(t, putOutbound(t, script, c.body), c.status, c.text)
		})
	}
}

// A domain moved onto a pool address gets a bound transport in master.cf and a
// line in the sender table, and Postfix is asked to accept both.
func TestDomainOutboundPutRewritesTheRouting(t *testing.T) {
	dir := t.TempDir()
	setForTest(t, &masterConfigPath, filepath.Join(dir, "master.cf"))
	setForTest(t, &senderTransportPath, filepath.Join(dir, "sender_transport"))
	if err := os.WriteFile(masterConfigPath, []byte("smtp inet n - n - - smtpd\n"), 0o644); err != nil {
		t.Fatalf("write master.cf: %v", err)
	}
	withLookPath(t, "postconf")
	calls := stubPostfix(t, func(string, ...string) ([]byte, error) { return nil, nil })
	script := outboundScript()
	script.rows[enabledPoolRead] = [][]driver.Value{{"203.0.113.5"}}
	script.rows[assignedRead] = [][]driver.Value{{"example.com", "203.0.113.5"}}

	assertAnswer(t, putOutbound(t, script, `{"ip":" 203.0.113.5 "}`), http.StatusOK, `"ip":"203.0.113.5"`)

	if save := script.onlyExec(t, outboundSave); !slices.Equal(save.args, []driver.Value{"203.0.113.5", int64(1)}) {
		t.Fatalf("saved %#v", save.args)
	}
	assertRoutingWritten(t, *calls)
	if actions := auditActions(script); !slices.Equal(actions, []string{"mail.outbound_ip.update"}) {
		t.Fatalf("audit actions = %v", actions)
	}
}

func assertRoutingWritten(t *testing.T, calls []string) {
	t.Helper()
	master, err := os.ReadFile(masterConfigPath)
	if err != nil || !strings.Contains(string(master), "servika_out_203_0_113_5 unix - - n - - smtp") {
		t.Fatalf("master.cf = %q (%v)", master, err)
	}
	table, err := os.ReadFile(senderTransportPath)
	if err != nil || !strings.Contains(string(table), "@example.com\tservika_out_203_0_113_5\n") {
		t.Fatalf("sender table = %q (%v)", table, err)
	}
	want := []string{
		"postmap " + senderTransportPath,
		"postconf -e sender_dependent_default_transport_maps=hash:" + senderTransportPath,
		"postfix check",
		"postfix reload",
	}
	if !slices.Equal(calls, want) {
		t.Fatalf("postfix calls = %q, want %q", calls, want)
	}
}

// Only an enabled, parseable address makes a transport, and only a plain domain
// pointing at one gets a sender line.
func TestPoolAddressesForRoutingKeepsOnlyUsableEntries(t *testing.T) {
	script := newScript()
	script.rows[enabledPoolRead] = [][]driver.Value{{"203.0.113.5"}, {"not-an-ip"}}
	script.rows[assignedRead] = [][]driver.Value{
		{"example.com", "203.0.113.5"}, {"gone.example", "198.51.100.9"}, {"not a domain", "203.0.113.5"},
	}
	addresses, assignments, err := poolAddressesForRouting(context.Background(), scriptDB(t, script))
	if err != nil {
		t.Fatalf("poolAddressesForRouting: %v", err)
	}
	if !slices.Equal(addresses, []string{"203.0.113.5"}) {
		t.Errorf("addresses = %v", addresses)
	}
	if want := map[string]string{"example.com": "203.0.113.5"}; !maps.Equal(assignments, want) {
		t.Errorf("assignments = %v, want %v", assignments, want)
	}
}

// Every read failure is returned rather than producing a partial configuration.
func TestPoolAddressesForRoutingFailures(t *testing.T) {
	cases := map[string]func(*sqlScript){
		"the pool read fails":             func(s *sqlScript) { s.fail[enabledPoolRead] = errScripted },
		"a pool row does not scan":        func(s *sqlScript) { s.rows[enabledPoolRead] = [][]driver.Value{{"a", "b"}} },
		"the pool read ends early":        func(s *sqlScript) { s.endWith[enabledPoolRead] = errScripted },
		"the assignment read fails":       func(s *sqlScript) { s.fail[assignedRead] = errScripted },
		"an assignment row does not scan": func(s *sqlScript) { s.rows[assignedRead] = [][]driver.Value{{"example.com"}} },
		"the assignment read ends early":  func(s *sqlScript) { s.endWith[assignedRead] = errScripted },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			script := newScript()
			script.rows[enabledPoolRead] = [][]driver.Value{{"203.0.113.5"}}
			script.rows[assignedRead] = [][]driver.Value{{"example.com", "203.0.113.5"}}
			setup(script)
			if _, _, err := poolAddressesForRouting(context.Background(), scriptDB(t, script)); err == nil {
				t.Fatal("the failure was not returned")
			}
		})
	}
}
