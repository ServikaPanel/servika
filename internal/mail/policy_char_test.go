package mail

import (
	"database/sql/driver"
	"testing"
)

const (
	mailboxForUpdate = "FROM mailboxes WHERE email=? FOR UPDATE"
	dailySendCount   = "mailbox_id=? AND ok=1 AND ts >= NOW()-INTERVAL 1 DAY"
	serverSettings   = "FROM mail_server_settings WHERE id = 1"
	domainSendCount  = "WHERE domain_id=? AND ok=1"
	clientSendCount  = "WHERE client_ip=? AND ok=1"
	acceptedSendLog  = "VALUES(?,?,1,?,?)"
	refusedSendLog   = "VALUES(?,?,0,?,?)"
)

// policyAnswers answers every read evaluateSendPolicy makes for mailbox 3 on domain
// 1, under both of its limits, with both server-wide ceilings off.
func policyAnswers() *sqlScript {
	s := newScript()
	s.rows[mailboxForUpdate] = [][]driver.Value{{int64(3), int64(1), "active", int64(100), int64(1000)}}
	s.rows["mailbox_id=? AND ok=1 AND ts >= NOW()-INTERVAL 1 HOUR"] = [][]driver.Value{{int64(1)}}
	s.rows[dailySendCount] = [][]driver.Value{{int64(1)}}
	s.rows[serverSettings] = [][]driver.Value{{int64(0), int64(0), int64(0), ""}}
	s.rows[domainSendCount] = [][]driver.Value{{int64(0)}}
	s.rows[clientSendCount] = [][]driver.Value{{int64(0)}}
	return s
}

// The policy answers Postfix for every outgoing message, so each verdict is
// pinned to the read or the write that produces it.
func TestTheSendPolicyVerdicts(t *testing.T) {
	cases := []struct {
		name  string
		setup func(s *sqlScript, attrs map[string]string)
		want  string
		check func(t *testing.T, s *sqlScript)
	}{
		{"a zero recipient count counts as one", func(_ *sqlScript, a map[string]string) { a["recipient_count"] = "0" },
			"DUNNO", loggedArgument(2, int64(1))},
		{"an address that is not an IP is not recorded", func(_ *sqlScript, a map[string]string) { a["client_address"] = "not-an-ip" },
			"DUNNO", loggedArgument(3, "")},
		{"a transaction that cannot open leaves the mail alone", func(s *sqlScript, _ map[string]string) { s.failBegin = errScripted },
			"DUNNO", noStep("FOR UPDATE")},
		{"an unknown sender is left to the next restriction", func(s *sqlScript, _ map[string]string) { s.rows[mailboxForUpdate] = nil },
			"DUNNO", noStep("INSERT INTO mail_send_log")},
		{"an inactive mailbox is refused", setMailboxStatus("suspended"),
			"REJECT 5.7.1 Mail account is not active", noStep("INSERT INTO mail_send_log")},
		{"unreadable server settings defer", func(s *sqlScript, _ map[string]string) { s.fail[serverSettings] = errScripted },
			"DEFER_IF_PERMIT 4.7.1 Send policy is temporarily unavailable", noStep("INSERT INTO mail_send_log")},
		{"the domain ceiling defers", setCeilings(5, 0, domainSendCount),
			"DEFER_IF_PERMIT 4.7.1 Domain hourly send limit reached; try again later", noStep("SET status='suspended'")},
		{"the connection ceiling defers", setCeilings(0, 5, clientSendCount),
			"DEFER_IF_PERMIT 4.7.1 Hourly send limit for this connection reached; try again later", noStep("SET status='suspended'")},
		{"a log row that cannot be written leaves the mail alone", func(s *sqlScript, _ map[string]string) { s.fail[acceptedSendLog] = errScripted },
			"DUNNO", noStep("COMMIT")},
		{"a commit that fails leaves the mail alone", func(s *sqlScript, _ map[string]string) { s.failCommit = errScripted },
			"DUNNO", stepsInOrder(acceptedSendLog, "COMMIT")},
		{"a mailbox over its daily limit is suspended", func(s *sqlScript, _ map[string]string) { s.rows[dailySendCount] = [][]driver.Value{{int64(1000)}} },
			"REJECT 5.7.1 Send limit exceeded; account suspended for security", suspendedAndLogged},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			script, attrs := policyAnswers(), policyAttrs()
			c.setup(script, attrs)
			if got := evaluateSendPolicy(scriptDB(t, script), attrs); got != c.want {
				t.Fatalf("verdict = %q, want %q", got, c.want)
			}
			c.check(t, script)
		})
	}
}

func setMailboxStatus(status string) func(*sqlScript, map[string]string) {
	return func(s *sqlScript, _ map[string]string) {
		s.rows[mailboxForUpdate] = [][]driver.Value{{int64(3), int64(1), status, int64(100), int64(1000)}}
	}
}

// setCeilings turns the server-wide ceilings on and puts the counted query at the
// ceiling, so one more recipient passes it.
func setCeilings(domain, client int64, counted string) func(*sqlScript, map[string]string) {
	return func(s *sqlScript, _ map[string]string) {
		s.rows[serverSettings] = [][]driver.Value{{int64(0), domain, client, ""}}
		s.rows[counted] = [][]driver.Value{{int64(5)}}
	}
}

func loggedArgument(index int, want driver.Value) func(*testing.T, *sqlScript) {
	return func(t *testing.T, s *sqlScript) {
		t.Helper()
		if got := s.onlyExec(t, acceptedSendLog).args[index]; got != want {
			t.Fatalf("logged argument %d = %#v, want %#v", index, got, want)
		}
	}
}

func noStep(fragment string) func(*testing.T, *sqlScript) {
	return func(t *testing.T, s *sqlScript) {
		t.Helper()
		if s.stepIndex(fragment) >= 0 {
			t.Fatalf("a step holding %q ran", fragment)
		}
	}
}

func stepsInOrder(first, second string) func(*testing.T, *sqlScript) {
	return func(t *testing.T, s *sqlScript) {
		t.Helper()
		a, b := s.stepIndex(first), s.stepIndex(second)
		if a < 0 || b < 0 || a > b {
			t.Fatalf("steps %q (%d) and %q (%d) did not run in that order", first, a, second, b)
		}
	}
}

func suspendedAndLogged(t *testing.T, s *sqlScript) {
	t.Helper()
	if suspend := s.onlyExec(t, "SET status='suspended', spam_suspended_at=NOW() WHERE id=?"); suspend.args[0] != int64(3) {
		t.Fatalf("suspended mailbox = %#v, want 3", suspend.args[0])
	}
	if refused := s.onlyExec(t, refusedSendLog); refused.args[2] != int64(1) || refused.args[3] != "203.0.113.5" {
		t.Fatalf("refused log row = %#v", refused.args)
	}
	stepsInOrder(refusedSendLog, "COMMIT")(t, s)
}
