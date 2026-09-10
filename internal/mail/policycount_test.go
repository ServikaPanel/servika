package mail

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// A scripted driver with transaction support, because evaluateSendPolicy does
// all of its reading inside one BeginTx. The repository has no sqlmock
// dependency, and what has to be asserted is the VERDICT the policy server
// returns when one specific read fails.
type policyScript struct {
	mu   sync.Mutex
	rows map[string][]driver.Value
	fail map[string]error
}

func (s *policyScript) answer(query string) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, err := range s.fail {
		if strings.Contains(query, fragment) {
			return nil, err
		}
	}
	for fragment, values := range s.rows {
		if strings.Contains(query, fragment) {
			return &policyRows{values: values}, nil
		}
	}
	return nil, fmt.Errorf("the test script has no answer for: %s", query)
}

type policyRows struct {
	values []driver.Value
	done   bool
}

func (r *policyRows) Columns() []string { return make([]string, len(r.values)) }
func (r *policyRows) Close() error      { return nil }
func (r *policyRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

type policyConn struct{ script *policyScript }

func (c policyConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c policyConn) Driver() driver.Driver                        { return policyDriver{} }
func (c policyConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c policyConn) Close() error                                 { return nil }
func (c policyConn) Begin() (driver.Tx, error)                    { return policyTx{}, nil }

func (c policyConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.script.answer(query)
}

func (c policyConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return policyResult{}, nil
}

type policyTx struct{}

func (policyTx) Commit() error   { return nil }
func (policyTx) Rollback() error { return nil }

type policyResult struct{}

func (policyResult) LastInsertId() (int64, error) { return 1, nil }
func (policyResult) RowsAffected() (int64, error) { return 1, nil }

type policyDriver struct{}

func (policyDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

// clearPolicyScript answers every read the policy makes, with the mailbox well
// under both of its limits. A test then breaks exactly the read it is about.
func clearPolicyScript() *policyScript {
	return &policyScript{
		rows: map[string][]driver.Value{
			// Each fragment must match ONE query. A fragment shared by two of them
			// would be picked by map order, which is random, so the test would
			// answer a different query on every run.
			"FROM mailboxes WHERE email=?": {int64(1), int64(1), "active", int64(100), int64(1000)},
			"INTERVAL 1 HOUR":              {int64(1)},
			"INTERVAL 1 DAY":               {int64(1)},
			// Both server-wide ceilings are 0, so ceilingCount returns before it
			// queries and neither adds a second INTERVAL 1 HOUR read.
			"FROM mail_server_settings": {int64(50), int64(0), int64(0), ""},
		},
		fail: map[string]error{},
	}
}

func policyDB(t *testing.T, script *policyScript) *sql.DB {
	t.Helper()
	db := sql.OpenDB(policyConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func policyAttrs() map[string]string {
	return map[string]string{
		"sasl_username":   "box@example.com",
		"recipient_count": "1",
		"client_address":  "203.0.113.5",
	}
}

// The per-mailbox counts are the whole spam-protection layer: they decide
// whether a compromised mailbox is suspended. Discarded, both totals stayed at
// 0, the exceeded test could never be true, and mail kept flowing at any rate
// for as long as mail_send_log could not be read, which is exactly the state a
// mass-mailing burst against that table produces.
//
// DEFER retries; it does not bounce. The server-settings read 25 lines below
// already answers this way, and so does ceilingCount.
func TestAnUnreadableSendCountDefers(t *testing.T) {
	for _, window := range []string{"INTERVAL 1 HOUR", "INTERVAL 1 DAY"} {
		t.Run(window, func(t *testing.T) {
			script := clearPolicyScript()
			script.fail[window] = errors.New("lost connection to MySQL server during query")

			verdict := evaluateSendPolicy(policyDB(t, script), policyAttrs())
			if !strings.HasPrefix(verdict, "DEFER_IF_PERMIT 4.7.1") {
				t.Fatalf("verdict = %q, want a DEFER when the send count cannot be read", verdict)
			}
		})
	}
}

// The opposite direction, so the test above is not merely watching a guard that
// always defers: a mailbox under both of its limits is accepted.
func TestAMailboxUnderItsLimitsIsAccepted(t *testing.T) {
	verdict := evaluateSendPolicy(policyDB(t, clearPolicyScript()), policyAttrs())
	if verdict != "DUNNO" {
		t.Fatalf("verdict = %q, want DUNNO for a mailbox under its limits", verdict)
	}
}

// A mailbox over its hourly limit is still suspended, so the fail-closed change
// did not replace the ceiling with a permanent defer.
func TestAMailboxOverItsHourlyLimitIsSuspended(t *testing.T) {
	script := clearPolicyScript()
	script.rows["INTERVAL 1 HOUR"] = []driver.Value{int64(100)}

	verdict := evaluateSendPolicy(policyDB(t, script), policyAttrs())
	if !strings.HasPrefix(verdict, "REJECT 5.7.1") {
		t.Fatalf("verdict = %q, want a REJECT once the hourly limit is passed", verdict)
	}
}
