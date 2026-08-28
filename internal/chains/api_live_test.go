package chains

// Live-database tests for the entry (Initial Access) stage. Skipped without
// SERVIKA_TEST_DSN.

import (
	"database/sql"
	"testing"

	"servika/internal/middleware"
)

const custUserA = 970003 // the customer user that owns domainA in these tests

func apiClean(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []struct {
		q    string
		args []any
	}{
		{`DELETE FROM audit_log WHERE actor_username='victim'`, nil},
		{`DELETE FROM av_events WHERE domain_id=? OR actor_user_id=?`, []any{domainA, custUserA}},
		{`DELETE FROM av_chains WHERE domain_id=?`, []any{domainA}},
		{`DELETE FROM domains WHERE id=?`, []any{domainA}},
		{`DELETE FROM customers WHERE id=?`, []any{customerA}},
	}
	for _, s := range stmts {
		if _, err := db.Exec(s.q, s.args...); err != nil {
			t.Fatalf("api clean %q: %v", s.q, err)
		}
	}
}

func floodAudit(t *testing.T, db *sql.DB, n int, withSuccess bool) {
	t.Helper()
	for range n {
		if _, err := db.Exec(`INSERT INTO audit_log (actor_user_id, actor_username, ip, action, ok, ts)
			VALUES (0, 'victim', '203.0.113.7', 'auth.login', 0, NOW() - INTERVAL 3 SECOND)`); err != nil {
			t.Fatalf("insert fail row: %v", err)
		}
	}
	if withSuccess {
		if _, err := db.Exec(`INSERT INTO audit_log (actor_user_id, actor_username, ip, action, ok, ts)
			VALUES (?, 'victim', '203.0.113.7', 'auth.login', 1, NOW() - INTERVAL 1 SECOND)`, custUserA); err != nil {
			t.Fatalf("insert success row: %v", err)
		}
	}
}

func entryCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM av_events WHERE stage='entry' AND actor_user_id=?`, custUserA).Scan(&n); err != nil {
		t.Fatalf("count entries: %v", err)
	}
	return n
}

// A failed flood WITHOUT a subsequent success is not a brute-force success: a bot
// hammering a stale password never earns an entry. A flood followed by a success
// does.
func TestApiScanNeedsASuccess(t *testing.T) {
	db := liveDB(t)
	apiClean(t, db)
	t.Cleanup(func() { apiClean(t, db) })

	floodAudit(t, db, entryThreshold, false)
	apiScan(db)
	if n := entryCount(t, db); n != 0 {
		t.Fatalf("a failed flood alone wrote %d entries, want 0", n)
	}

	floodAudit(t, db, entryThreshold, true)
	apiScan(db)
	if n := entryCount(t, db); n != 1 {
		t.Fatalf("a flood then a success wrote %d entries, want 1", n)
	}
}

// The same account's entry is not written twice inside the re-dedup window.
func TestApiScanDedups(t *testing.T) {
	db := liveDB(t)
	apiClean(t, db)
	t.Cleanup(func() { apiClean(t, db) })

	floodAudit(t, db, entryThreshold, true)
	apiScan(db)
	apiScan(db)
	if n := entryCount(t, db); n != 1 {
		t.Fatalf("the entry was written %d times, want 1 (dedup)", n)
	}
}

// An entry event completes a chain: entry > file_write > execution, three ordered
// distinct stages, is a critical chain at confidence 75.
func TestEntryCompletesTheChain(t *testing.T) {
	db := liveDB(t)
	apiClean(t, db)
	t.Cleanup(func() { apiClean(t, db) })

	exec := func(q string, a ...any) {
		if _, err := db.Exec(q, a...); err != nil {
			t.Fatalf("fixture %q: %v", q, err)
		}
	}
	exec(`INSERT INTO customers (id, name, email, owner_user_id, user_id) VALUES (?,?,?,?,?)`,
		customerA, "A", "a@x", resellerA, custUserA)
	exec(`INSERT INTO domains (id, domain_name, system_user, customer_id) VALUES (?,?,?,?)`,
		domainA, "a.example", "c_a", customerA)
	exec(`INSERT INTO av_events (domain_id, actor_user_id, source, stage, level, summary, path, pid, created_at)
		VALUES (NULL, ?, 'api', 'entry', 'warning', 'brute force', '', 0, NOW() - INTERVAL 3 SECOND)`, custUserA)
	exec(`INSERT INTO av_events (domain_id, source, stage, level, summary, path, pid, created_at)
		VALUES (?, 'file', 'file_write', 'critical', 'shell.php', '/home/c_a/public_html/shell.php', 0, NOW() - INTERVAL 2 SECOND)`, domainA)
	exec(`INSERT INTO av_events (domain_id, source, stage, level, summary, path, pid, created_at)
		VALUES (?, 'process', 'execution', 'critical', '', '/tmp/x', 4242, NOW() - INTERVAL 1 SECOND)`, domainA)

	if err := Run(db); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var stages string
	var confidence int
	if err := db.QueryRow(`SELECT stages, confidence FROM av_chains WHERE domain_id=?`, domainA).
		Scan(&stages, &confidence); err != nil {
		t.Fatalf("no chain written: %v", err)
	}
	if stages != "entry>file_write>execution" {
		t.Fatalf("stages = %q, want entry>file_write>execution", stages)
	}
	if confidence != 75 {
		t.Fatalf("confidence = %d, want 75 (70 + 5 ordered)", confidence)
	}
}

// The endpoint hides the entry event from a customer (a login attack is
// account-level), while the owning reseller sees it.
func TestEndpointHidesEntryFromCustomer(t *testing.T) {
	db := liveDB(t)
	apiClean(t, db)
	t.Cleanup(func() { apiClean(t, db) })

	exec := func(q string, a ...any) {
		if _, err := db.Exec(q, a...); err != nil {
			t.Fatalf("fixture %q: %v", q, err)
		}
	}
	exec(`INSERT INTO customers (id, name, email, owner_user_id, user_id) VALUES (?,?,?,?,?)`,
		customerA, "A", "a@x", resellerA, custUserA)
	exec(`INSERT INTO domains (id, domain_name, system_user, customer_id) VALUES (?,?,?,?)`,
		domainA, "a.example", "c_a", customerA)
	exec(`INSERT INTO av_chains (domain_id, stages, confidence, level, event_count, signature) VALUES (?,?,?,?,?,?)`,
		domainA, "entry>file_write>execution", 75, "critical", 3, "sigEntry")
	exec(`INSERT INTO av_events (domain_id, actor_user_id, source, stage, level, summary, path, pid) VALUES (NULL, ?, 'api', 'entry', 'warning', 'brute force', '', 0)`, custUserA)
	exec(`INSERT INTO av_events (domain_id, source, stage, level, summary, path, pid) VALUES (?, 'file', 'file_write', 'critical', 'shell.php', '/home/c_a/public_html/shell.php', 0)`, domainA)

	h := &Handlers{DB: db}

	// The customer owns the domain, so they see the chain, but not the entry event.
	cust := listAs(t, h, middleware.RoleUser, custUserA)
	if len(cust) != 1 {
		t.Fatalf("the customer saw %d chains, want 1", len(cust))
	}
	if hasEntry(cust[0].Events) {
		t.Fatalf("the customer saw the entry event, want it hidden")
	}
	// The owning reseller sees the entry event.
	res := listAs(t, h, middleware.RoleReseller, resellerA)
	if len(res) != 1 || !hasEntry(res[0].Events) {
		t.Fatalf("the reseller did not see the entry event: %+v", res)
	}
}

func hasEntry(events []EventDTO) bool {
	for _, e := range events {
		if e.Stage == "entry" {
			return true
		}
	}
	return false
}
