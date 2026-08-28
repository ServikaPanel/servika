package chains

// Live-database test for the list endpoint's scope. Skipped without
// SERVIKA_TEST_DSN. It proves the ownership-chain narrowing end to end: an admin
// sees every chain including the panel-wide (NULL domain_id) one, while a
// reseller sees only chains on a domain they own and never the panel-wide one.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"
)

const (
	resellerA = 970001
	resellerB = 970002
	customerA = 980001
	customerB = 980002
	domainA   = 990001
	domainB   = 990002
)

func TestListScopesChainsToTheCaller(t *testing.T) {
	db := liveDB(t)
	scopeClean(t, db)
	t.Cleanup(func() { scopeClean(t, db) })

	exec := func(q string, a ...any) {
		if _, err := db.Exec(q, a...); err != nil {
			t.Fatalf("fixture %q: %v", q, err)
		}
	}
	exec(`INSERT INTO customers (id, name, email, owner_user_id) VALUES (?,?,?,?)`, customerA, "A", "a@x", resellerA)
	exec(`INSERT INTO customers (id, name, email, owner_user_id) VALUES (?,?,?,?)`, customerB, "B", "b@x", resellerB)
	exec(`INSERT INTO domains (id, domain_name, system_user, customer_id) VALUES (?,?,?,?)`, domainA, "a.example", "c_a", customerA)
	exec(`INSERT INTO domains (id, domain_name, system_user, customer_id) VALUES (?,?,?,?)`, domainB, "b.example", "c_b", customerB)
	exec(`INSERT INTO av_chains (domain_id, stages, confidence, level, event_count, signature) VALUES (?,?,?,?,?,?)`,
		domainA, "file_write>execution", 85, "critical", 2, "sigA")
	exec(`INSERT INTO av_chains (domain_id, stages, confidence, level, event_count, signature) VALUES (?,?,?,?,?,?)`,
		domainB, "file_write>execution", 60, "warning", 2, "sigB")
	exec(`INSERT INTO av_chains (domain_id, stages, confidence, level, event_count, signature) VALUES (?,?,?,?,?,?)`,
		nil, "execution>c2", 70, "warning", 2, "sigNull")

	h := &Handlers{DB: db}

	// Admin sees all three, including the panel-wide NULL-domain chain.
	if got := listAs(t, h, middleware.RoleAdmin, 0); len(got) != 3 {
		t.Fatalf("admin saw %d chains, want 3 (both domains + panel-wide)", len(got))
	}
	// Reseller A sees only their own domain's chain, never the neighbour's or the
	// panel-wide one.
	a := listAs(t, h, middleware.RoleReseller, resellerA)
	if len(a) != 1 || a[0].Domain != "a.example" {
		t.Fatalf("reseller A saw %+v, want only a.example", a)
	}
	b := listAs(t, h, middleware.RoleReseller, resellerB)
	if len(b) != 1 || b[0].Domain != "b.example" {
		t.Fatalf("reseller B saw %+v, want only b.example", b)
	}
}

func listAs(t *testing.T, h *Handlers, role string, userID int64) []ChainDTO {
	t.Helper()
	r := reqAs(role, userID)
	rec := httptest.NewRecorder()
	h.List(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("list as %s: status %d", role, rec.Code)
	}
	var body struct {
		Chains []ChainDTO `json:"chains"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body.Chains
}

func scopeClean(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []struct {
		q    string
		args []any
	}{
		{`DELETE FROM av_events WHERE domain_id IN (?,?)`, []any{domainA, domainB}},
		{`DELETE FROM av_chains WHERE domain_id IN (?,?) OR signature='sigNull'`, []any{domainA, domainB}},
		{`DELETE FROM domains WHERE id IN (?,?)`, []any{domainA, domainB}},
		{`DELETE FROM customers WHERE id IN (?,?)`, []any{customerA, customerB}},
	}
	for _, s := range stmts {
		if _, err := db.Exec(s.q, s.args...); err != nil {
			t.Fatalf("scope clean: %v", err)
		}
	}
}

// After a domain is transferred to another reseller, the old owner must see
// neither the chain nor its events. The chain disappears from the outer scoped
// query (scope is resolved live from the ownership chain, not a stored snapshot),
// and chainEvents is independently scoped, so it cannot leak the new owner's
// events to the old one either.
func TestTransferHidesTheChainFromTheOldOwner(t *testing.T) {
	db := liveDB(t)
	scopeClean(t, db)
	t.Cleanup(func() { scopeClean(t, db) })

	exec := func(q string, a ...any) {
		if _, err := db.Exec(q, a...); err != nil {
			t.Fatalf("fixture %q: %v", q, err)
		}
	}
	exec(`INSERT INTO customers (id, name, email, owner_user_id) VALUES (?,?,?,?)`, customerA, "A", "a@x", resellerA)
	exec(`INSERT INTO domains (id, domain_name, system_user, customer_id) VALUES (?,?,?,?)`, domainA, "a.example", "c_a", customerA)
	exec(`INSERT INTO av_chains (domain_id, stages, confidence, level, event_count, signature) VALUES (?,?,?,?,?,?)`,
		domainA, "file_write>execution", 85, "critical", 2, "sigA")
	exec(`INSERT INTO av_events (domain_id, source, stage, level, summary, path, pid) VALUES (?,?,?,?,?,?,?)`,
		domainA, "file", "file_write", "critical", "shell.php", "/home/c_a/public_html/shell.php", 0)

	h := &Handlers{DB: db}

	// Before transfer: reseller A sees the chain with its event.
	before := listAs(t, h, middleware.RoleReseller, resellerA)
	if len(before) != 1 || len(before[0].Events) != 1 {
		t.Fatalf("before transfer, reseller A saw %+v, want 1 chain with 1 event", before)
	}

	// Transfer the domain to reseller B.
	exec(`UPDATE customers SET owner_user_id=? WHERE id=?`, resellerB, customerA)

	// After transfer: the old owner A sees nothing; the new owner B sees the chain.
	if a := listAs(t, h, middleware.RoleReseller, resellerA); len(a) != 0 {
		t.Fatalf("after transfer, the old owner still saw %+v, want nothing", a)
	}
	b := listAs(t, h, middleware.RoleReseller, resellerB)
	if len(b) != 1 || len(b[0].Events) != 1 {
		t.Fatalf("after transfer, the new owner saw %+v, want 1 chain with 1 event", b)
	}
}

// chainEvents scopes by the caller's own condition, so calling it for a domain
// the caller does NOT own returns nothing even though events exist for it. This
// proves the events-query scoping is not vacuous.
func TestChainEventsIsScopedIndependently(t *testing.T) {
	db := liveDB(t)
	scopeClean(t, db)
	t.Cleanup(func() { scopeClean(t, db) })

	exec := func(q string, a ...any) {
		if _, err := db.Exec(q, a...); err != nil {
			t.Fatalf("fixture %q: %v", q, err)
		}
	}
	exec(`INSERT INTO customers (id, name, email, owner_user_id) VALUES (?,?,?,?)`, customerA, "A", "a@x", resellerA)
	exec(`INSERT INTO domains (id, domain_name, system_user, customer_id) VALUES (?,?,?,?)`, domainA, "a.example", "c_a", customerA)
	exec(`INSERT INTO av_events (domain_id, source, stage, level, summary, path, pid) VALUES (?,?,?,?,?,?,?)`,
		domainA, "file", "file_write", "critical", "shell.php", "/home/c_a/public_html/shell.php", 0)

	var now string
	if err := db.QueryRow(`SELECT DATE_FORMAT(NOW(), '%Y-%m-%d %H:%i:%s')`).Scan(&now); err != nil {
		t.Fatalf("now: %v", err)
	}
	h := &Handlers{DB: db}

	// The owner sees the event.
	rOwn := reqAs(middleware.RoleReseller, resellerA)
	condA, argsA, _ := middleware.ScopeCondition(rOwn, "d")
	if ev := h.chainEvents(rOwn.Context(), domainA, now, condA, argsA); len(ev) != 1 {
		t.Fatalf("the owner saw %d events, want 1", len(ev))
	}
	// A different reseller, scoped to their own domains, sees none of domainA's
	// events even when asking for domainA directly.
	rOther := reqAs(middleware.RoleReseller, resellerB)
	condB, argsB, _ := middleware.ScopeCondition(rOther, "d")
	if ev := h.chainEvents(rOther.Context(), domainA, now, condB, argsB); len(ev) != 0 {
		t.Fatalf("a non-owner saw %d of domainA's events, want 0", len(ev))
	}
}

func reqAs(role string, userID int64) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/antivirus/chains", nil)
	return r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{UserID: userID, Username: "t", Role: role}))
}
