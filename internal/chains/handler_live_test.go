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
	r := httptest.NewRequest(http.MethodGet, "/antivirus/chains", nil)
	r = r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{UserID: userID, Username: "t", Role: role}))
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
