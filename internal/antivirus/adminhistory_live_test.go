package antivirus

// Who sees which finding, measured against a real MariaDB.
//
// An in-memory fake proves nothing here: what is being tested is an EXISTS
// subquery over two LEFT JOINs, and all of that belongs to the server. The test
// is skipped without SERVIKA_TEST_DSN, exactly like the rest of this package's
// live tests.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"
)

// historyFixture is two resellers, each with one customer and one domain, plus
// four findings: one per domain, one with no domain at all, and one that was
// quarantined and then restored.
type historyFixture struct {
	resellerA, resellerB, customerA int64
	domainA, domainB                int64
	findingA, findingB, findingNone int64
	findingHeld, findingRestored    int64
}

func newHistoryFixture(t *testing.T, db *sql.DB) historyFixture {
	t.Helper()
	ctx := context.Background()
	var f historyFixture

	// A row's cleanup is registered as soon as the row exists. Registering them
	// all at the end means a fixture that fails half way leaves everything
	// before it behind, and the next run then fails on a duplicate name rather
	// than on the real defect.
	insert := func(table, query string, args ...any) int64 {
		t.Helper()
		res, err := db.ExecContext(ctx, query, args...)
		if err != nil {
			t.Fatalf("fixture: %v (%s)", err, query)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("fixture id: %v", err)
		}
		t.Cleanup(func() {
			// #nosec G202 -- table is a literal from this file, never caller text.
			_, _ = db.Exec(`DELETE FROM `+table+` WHERE id=?`, id)
		})
		return id
	}

	f.resellerA = insert("users", `INSERT INTO users (username, password_hash, dashboard_layout, role) VALUES (?, 'x', '', 'reseller')`, histName(t, "resa"))
	f.resellerB = insert("users", `INSERT INTO users (username, password_hash, dashboard_layout, role) VALUES (?, 'x', '', 'reseller')`, histName(t, "resb"))
	f.customerA = insert("users", `INSERT INTO users (username, password_hash, dashboard_layout, role) VALUES (?, 'x', '', 'user')`, histName(t, "cusa"))

	custA := insert("customers", `INSERT INTO customers (name, email, owner_user_id, user_id) VALUES ('A', ?, ?, ?)`,
		histName(t, "a")+"@example.com", f.resellerA, f.customerA)
	custB := insert("customers", `INSERT INTO customers (name, email, owner_user_id) VALUES ('B', ?, ?)`,
		histName(t, "b")+"@example.com", f.resellerB)

	userA, userB := histName(t, "c_a"), histName(t, "c_b")
	f.domainA = insert("domains", `INSERT INTO domains (domain_name, system_user, customer_id) VALUES (?, ?, ?)`,
		histName(t, "a")+".example.com", userA, custA)
	f.domainB = insert("domains", `INSERT INTO domains (domain_name, system_user, customer_id) VALUES (?, ?, ?)`,
		histName(t, "b")+".example.com", userB, custB)

	scan := insert("av_scans", `INSERT INTO av_scans (domain_id, scope, status, engine, source) VALUES (NULL,'host','finished','heuristic','manual')`)

	finding := func(domain any, file, level string) int64 {
		return insert("av_findings",
			`INSERT INTO av_findings (scan_id, domain_id, file, signature, engine, score, level)
			 VALUES (?,?,?,'PHP.Webshell.EvalBase64','heuristic',100,?)`, scan, domain, file, level)
	}
	f.findingA = finding(f.domainA, "/home/"+userA+"/public_html/a.php", LevelCritical)
	f.findingB = finding(f.domainB, "/home/"+userB+"/public_html/b.php", LevelCritical)
	// Outside every tenant home, so it belongs to no customer.
	f.findingNone = finding(nil, "/opt/somewhere/x.php", LevelCritical)

	// The two whose containment state the screen has to derive.
	f.findingHeld = finding(f.domainA, "/home/"+userA+"/public_html/held.php", LevelCritical)
	f.findingRestored = finding(f.domainA, "/home/"+userA+"/public_html/back.php", LevelSuspicious)
	insert("av_quarantine",
		`INSERT INTO av_quarantine (domain_id, finding_id, system_user, orig_rel, stored_name, size_bytes, signature, engine)
		 VALUES (?,?,?,'public_html/held.php','1.bin',10,'s','heuristic')`, f.domainA, f.findingHeld, userA)
	insert("av_quarantine",
		`INSERT INTO av_quarantine (domain_id, finding_id, system_user, orig_rel, stored_name, size_bytes, signature, engine, restored_at)
		 VALUES (?,?,?,'public_html/back.php','2.bin',10,'s','heuristic',NOW())`, f.domainA, f.findingRestored, userA)

	return f
}

var histCounter int

func histName(t *testing.T, prefix string) string {
	t.Helper()
	histCounter++
	name := t.Name()
	if len(name) > 20 {
		name = name[:20]
	}
	return prefix + "_" + name + "_" + strconvItoa(histCounter)
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	out := ""
	for n > 0 {
		out = string(rune('0'+n%10)) + out
		n /= 10
	}
	return out
}

func historyFor(t *testing.T, h *Handlers, role string, userID int64) []HistoryEntry {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{UserID: userID, Username: "t", Role: role}))
	rec := httptest.NewRecorder()
	h.AdminHistory(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("the history answered %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Entries []HistoryEntry `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body.Entries
}

func hasFinding(entries []HistoryEntry, id int64) bool {
	for _, e := range entries {
		if e.ID == id {
			return true
		}
	}
	return false
}

func TestAResellerSeesOnlyTheirOwnFindings(t *testing.T) {
	db := liveDB(t)
	f := newHistoryFixture(t, db)
	h := &Handlers{DB: db}

	a := historyFor(t, h, middleware.RoleReseller, f.resellerA)
	if !hasFinding(a, f.findingA) {
		t.Error("reseller A cannot see their own finding")
	}
	if hasFinding(a, f.findingB) {
		t.Error("reseller A can see reseller B's finding")
	}

	b := historyFor(t, h, middleware.RoleReseller, f.resellerB)
	if !hasFinding(b, f.findingB) {
		t.Error("reseller B cannot see their own finding")
	}
	if hasFinding(b, f.findingA) {
		t.Error("reseller B can see reseller A's finding")
	}
}

func TestAFindingOutsideEveryHomeReachesAdminsAlone(t *testing.T) {
	// A NULL domain_id belongs to no customer, so no ownership condition can
	// grant it. The narrowing drops it because the LEFT JOIN leaves
	// d.customer_id NULL and the EXISTS subquery matches nothing.
	db := liveDB(t)
	f := newHistoryFixture(t, db)
	h := &Handlers{DB: db}

	if entries := historyFor(t, h, middleware.RoleReseller, f.resellerA); hasFinding(entries, f.findingNone) {
		t.Error("a reseller can see a finding that belongs to no customer")
	}
	if entries := historyFor(t, h, middleware.RoleReseller, f.resellerB); hasFinding(entries, f.findingNone) {
		t.Error("the other reseller can see it too")
	}
	// Non-vacuity: it really is in the table, and an admin really does get it.
	// Without this the two checks above pass on an empty result set.
	admin := historyFor(t, h, middleware.RoleAdmin, 0)
	if !hasFinding(admin, f.findingNone) {
		t.Fatal("an admin cannot see the finding either, so the checks above measure nothing")
	}
	if !hasFinding(admin, f.findingA) || !hasFinding(admin, f.findingB) {
		t.Error("an admin cannot see both resellers' findings")
	}
}

func TestACustomerSeesOnlyTheirOwnDomainsFindings(t *testing.T) {
	db := liveDB(t)
	f := newHistoryFixture(t, db)
	h := &Handlers{DB: db}

	entries := historyFor(t, h, middleware.RoleUser, f.customerA)
	if !hasFinding(entries, f.findingA) {
		t.Error("the customer cannot see a finding on their own domain")
	}
	if hasFinding(entries, f.findingB) {
		t.Error("the customer can see another reseller's domain")
	}
	if hasFinding(entries, f.findingNone) {
		t.Error("the customer can see a finding that belongs to no customer")
	}
}

func TestAnAnonymousRequestSeesNothing(t *testing.T) {
	db := liveDB(t)
	newHistoryFixture(t, db)
	h := &Handlers{DB: db}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.AdminHistory(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("answered %d", rec.Code)
	}
	var body struct {
		Entries []HistoryEntry `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Entries) != 0 {
		t.Errorf("an anonymous request read %d findings", len(body.Entries))
	}
}

func TestTheContainmentStateComesFromTheQuarantineTable(t *testing.T) {
	// av_findings.quarantined records what happened when the row was written and
	// is never updated, so a file taken and then put back still reads as held
	// there. The join answers what is true now.
	db := liveDB(t)
	f := newHistoryFixture(t, db)
	h := &Handlers{DB: db}

	states := map[int64]string{}
	for _, e := range historyFor(t, h, middleware.RoleAdmin, 0) {
		states[e.ID] = e.State
	}
	for id, want := range map[int64]string{
		f.findingA:        "none",
		f.findingHeld:     "quarantined",
		f.findingRestored: "restored",
	} {
		if states[id] != want {
			t.Errorf("finding %d reads as %q, expected %q", id, states[id], want)
		}
	}
}

func TestTheHistoryCarriesTheDomainNameAndTheVerdict(t *testing.T) {
	// The list crosses domains, so the path alone does not say whose site it is,
	// and a suspicious verdict must not be drawn as a critical one.
	db := liveDB(t)
	f := newHistoryFixture(t, db)
	h := &Handlers{DB: db}

	entries := historyFor(t, h, middleware.RoleAdmin, 0)
	var restored *HistoryEntry
	for i := range entries {
		if entries[i].ID == f.findingRestored {
			restored = &entries[i]
			break
		}
	}
	if restored == nil {
		t.Fatal("the restored finding is missing from the list")
	}
	if restored.Domain == "" {
		t.Error("the entry carries no domain name")
	}
	if restored.DomainID != f.domainA {
		t.Errorf("the entry names domain %d, expected %d", restored.DomainID, f.domainA)
	}
	if restored.Level != LevelSuspicious {
		t.Errorf("the entry reads as %q, expected %q", restored.Level, LevelSuspicious)
	}
}
