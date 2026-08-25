package antivirus

// The server-wide quarantine narrowing, exercised against a real MariaDB.
//
// An in-memory fake proves nothing here: what is being tested is a SQL clause
// over a JOIN, and that belongs to the server. The test is skipped without
// SERVIKA_TEST_DSN, and the CI gate runs the rest of the suite without it.
//
// Only the LOOKUP is exercised. Restoring and deleting touch the filesystem as
// root under /home, which a test must not do; what decides whether a caller may
// act on an entry is `entryInScope`, and every action endpoint refuses before it
// reaches a file when that answers false.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
)

// liveDB lives in slot_live_test.go: one helper for the package, so both live
// tests skip on the same condition.

// quarantineFixture builds two resellers, each with one customer and one domain,
// and one held file under each domain.
type quarantineFixture struct {
	adminID, resellerA, resellerB, customerA int64
	domainA, domainB                         int64
	entryA, entryB                           int64
}

func newQuarantineFixture(t *testing.T, db *sql.DB) quarantineFixture {
	t.Helper()
	ctx := context.Background()
	var f quarantineFixture

	// The cleanup for a row is registered AS SOON AS the row exists, not after
	// the whole fixture is built. Registering it at the end means an insert that
	// fails half way leaves everything before it behind, and since the names are
	// derived from the test name the NEXT run then fails on a duplicate rather
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

	f.adminID = insert("users", `INSERT INTO users (username, password_hash, dashboard_layout, role) VALUES (?, 'x', '', 'admin')`, uniqueName(t, "adm"))
	f.resellerA = insert("users", `INSERT INTO users (username, password_hash, dashboard_layout, role) VALUES (?, 'x', '', 'reseller')`, uniqueName(t, "resa"))
	f.resellerB = insert("users", `INSERT INTO users (username, password_hash, dashboard_layout, role) VALUES (?, 'x', '', 'reseller')`, uniqueName(t, "resb"))
	f.customerA = insert("users", `INSERT INTO users (username, password_hash, dashboard_layout, role) VALUES (?, 'x', '', 'user')`, uniqueName(t, "cusa"))

	custA := insert("customers", `INSERT INTO customers (name, email, owner_user_id, user_id) VALUES ('A', ?, ?, ?)`, uniqueName(t, "a")+"@example.com", f.resellerA, f.customerA)
	custB := insert("customers", `INSERT INTO customers (name, email, owner_user_id) VALUES ('B', ?, ?)`, uniqueName(t, "b")+"@example.com", f.resellerB)

	userA := uniqueName(t, "c_a")
	userB := uniqueName(t, "c_b")
	f.domainA = insert("domains", `INSERT INTO domains (domain_name, system_user, customer_id) VALUES (?, ?, ?)`,
		uniqueName(t, "a")+".example.com", userA, custA)
	f.domainB = insert("domains", `INSERT INTO domains (domain_name, system_user, customer_id) VALUES (?, ?, ?)`,
		uniqueName(t, "b")+".example.com", userB, custB)

	f.entryA = insert("av_quarantine", `INSERT INTO av_quarantine (domain_id, system_user, orig_rel, stored_name, signature, engine)
	                   VALUES (?, ?, 'public_html/a.php', '1_a.php', 'PHP.Webshell.EvalBase64', 'heuristic')`, f.domainA, userA)
	f.entryB = insert("av_quarantine", `INSERT INTO av_quarantine (domain_id, system_user, orig_rel, stored_name, signature, engine)
	                   VALUES (?, ?, 'public_html/b.php', '2_b.php', 'PHP.Webshell.EvalBase64', 'heuristic')`, f.domainB, userB)

	return f
}

var quarantineNameCounter int

func uniqueName(t *testing.T, prefix string) string {
	t.Helper()
	quarantineNameCounter++
	name := t.Name()
	if len(name) > 20 {
		name = name[:20]
	}
	return prefix + "_" + name + "_" + strconv.Itoa(quarantineNameCounter)
}

func scopedRequest(role string, userID int64) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	return r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{UserID: userID, Username: "t", Role: role}))
}

// withQID puts the entry id where chi's URL parameter would be, so the handler
// reads it exactly as it does in production.
func withQID(r *http.Request, qid int64) *http.Request {
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add("qid", strconv.FormatInt(qid, 10))
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
}

type adminListBody struct {
	Entries []AdminEntry `json:"entries"`
}

func adminList(t *testing.T, h *Handlers, r *http.Request) adminListBody {
	t.Helper()
	rec := httptest.NewRecorder()
	h.AdminQuarantineList(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("the list answered %d: %s", rec.Code, rec.Body.String())
	}
	var body adminListBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("list body: %v", err)
	}
	return body
}

func holds(body adminListBody, id int64) bool {
	for _, e := range body.Entries {
		if e.ID == id {
			return true
		}
	}
	return false
}

// A reseller reading the server-wide quarantine must see their own customers'
// held files and NOTHING else. The narrowing is in the query, so this is the
// test that fails if somebody replaces it with a row-by-row check or drops it.
func TestTheServerWideQuarantineShowsOnlyWhatTheCallerOwns(t *testing.T) {
	db := liveDB(t)
	f := newQuarantineFixture(t, db)
	h := &Handlers{DB: db}

	admin := adminList(t, h, scopedRequest(middleware.RoleAdmin, f.adminID))
	if !holds(admin, f.entryA) || !holds(admin, f.entryB) {
		t.Error("the admin does not see every held file")
	}

	reseller := adminList(t, h, scopedRequest(middleware.RoleReseller, f.resellerA))
	if !holds(reseller, f.entryA) {
		t.Error("the reseller does not see their own customer's held file")
	}
	if holds(reseller, f.entryB) {
		t.Error("the reseller sees another reseller's held file")
	}
}

// The domain NAME travels with the entry, because a path alone does not say
// whose site it is on a list that crosses domains.
func TestTheServerWideQuarantineNamesTheDomain(t *testing.T) {
	db := liveDB(t)
	f := newQuarantineFixture(t, db)
	h := &Handlers{DB: db}

	var want string
	if err := db.QueryRow(`SELECT domain_name FROM domains WHERE id=?`, f.domainA).Scan(&want); err != nil {
		t.Fatal(err)
	}
	body := adminList(t, h, scopedRequest(middleware.RoleAdmin, f.adminID))
	for _, e := range body.Entries {
		if e.ID == f.entryA {
			if e.Domain != want {
				t.Errorf("the entry names domain %q, want %q", e.Domain, want)
			}
			if e.OrigPath == "" {
				t.Error("the entry carries no original path")
			}
			return
		}
	}
	t.Fatal("the entry was not in the list")
}

// Acting on a neighbour's entry is refused, and refused the same way a
// nonexistent id is. Answering differently would confirm the id exists, which
// is a fact the caller is not entitled to.
func TestActingOnANeighboursHeldFileIsRefused(t *testing.T) {
	db := liveDB(t)
	f := newQuarantineFixture(t, db)
	h := &Handlers{DB: db}

	// Reseller A may act on their own entry: the lookup answers.
	own := withQID(scopedRequest(middleware.RoleReseller, f.resellerA), f.entryA)
	if _, _, _, ok := h.entryInScope(own, f.entryA, false); !ok {
		t.Fatal("the reseller cannot reach their own held file, so this test proves nothing")
	}

	// The neighbour's entry is not reachable.
	neighbour := withQID(scopedRequest(middleware.RoleReseller, f.resellerA), f.entryB)
	if _, _, _, ok := h.entryInScope(neighbour, f.entryB, false); ok {
		t.Error("the reseller reached another reseller's held file")
	}

	// Every action endpoint refuses before it touches a file, and all three
	// answer the not-found code rather than a forbidden one.
	for name, handler := range map[string]http.HandlerFunc{
		"restore": h.AdminQuarantineRestore,
		"delete":  h.AdminQuarantineDelete,
		"inspect": h.AdminQuarantineInspect,
	} {
		rec := httptest.NewRecorder()
		handler(rec, neighbour)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s answered %d for a neighbour's entry, want 404: %s", name, rec.Code, rec.Body.String())
		}
	}
}

// A restore needs an entry that is still being held. A row already restored is
// not reachable through the restore path, so the same file cannot be written
// back twice.
func TestARestoredEntryIsNoLongerReachableForRestoring(t *testing.T) {
	db := liveDB(t)
	f := newQuarantineFixture(t, db)
	h := &Handlers{DB: db}

	held := withQID(scopedRequest(middleware.RoleAdmin, f.adminID), f.entryA)
	if _, _, _, ok := h.entryInScope(held, f.entryA, true); !ok {
		t.Fatal("a held entry is not reachable, so this test proves nothing")
	}

	if _, err := db.Exec(`UPDATE av_quarantine SET restored_at=NOW() WHERE id=?`, f.entryA); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := h.entryInScope(held, f.entryA, true); ok {
		t.Error("an already restored entry is still reachable for restoring")
	}
	// Delete and inspect still reach it: the row survives a restore and both
	// remain meaningful for it.
	if _, _, _, ok := h.entryInScope(held, f.entryA, false); !ok {
		t.Error("a restored entry can no longer be inspected or deleted")
	}
}
