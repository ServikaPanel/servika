package notifications

// The visibility rule and the per-reader read state, exercised against a real
// MariaDB.
//
// An in-memory fake proves nothing here: what is being tested is a SQL clause
// over a LEFT JOIN and a UNIQUE key, and both belong to the server. The test is
// skipped without SERVIKA_TEST_DSN, and the CI gate runs the rest of the suite
// without it.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"servika/internal/auth"
	"servika/internal/middleware"

	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
)

func liveDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("SERVIKA_TEST_DSN")
	if dsn == "" {
		t.Skip("SERVIKA_TEST_DSN is not set")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// fixture builds two resellers, each with one customer and one domain, plus the
// notifications: one per domain and one panel-wide.
type fixture struct {
	adminID, resellerA, resellerB, customerA int64
	domainA, domainB                         int64
	noteA, noteB, notePanel                  int64
}

func newFixture(t *testing.T, db *sql.DB) fixture {
	t.Helper()
	ctx := context.Background()
	var f fixture

	// The cleanup for a row is registered AS SOON AS the row exists, not after
	// the whole fixture is built. Registering it at the end means an insert that
	// fails half way leaves everything before it behind, and since the names are
	// derived from the test name the NEXT run then fails on a duplicate rather
	// than on the real defect. Measured: a fixture that aborted on the
	// notifications insert left its four users, and the following run reported
	// `Duplicate entry 'adm_TestEachRoleSeesOnly_1' for key 'username'`.
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

	f.domainA = insert("domains", `INSERT INTO domains (domain_name, system_user, customer_id) VALUES (?, ?, ?)`,
		uniqueName(t, "a")+".example.com", uniqueName(t, "c_a"), custA)
	f.domainB = insert("domains", `INSERT INTO domains (domain_name, system_user, customer_id) VALUES (?, ?, ?)`,
		uniqueName(t, "b")+".example.com", uniqueName(t, "c_b"), custB)

	// The rows a domain owns go with it through the foreign keys; these three
	// are removed by their own registered cleanup, which is why the panel-wide
	// one needs no special case any more.
	f.noteA = insert("notifications", `INSERT INTO notifications (level, category, title, message, domain_id) VALUES ('critical','antivirus','A','m',?)`, f.domainA)
	f.noteB = insert("notifications", `INSERT INTO notifications (level, category, title, message, domain_id) VALUES ('critical','antivirus','B','m',?)`, f.domainB)
	f.notePanel = insert("notifications", `INSERT INTO notifications (level, category, title, message, domain_id) VALUES ('warning','antivirus','P','m',NULL)`)

	return f
}

var nameCounter int

func uniqueName(t *testing.T, prefix string) string {
	t.Helper()
	nameCounter++
	return prefix + "_" + t.Name()[:min(len(t.Name()), 20)] + "_" + itoa(nameCounter)
}

func itoa(n int) string {
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

func request(role string, userID int64) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	return r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{UserID: userID, Username: "t", Role: role}))
}

type listBody struct {
	Notifications []Notification `json:"notifications"`
	Unread        int            `json:"unread"`
}

func list(t *testing.T, h *Handlers, r *http.Request) listBody {
	t.Helper()
	rec := httptest.NewRecorder()
	h.List(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("list answered %d: %s", rec.Code, rec.Body.String())
	}
	var body listBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("list body: %v", err)
	}
	return body
}

func has(body listBody, id int64) bool {
	for _, n := range body.Notifications {
		if n.ID == id {
			return true
		}
	}
	return false
}

// A writer that carries only the English text must be accepted.
//
// 0112's header states that both new columns default to empty "so a writer that
// supplies only English is still valid", and for `params` that was false: the
// column was NOT NULL with no default, and MariaDB answers such an INSERT with
// `ERROR 1364 ... Field 'params' doesn't have a default value`. Nothing in the
// panel broke, because `Write` always supplies the column, but the fixture in
// this very file did not, and the failure was invisible for as long as nobody
// ran these tests against a real database.
//
// The insert is written the way a caller reaching for the simplest shape would
// write it, which is what makes this a test of the SCHEMA rather than of Write.
func TestANotificationCanBeWrittenWithNothingButItsEnglish(t *testing.T) {
	db := liveDB(t)
	var id int64
	res, err := db.Exec(
		`INSERT INTO notifications (level, category, title, message) VALUES ('info','test','T','m')`)
	if err != nil {
		t.Fatalf("an English-only notification was refused: %v", err)
	}
	id, err = res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM notifications WHERE id=?`, id) })

	var key, params string
	if err := db.QueryRow(`SELECT message_key, params FROM notifications WHERE id=?`, id).Scan(&key, &params); err != nil {
		t.Fatal(err)
	}
	// Empty rather than NULL, so "no key" is one value and every reader tests it
	// the same way.
	if key != "" || params != "" {
		t.Errorf("the defaults are %q and %q, want both empty", key, params)
	}
}

// A reseller must not read a neighbour's alert off a screen built to tell them
// about their own, and a panel-wide notification is the panel's own business:
// there is no ownership chain to narrow it by, so nobody below admin sees it.
func TestEachRoleSeesOnlyItsOwnNotifications(t *testing.T) {
	db := liveDB(t)
	f := newFixture(t, db)
	h := &Handlers{DB: db}

	admin := list(t, h, request(middleware.RoleAdmin, f.adminID))
	if !has(admin, f.noteA) || !has(admin, f.noteB) || !has(admin, f.notePanel) {
		t.Error("the admin does not see every notification")
	}

	reseller := list(t, h, request(middleware.RoleReseller, f.resellerA))
	if !has(reseller, f.noteA) {
		t.Error("the reseller does not see their own customer's notification")
	}
	if has(reseller, f.noteB) {
		t.Error("the reseller sees another reseller's notification")
	}
	if has(reseller, f.notePanel) {
		t.Error("the reseller sees a panel-wide notification")
	}

	customer := list(t, h, request(middleware.RoleUser, f.customerA))
	if !has(customer, f.noteA) {
		t.Error("the customer does not see their own domain's notification")
	}
	if has(customer, f.noteB) || has(customer, f.notePanel) {
		t.Error("the customer sees a notification that is not theirs")
	}

	anonymous := httptest.NewRecorder()
	h.List(anonymous, httptest.NewRequest(http.MethodGet, "/", nil))
	if anonymous.Code != http.StatusUnauthorized {
		t.Errorf("an anonymous request answered %d", anonymous.Code)
	}
}

// One domain notification has up to three viewers. With a read flag on the
// notification row, whichever of them opens it first marks it read for the
// others, so an admin dismissing a notice hides it from the customer who has to
// act on it.
func TestOneReaderMarkingSomethingReadLeavesTheOthersUnread(t *testing.T) {
	db := liveDB(t)
	f := newFixture(t, db)
	h := &Handlers{DB: db}

	before := list(t, h, request(middleware.RoleUser, f.customerA))
	if before.Unread == 0 {
		t.Fatal("the customer starts with nothing unread, so the test proves nothing")
	}

	markOne(t, h, request(middleware.RoleAdmin, f.adminID), f.noteA)

	admin := list(t, h, request(middleware.RoleAdmin, f.adminID))
	for _, n := range admin.Notifications {
		if n.ID == f.noteA && !n.Read {
			t.Error("the admin's own read was not recorded")
		}
	}
	after := list(t, h, request(middleware.RoleUser, f.customerA))
	if after.Unread != before.Unread {
		t.Errorf("the admin's read changed the customer's unread count: %d -> %d", before.Unread, after.Unread)
	}
	for _, n := range after.Notifications {
		if n.ID == f.noteA && n.Read {
			t.Error("the admin's read marked the notification read for the customer")
		}
	}
}

// "Mark everything read" runs the same visibility test the list does, so it
// cannot reach a row the caller was never allowed to see. Upstream's version
// takes id=0 to mean every row in the table, across every tenant.
func TestMarkingEverythingReadCannotReachSomebodyElsesNotification(t *testing.T) {
	db := liveDB(t)
	f := newFixture(t, db)
	h := &Handlers{DB: db}

	rec := httptest.NewRecorder()
	h.MarkRead(rec, request(middleware.RoleUser, f.customerA))
	if rec.Code != http.StatusOK {
		t.Fatalf("read-all answered %d: %s", rec.Code, rec.Body.String())
	}

	// Their own is now read, so the pass was not a no-op.
	own := list(t, h, request(middleware.RoleUser, f.customerA))
	if own.Unread != 0 {
		t.Errorf("the customer still has %d unread after marking everything read", own.Unread)
	}
	// The neighbour's and the panel-wide row are untouched.
	var reads int
	if err := db.QueryRow(`SELECT COUNT(*) FROM notification_reads WHERE notification_id IN (?,?)`,
		f.noteB, f.notePanel).Scan(&reads); err != nil {
		t.Fatalf("count: %v", err)
	}
	if reads != 0 {
		t.Errorf("marking everything read reached %d notification(s) the caller cannot see", reads)
	}
}

// Marking a single notification read is narrowed by the same test, so naming a
// neighbour's id changes nothing rather than recording a read against it.
func TestMarkingOneReadRefusesANotificationTheCallerCannotSee(t *testing.T) {
	db := liveDB(t)
	f := newFixture(t, db)
	h := &Handlers{DB: db}

	markOne(t, h, request(middleware.RoleUser, f.customerA), f.noteB)

	var reads int
	if err := db.QueryRow(`SELECT COUNT(*) FROM notification_reads WHERE notification_id=?`, f.noteB).Scan(&reads); err != nil {
		t.Fatalf("count: %v", err)
	}
	if reads != 0 {
		t.Error("a read was recorded against a notification the caller cannot see")
	}

	// And the same call against their OWN notification does record one, so the
	// refusal above is not simply a broken statement.
	markOne(t, h, request(middleware.RoleUser, f.customerA), f.noteA)
	if err := db.QueryRow(`SELECT COUNT(*) FROM notification_reads WHERE notification_id=?`, f.noteA).Scan(&reads); err != nil {
		t.Fatalf("count: %v", err)
	}
	if reads != 1 {
		t.Errorf("the caller's own notification recorded %d reads", reads)
	}
}

func markOne(t *testing.T, h *Handlers, r *http.Request, id int64) {
	t.Helper()
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add("id", itoa64(id))
	rec := httptest.NewRecorder()
	h.MarkRead(rec, r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx)))
	if rec.Code != http.StatusOK {
		t.Fatalf("mark read answered %d: %s", rec.Code, rec.Body.String())
	}
}

func itoa64(n int64) string { return itoa(int(n)) }
