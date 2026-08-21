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

	insert := func(query string, args ...any) int64 {
		t.Helper()
		res, err := db.ExecContext(ctx, query, args...)
		if err != nil {
			t.Fatalf("fixture: %v (%s)", err, query)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("fixture id: %v", err)
		}
		return id
	}

	f.adminID = insert(`INSERT INTO users (username, password_hash, dashboard_layout, role) VALUES (?, 'x', '', 'admin')`, uniqueName(t, "adm"))
	f.resellerA = insert(`INSERT INTO users (username, password_hash, dashboard_layout, role) VALUES (?, 'x', '', 'reseller')`, uniqueName(t, "resa"))
	f.resellerB = insert(`INSERT INTO users (username, password_hash, dashboard_layout, role) VALUES (?, 'x', '', 'reseller')`, uniqueName(t, "resb"))
	f.customerA = insert(`INSERT INTO users (username, password_hash, dashboard_layout, role) VALUES (?, 'x', '', 'user')`, uniqueName(t, "cusa"))

	custA := insert(`INSERT INTO customers (name, email, owner_user_id, user_id) VALUES ('A', 'a@example.com', ?, ?)`, f.resellerA, f.customerA)
	custB := insert(`INSERT INTO customers (name, email, owner_user_id) VALUES ('B', 'b@example.com', ?)`, f.resellerB)

	f.domainA = insert(`INSERT INTO domains (domain_name, system_user, customer_id) VALUES (?, ?, ?)`,
		uniqueName(t, "a")+".example.com", uniqueName(t, "c_a"), custA)
	f.domainB = insert(`INSERT INTO domains (domain_name, system_user, customer_id) VALUES (?, ?, ?)`,
		uniqueName(t, "b")+".example.com", uniqueName(t, "c_b"), custB)

	f.noteA = insert(`INSERT INTO notifications (level, category, title, message, domain_id) VALUES ('critical','antivirus','A','m',?)`, f.domainA)
	f.noteB = insert(`INSERT INTO notifications (level, category, title, message, domain_id) VALUES ('critical','antivirus','B','m',?)`, f.domainB)
	f.notePanel = insert(`INSERT INTO notifications (level, category, title, message, domain_id) VALUES ('warning','antivirus','P','m',NULL)`)

	t.Cleanup(func() {
		// The notification rows and their reads go with the domains through the
		// foreign keys; the panel-wide one names no domain, so it is removed here.
		_, _ = db.Exec(`DELETE FROM notifications WHERE id=?`, f.notePanel)
		_, _ = db.Exec(`DELETE FROM domains WHERE id IN (?,?)`, f.domainA, f.domainB)
		_, _ = db.Exec(`DELETE FROM customers WHERE id IN (?,?)`, custA, custB)
		_, _ = db.Exec(`DELETE FROM users WHERE id IN (?,?,?,?)`, f.adminID, f.resellerA, f.resellerB, f.customerA)
	})
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
