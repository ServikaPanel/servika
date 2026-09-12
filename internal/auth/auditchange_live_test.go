package auth

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	"servika/internal/db"
)

// changeDB opens the shared test database, or skips.
func changeDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("SERVIKA_TEST_DSN")
	if dsn == "" {
		t.Skip("SERVIKA_TEST_DSN is unset, so there is no server to ask")
	}
	handle, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	return handle
}

// storedChange reads back the one row a test wrote, by the request id it named.
type storedChange struct {
	actionType sql.NullString
	table      string
	recordID   string
	affected   sql.NullInt64
	oldValues  sql.NullString
	newValues  sql.NullString
}

func readChange(t *testing.T, handle *sql.DB, requestID string) storedChange {
	t.Helper()
	var got storedChange
	if err := handle.QueryRow(
		`SELECT action_type, table_name, record_id, affected_count, old_values, new_values
		   FROM audit_log WHERE request_id=?`, requestID).
		Scan(&got.actionType, &got.table, &got.recordID, &got.affected, &got.oldValues, &got.newValues); err != nil {
		t.Fatalf("read: %v", err)
	}
	return got
}

// The question audit_log could not answer before: what the value WAS.
func TestAChangeRecordsBothSidesOfTheValue(t *testing.T) {
	handle := changeDB(t)
	const reqID = "auditchange-both-sides"
	t.Cleanup(func() { _, _ = handle.Exec(`DELETE FROM audit_log WHERE request_id=?`, reqID) })

	WriteAuditChange(handle, 1, "root", "203.0.113.7", "user.update", "42", true, 0, Change{
		RequestID: reqID,
		Type:      ActionUpdate,
		Table:     "users",
		RecordID:  "42",
		OldValues: map[string]any{"role": "admin"},
		NewValues: map[string]any{"role": "user"},
	})

	got := readChange(t, handle, reqID)
	if got.actionType.String != ActionUpdate || got.table != "users" || got.recordID != "42" {
		t.Errorf("the row came back as %+v", got)
	}
	if !strings.Contains(got.oldValues.String, `"role":"admin"`) {
		t.Errorf("the old value is missing: %q", got.oldValues.String)
	}
	if !strings.Contains(got.newValues.String, `"role":"user"`) {
		t.Errorf("the new value is missing: %q", got.newValues.String)
	}
}

// A secret must not reach audit_log either. The word list is shared with
// request_logs rather than copied, because two lists are two lists that drift.
func TestAChangeCarriesNoSecretValue(t *testing.T) {
	handle := changeDB(t)
	const reqID = "auditchange-secret"
	t.Cleanup(func() { _, _ = handle.Exec(`DELETE FROM audit_log WHERE request_id=?`, reqID) })

	WriteAuditChange(handle, 1, "root", "203.0.113.7", "user.create", "bob", true, 0, Change{
		RequestID: reqID,
		Type:      ActionInsert,
		Table:     "users",
		RecordID:  "43",
		NewValues: map[string]any{"username": "bob", "password_hash": "$2y$hunter2", "api_token": "abc123"},
	})

	got := readChange(t, handle, reqID)
	for _, secret := range []string{"hunter2", "abc123"} {
		if strings.Contains(got.newValues.String, secret) {
			t.Errorf("%q reached audit_log: %s", secret, got.newValues.String)
		}
	}
	if !strings.Contains(got.newValues.String, "bob") {
		t.Errorf("the username was redacted too: %s", got.newValues.String)
	}
}

// A security event names no row. Those columns must be NULL rather than an
// empty string, so a reader can tell "no row" from "a row with no values".
func TestASecurityEventNamesNoRow(t *testing.T) {
	handle := changeDB(t)
	const reqID = "auditchange-security"
	t.Cleanup(func() { _, _ = handle.Exec(`DELETE FROM audit_log WHERE request_id=?`, reqID) })

	WriteAuditChange(handle, 0, "unknown", "203.0.113.7", "auth.login", "bob", false, 0, Change{
		RequestID: reqID,
	})

	got := readChange(t, handle, reqID)
	if got.actionType.Valid {
		t.Errorf("action_type is %q, expected NULL", got.actionType.String)
	}
	if got.affected.Valid || got.oldValues.Valid || got.newValues.Valid {
		t.Errorf("a security event carried change columns: %+v", got)
	}
}

// A bulk operation names a count instead of one row, because there is no single
// record id to name.
func TestABulkChangeRecordsItsCount(t *testing.T) {
	handle := changeDB(t)
	const reqID = "auditchange-bulk"
	t.Cleanup(func() { _, _ = handle.Exec(`DELETE FROM audit_log WHERE request_id=?`, reqID) })

	WriteAuditChange(handle, 1, "root", "203.0.113.7", "domains.bulk_suspend", "12 domains", true, 0, Change{
		RequestID: reqID,
		Type:      ActionBulk,
		Table:     "domains",
		Affected:  12,
	})

	got := readChange(t, handle, reqID)
	if got.affected.Int64 != 12 {
		t.Errorf("affected_count is %v, want 12", got.affected)
	}
	if got.recordID != "" {
		t.Errorf("a bulk row named record_id=%q", got.recordID)
	}
}

// The pre-existing writer must keep working unchanged: every caller that names
// no row still goes through it, and its rows must stay readable.
func TestTheOlderWriterStillWrites(t *testing.T) {
	handle := changeDB(t)
	const action = "auditchange-legacy-test"
	t.Cleanup(func() { _, _ = handle.Exec(`DELETE FROM audit_log WHERE action=?`, action) })

	WriteAuditScoped(handle, 1, "root", "203.0.113.7", action, "target", true, 0)

	var rows int
	if err := handle.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action=? AND request_id='' AND action_type IS NULL`,
		action).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Errorf("%d row(s) were written by the older writer, expected 1", rows)
	}
}
