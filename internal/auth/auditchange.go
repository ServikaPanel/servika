package auth

// The row a mutation touched, recorded next to the action that touched it.
//
// audit_log has always recorded THAT something happened: an action name and a
// free-text target. It could not answer the question an operator actually
// arrives with, which is what the value used to be. "user.update on 42" does
// not say whether 42 was demoted from admin, and reading the current row cannot
// say either, because the change already happened.

import (
	"database/sql"
	"encoding/json"

	"servika/internal/logsink"
	"servika/internal/logx"
)

// Action types, matching the audit_log.action_type enum.
const (
	ActionInsert = "INSERT"
	ActionUpdate = "UPDATE"
	ActionDelete = "DELETE"
	ActionBulk   = "BULK"
)

// Change names the row a mutation touched.
//
// Every field is optional. A security event (a login, a refused permission)
// carries none of them, which is why the columns are nullable rather than a
// second table: the reader asks one table what happened, and the change columns
// are empty for the rows where there is no row to name.
type Change struct {
	RequestID string
	Type      string // one of the Action* constants, empty for a security event
	Table     string
	RecordID  string
	// Affected is set INSTEAD of RecordID by a bulk operation, which touches a
	// count of rows rather than one identifiable row.
	Affected  int
	OldValues map[string]any
	NewValues map[string]any
}

// changeJSON renders one value map, with every secret replaced.
//
// It shares logsink's word list rather than carrying a second one: a field that
// must not reach request_logs must not reach audit_log either, and two lists
// are two lists that drift.
func changeJSON(values map[string]any) any {
	if len(values) == 0 {
		return nil
	}
	safe := make(map[string]any, len(values))
	for key, value := range values {
		if logsink.IsSecretKey(key) {
			safe[key] = "[REDACTED]"
			continue
		}
		safe[key] = value
	}
	encoded, err := json.Marshal(safe)
	if err != nil {
		return nil
	}
	return string(encoded)
}

// nullableType turns an empty action type into a SQL NULL, because the column
// is an ENUM and refuses "".
func nullableType(actionType string) any {
	if actionType == "" {
		return nil
	}
	return actionType
}

// nullableCount turns a zero count into a SQL NULL, so "no rows were affected"
// and "this was not a bulk operation" stay distinguishable.
func nullableCount(affected int) any {
	if affected <= 0 {
		return nil
	}
	return affected
}

const auditInsert = `INSERT INTO audit_log
	(actor_user_id, actor_username, ip, action, target, ok, reseller_id,
	 request_id, action_type, table_name, record_id, affected_count, old_values, new_values)
	VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

// WriteAuditChange records an audit entry that also names the row it changed.
//
// It is WriteAuditScoped plus the change columns, and it is a separate function
// rather than a longer signature because most callers have no row to name and
// should not have to pass seven empty arguments to say so.
func WriteAuditChange(db *sql.DB, uid int64, username, ip, action, target string, ok bool, resellerScope int64, change Change) {
	var uidVal any
	if uid > 0 {
		uidVal = uid
	}
	okv := 0
	if ok {
		okv = 1
	}
	if resellerScope < 0 {
		resellerScope = 0
	}
	if _, err := db.Exec(auditInsert,
		uidVal, username, ip, action, target, okv, resellerScope,
		change.RequestID, nullableType(change.Type), change.Table, change.RecordID,
		nullableCount(change.Affected), changeJSON(change.OldValues), changeJSON(change.NewValues),
	); err != nil {
		logx.Errorf("audit log insert failed: %v", err)
	}
}
