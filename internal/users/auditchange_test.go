package users

import (
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The snapshot query the audit path reads before it writes.
const profileRead = "SELECT email, full_name, role FROM users WHERE id=?"

// changeArgs returns the arguments of the audit INSERT one handler wrote.
func changeArgs(t *testing.T, script *sqlScript) []driver.Value {
	t.Helper()
	script.mu.Lock()
	defer script.mu.Unlock()
	for _, exec := range script.execs {
		if strings.Contains(exec.query, "INSERT INTO audit_log") {
			return exec.args
		}
	}
	t.Fatal("no audit row was written")
	return nil
}

// argAt reports one audit argument as a string, so a test names the column
// rather than counting placeholders in two places.
func argAt(args []driver.Value, index int) string {
	if index >= len(args) || args[index] == nil {
		return ""
	}
	if text, ok := args[index].(string); ok {
		return text
	}
	return ""
}

// The audit INSERT's argument order, matching auth.auditInsert.
const (
	argAction     = 3
	argActionType = 8
	argTable      = 9
	argRecordID   = 10
	argOldValues  = 12
	argNewValues  = 13
)

// The question the change columns exist for: a demotion must record what the
// role WAS. Reading the row afterwards cannot answer it, because the change has
// already happened.
func TestAnUpdateRecordsTheRoleItChangedFrom(t *testing.T) {
	script := newScript()
	script.rows[adminCount] = [][]driver.Value{{int64(2)}}
	script.rows[roleOfUser] = [][]driver.Value{{"admin"}}
	script.rows[scopeOfUser] = [][]driver.Value{{"user", int64(0)}}
	script.rows[resellerOfUser] = [][]driver.Value{{nil}}
	script.rows[profileRead] = [][]driver.Value{{"bob@example.test", "Bob", "admin"}}

	handlers := &Handlers{DB: scriptDB(t, script)}
	request := userRequest(http.MethodPut, `{"role":"user"}`, actorAdmin(), "42")
	handlers.Update(httptest.NewRecorder(), request)

	args := changeArgs(t, script)
	if got := argAt(args, argActionType); got != "UPDATE" {
		t.Errorf("action_type is %q, want UPDATE", got)
	}
	if got := argAt(args, argTable); got != "users" {
		t.Errorf("table_name is %q, want users", got)
	}
	if got := argAt(args, argRecordID); got != "42" {
		t.Errorf("record_id is %q, want 42", got)
	}
	if old := argAt(args, argOldValues); !strings.Contains(old, `"role":"admin"`) {
		t.Errorf("the old role was not recorded: %q", old)
	}
	if next := argAt(args, argNewValues); !strings.Contains(next, `"role":"user"`) {
		t.Errorf("the new role was not recorded: %q", next)
	}
}

// A field the caller did not name is not a change and must not be recorded as
// one, or every update would read as a change to the whole account.
func TestOnlyTheNamedFieldIsRecordedAsChanged(t *testing.T) {
	script := newScript()
	script.rows[adminCount] = [][]driver.Value{{int64(2)}}
	script.rows[scopeOfUser] = [][]driver.Value{{"user", int64(0)}}
	script.rows[resellerOfUser] = [][]driver.Value{{nil}}
	script.rows[profileRead] = [][]driver.Value{{"bob@example.test", "Bob", "user"}}

	handlers := &Handlers{DB: scriptDB(t, script)}
	handlers.Update(httptest.NewRecorder(),
		userRequest(http.MethodPut, `{"email":"new@example.test"}`, actorAdmin(), "42"))

	args := changeArgs(t, script)
	next := argAt(args, argNewValues)
	if !strings.Contains(next, "new@example.test") {
		t.Errorf("the changed email is missing: %q", next)
	}
	if strings.Contains(next, `"role"`) || strings.Contains(next, `"full_name"`) {
		t.Errorf("a field the request never named was recorded as changed: %q", next)
	}
	if old := argAt(args, argOldValues); strings.Contains(old, `"role"`) {
		t.Errorf("the old values list a field that did not change: %q", old)
	}
}

// A delete must record WHO was removed. Afterwards the id resolves to nothing,
// so a row naming only the id says nothing at all.
func TestADeleteRecordsTheAccountItRemoved(t *testing.T) {
	script := newScript()
	script.rows[adminCount] = [][]driver.Value{{int64(2)}}
	script.rows[scopeOfUser] = [][]driver.Value{{"user", int64(7)}}
	script.rows[resellerOfUser] = [][]driver.Value{{nil}}
	script.rows[profileRead] = [][]driver.Value{{"bob@example.test", "Bob", "user"}}

	handlers := &Handlers{DB: scriptDB(t, script)}
	handlers.Delete(httptest.NewRecorder(), userRequest(http.MethodDelete, "", actorAdmin(), "42"))

	args := changeArgs(t, script)
	if got := argAt(args, argActionType); got != "DELETE" {
		t.Errorf("action_type is %q, want DELETE", got)
	}
	old := argAt(args, argOldValues)
	if !strings.Contains(old, "bob@example.test") {
		t.Errorf("the removed account was not recorded: %q", old)
	}
}

// The snapshot must be read BEFORE the write, or it reads back the new value
// and both sides of the audit row say the same thing.
func TestTheSnapshotIsReadBeforeTheWrite(t *testing.T) {
	script := newScript()
	script.rows[adminCount] = [][]driver.Value{{int64(2)}}
	script.rows[roleOfUser] = [][]driver.Value{{"admin"}}
	script.rows[scopeOfUser] = [][]driver.Value{{"user", int64(0)}}
	script.rows[resellerOfUser] = [][]driver.Value{{nil}}
	script.rows[profileRead] = [][]driver.Value{{"bob@example.test", "Bob", "admin"}}

	handlers := &Handlers{DB: scriptDB(t, script)}
	handlers.Update(httptest.NewRecorder(),
		userRequest(http.MethodPut, `{"role":"user"}`, actorAdmin(), "42"))

	script.mu.Lock()
	defer script.mu.Unlock()
	snapshotAt, writeAt := -1, -1
	for i, step := range script.steps {
		if snapshotAt < 0 && strings.Contains(step, "SELECT email, full_name, role") {
			snapshotAt = i
		}
		if writeAt < 0 && strings.Contains(step, "UPDATE users SET role=") {
			writeAt = i
		}
	}
	if snapshotAt < 0 || writeAt < 0 {
		t.Fatalf("the handler did not run both steps: snapshot=%d write=%d\n%v", snapshotAt, writeAt, script.steps)
	}
	if snapshotAt > writeAt {
		t.Error("the old values were read after the write, so both sides of the audit row hold the new value")
	}
}

// A failed snapshot must not refuse the update: the audit row is worth writing
// without the old values.
func TestAFailedSnapshotStillWritesTheAuditRow(t *testing.T) {
	script := newScript()
	script.rows[adminCount] = [][]driver.Value{{int64(2)}}
	script.rows[scopeOfUser] = [][]driver.Value{{"user", int64(0)}}
	script.rows[resellerOfUser] = [][]driver.Value{{nil}}
	script.rows[profileRead] = [][]driver.Value{}

	handlers := &Handlers{DB: scriptDB(t, script)}
	response := httptest.NewRecorder()
	handlers.Update(response, userRequest(http.MethodPut, `{"email":"new@example.test"}`, actorAdmin(), "42"))

	if response.Code != http.StatusOK {
		t.Errorf("the update answered %d, so a failed audit snapshot refused a valid change", response.Code)
	}
	if old := argAt(changeArgs(t, script), argOldValues); old != "" {
		t.Errorf("old values were invented from a failed read: %q", old)
	}
}
