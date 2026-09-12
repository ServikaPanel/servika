package auth

import (
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ChangePassword serves the two password worlds from one endpoint: root's
// password lives in /etc/shadow and every other account's in
// users.password_hash. These pin which world each caller reaches and what each
// refusal says.

// changePassword sends a password change as the signed-in caller.
func changePassword(t *testing.T, script *totpScript, username string, uid int64, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/me/password", strings.NewReader(body))
	if username != "" {
		request = request.WithContext(WithClaims(request.Context(),
			&Claims{UserID: uid, Username: username, Role: "admin"}))
	}
	recorder := httptest.NewRecorder()
	(&Handlers{DB: totpDB(t, script)}).ChangePassword(recorder, request)
	return recorder
}

// accountWithPassword scripts the row the non-root branch reads.
func accountWithPassword(t *testing.T, password string) *totpScript {
	t.Helper()
	return &totpScript{rows: map[string][]driver.Value{
		"SELECT password_hash FROM users": {mustHash(t, password)},
	}}
}

// The checks that run before either world is chosen.
func TestAPasswordChangeRefusesWhatItCannotAct(t *testing.T) {
	for _, tc := range []struct {
		name, username, body, message string
		status                        int
	}{
		{
			name: "no session", username: "", body: `{"current":"a","new":"long-enough-1"}`,
			status: http.StatusUnauthorized, message: "no active session",
		},
		{
			name: "a body that is not JSON", username: "operator", body: `{"current":`,
			status: http.StatusBadRequest, message: "invalid request body",
		},
		{
			name: "a new password under the minimum", username: "operator",
			body:   `{"current":"correct-horse","new":"short"}`,
			status: http.StatusBadRequest, message: "at least 8 characters",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := changePassword(t, accountWithPassword(t, "correct-horse"), tc.username, 7, tc.body)
			assertLogin(t, recorder, tc.status, tc.message)
		})
	}
}

// root goes to /etc/shadow and to chpasswd, never to users.password_hash.
func TestTheRootPasswordChangeGoesThroughTheSystem(t *testing.T) {
	var written string
	setForTest(t, &rootPasswordOK, func(current string) bool { return current == "the-current-one" })
	setForTest(t, &setRootPassword, func(password string) error {
		written = password
		return nil
	})
	script := &totpScript{rows: map[string][]driver.Value{}}

	recorder := changePassword(t, script, "root", 1,
		`{"current":"the-current-one","new":"a-new-long-password"}`)

	assertLogin(t, recorder, http.StatusOK, `"ok":true`)
	if written != "a-new-long-password" {
		t.Errorf("chpasswd was handed %q", written)
	}
	if !executed(script, "token_version=token_version+1") {
		t.Error("the existing sessions were not revoked")
	}
	if !auditRecorded(script, "auth.password") {
		t.Error("the change was not written to the audit log")
	}
}

// Every way the root branch can refuse.
func TestTheRootPasswordChangeRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, body, message string
		currentOK           bool
		chpasswd            error
		fail                map[string]error
		status              int
	}{
		{
			name: "the current password is wrong", body: `{"current":"nope","new":"a-new-long-password"}`,
			status: http.StatusUnauthorized, message: "current password is incorrect",
		},
		{
			name:      "the new password carries a newline",
			body:      "{\"current\":\"the-current-one\",\"new\":\"a-new-long\\npassword\"}",
			currentOK: true,
			status:    http.StatusBadRequest, message: "password contains invalid characters",
		},
		{
			name: "chpasswd fails", body: `{"current":"the-current-one","new":"a-new-long-password"}`,
			currentOK: true, chpasswd: errors.New("chpasswd: exit 1"),
			status: http.StatusInternalServerError, message: "password change failed",
		},
		{
			name: "the sessions cannot be revoked", body: `{"current":"the-current-one","new":"a-new-long-password"}`,
			currentOK: true,
			fail:      map[string]error{"token_version=token_version+1": errors.New("disk full")},
			status:    http.StatusInternalServerError, message: "could not revoke existing sessions",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setForTest(t, &rootPasswordOK, func(string) bool { return tc.currentOK })
			setForTest(t, &setRootPassword, func(string) error { return tc.chpasswd })
			script := &totpScript{rows: map[string][]driver.Value{}, fail: tc.fail}

			recorder := changePassword(t, script, "root", 1, tc.body)

			assertLogin(t, recorder, tc.status, tc.message)
		})
	}
}

// A reseller account is judged against users.password_hash and the new hash is
// stored with the same statement that revokes the old sessions.
func TestAnAccountPasswordChangeStoresANewHash(t *testing.T) {
	script := accountWithPassword(t, "correct-horse")

	recorder := changePassword(t, script, "operator", 7,
		`{"current":"correct-horse","new":"a-new-long-password"}`)

	assertLogin(t, recorder, http.StatusOK, `"ok":true`)
	stored := statementArgs(t, script, "SET password_hash=?")
	hash, ok := stored[0].(string)
	if !ok || hash == "a-new-long-password" || !PasswordMatches(hash, "a-new-long-password") {
		t.Fatalf("the stored value is not a hash of the new password: %v", stored[0])
	}
	if !strings.Contains(lastStatement(t, script, "SET password_hash=?"), "token_version=token_version+1") {
		t.Error("the password write does not revoke the existing sessions")
	}
	if !auditRecorded(script, "auth.password") {
		t.Error("the change was not written to the audit log")
	}
}

// Every way the account branch can refuse.
func TestTheAccountPasswordChangeRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, message string
		script        func(*testing.T) *totpScript
		body          string
		status        int
	}{
		{
			name:   "the account row cannot be read",
			script: func(*testing.T) *totpScript { return &totpScript{rows: map[string][]driver.Value{}} },
			body:   `{"current":"correct-horse","new":"a-new-long-password"}`,
			status: http.StatusInternalServerError, message: "account could not be read",
		},
		{
			name:   "the current password is wrong",
			script: func(t *testing.T) *totpScript { return accountWithPassword(t, "correct-horse") },
			body:   `{"current":"nope","new":"a-new-long-password"}`,
			status: http.StatusUnauthorized, message: "current password is incorrect",
		},
		{
			name: "the new hash cannot be stored",
			script: func(t *testing.T) *totpScript {
				script := accountWithPassword(t, "correct-horse")
				script.fail = map[string]error{"SET password_hash=?": errors.New("disk full")}
				return script
			},
			body:   `{"current":"correct-horse","new":"a-new-long-password"}`,
			status: http.StatusInternalServerError, message: "password change failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := changePassword(t, tc.script(t), "operator", 7, tc.body)
			assertLogin(t, recorder, tc.status, tc.message)
		})
	}
}

// executed reports whether a statement carrying fragment ran.
func executed(script *totpScript, fragment string) bool {
	script.mu.Lock()
	defer script.mu.Unlock()
	for _, exec := range script.execs {
		if strings.Contains(exec.query, fragment) {
			return true
		}
	}
	return false
}

// statementArgs returns the arguments of the statement carrying fragment.
func statementArgs(t *testing.T, script *totpScript, fragment string) []driver.Value {
	t.Helper()
	script.mu.Lock()
	defer script.mu.Unlock()
	for _, exec := range script.execs {
		if strings.Contains(exec.query, fragment) {
			return exec.args
		}
	}
	t.Fatalf("no statement carrying %q ran", fragment)
	return nil
}

// lastStatement returns the text of the statement carrying fragment.
func lastStatement(t *testing.T, script *totpScript, fragment string) string {
	t.Helper()
	script.mu.Lock()
	defer script.mu.Unlock()
	for _, exec := range script.execs {
		if strings.Contains(exec.query, fragment) {
			return exec.query
		}
	}
	t.Fatalf("no statement carrying %q ran", fragment)
	return ""
}
