package auth

import (
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// What a login DOES, pinned before the handler is split: the root branch, the
// 2FA block and the two failures at the end of the happy path.

// setForTest replaces a package-level seam for one test.
func setForTest[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

// loginBody sends a login carrying a 2FA code as well.
func loginBody(t *testing.T, script *totpScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handlers := &Handlers{
		DB:          totpDB(t, script),
		Secret:      []byte(strings.Repeat("k", 32)),
		LifetimeSec: 3600,
	}
	handlers.Login(recorder, httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body)))
	return recorder
}

// assertLogin checks the status and the message of a refusal.
func assertLogin(t *testing.T, recorder *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if recorder.Code != status || !strings.Contains(recorder.Body.String(), message) {
		t.Fatalf("status = %d, body = %s; want %d carrying %q",
			recorder.Code, recorder.Body.String(), status, message)
	}
}

// A body that is not a login is refused before anything is looked up.
func TestALoginRefusesABodyItCannotRead(t *testing.T) {
	for _, tc := range []struct{ name, body, message string }{
		{"not JSON", `{"username":`, "invalid request body"},
		{"no username", `{"username":"  ","password":"correct-horse"}`, "username and password are required"},
		{"no password", `{"username":"operator","password":""}`, "username and password are required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := loginBody(t, &totpScript{rows: map[string][]driver.Value{}}, tc.body)
			assertLogin(t, recorder, http.StatusBadRequest, tc.message)
		})
	}
}

// root does not exist in users.password_hash: its password lives in
// /etc/shadow, and a wrong one is answered with the SAME message a wrong
// database password gets, so which world an account belongs to is not leaked.
func TestARootLoginIsJudgedAgainstTheSystemPassword(t *testing.T) {
	setForTest(t, &rootPasswordOK, func(string) bool { return false })
	script := &totpScript{rows: map[string][]driver.Value{}}

	recorder := loginBody(t, script, `{"username":"root","password":"wrong"}`)

	assertLogin(t, recorder, http.StatusUnauthorized, "invalid username or password")
	if managementSessionCookie(recorder) != nil {
		t.Fatal("the refused root login was given a session cookie")
	}
	if !auditRecorded(script, "auth.login") {
		t.Error("the failed root login was not written to the audit log")
	}
}

// The accepted root login is id=1, name root, role admin, and the full name is
// the only field it reads from the database.
func TestAnAcceptedRootLoginIsAdminIDOne(t *testing.T) {
	t.Setenv("SERVIKA_VERSION_CHECK", "0")
	setForTest(t, &rootPasswordOK, func(string) bool { return true })
	script := &totpScript{rows: map[string][]driver.Value{
		"SELECT full_name":          {"Server Owner"},
		"totp_enabled, totp_secret": {int64(0), "", int64(0)},
		"SELECT token_version":      {int64(4)},
	}}

	recorder := loginBody(t, script, `{"username":"root","password":"right"}`)

	assertLogin(t, recorder, http.StatusOK, `"role":"admin"`)
	for _, want := range []string{`"id":1`, `"name":"root"`, `"full_name":"Server Owner"`} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Errorf("the answer does not carry %s: %s", want, recorder.Body.String())
		}
	}
	if managementSessionCookie(recorder) == nil {
		t.Error("the accepted root login got no session cookie")
	}
}

// twoFactorAccount scripts an active admin whose 2FA state the case decides.
func twoFactorAccount(t *testing.T, enabled int, stored string) *totpScript {
	t.Helper()
	rows := managementIdentity(t, "admin", "active")
	rows["totp_enabled, totp_secret"] = []driver.Value{int64(enabled), stored, int64(0)}
	rows["SELECT token_version"] = []driver.Value{int64(1)}
	return &totpScript{rows: rows}
}

// The 2FA state is read fail-closed on every branch: a state that cannot be
// read, a seed that cannot be opened and a replay counter that cannot be
// written all deny the login rather than issuing a token.
func TestTheSecondFactorFailsClosed(t *testing.T) {
	initSecret(t)
	sealed, err := SealTOTPSecret("JBSWY3DPEHPK3PXP", 7)
	if err != nil {
		t.Fatalf("SealTOTPSecret: %v", err)
	}
	code, err := totpCodeFor("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("build a valid code: %v", err)
	}
	for _, tc := range []struct {
		name    string
		script  func() *totpScript
		body    string
		status  int
		message string
	}{
		{
			name: "the state cannot be read",
			script: func() *totpScript {
				return &totpScript{rows: managementIdentity(t, "admin", "active")}
			},
			status:  http.StatusInternalServerError,
			message: "could not verify 2FA state",
		},
		{
			name:    "2FA is on but no seed is stored",
			script:  func() *totpScript { return twoFactorAccount(t, 1, "   ") },
			status:  http.StatusInternalServerError,
			message: "2FA configuration is invalid",
		},
		{
			name:    "the stored seed cannot be opened",
			script:  func() *totpScript { return twoFactorAccount(t, 1, "enc:v1:not-a-sealed-value") },
			body:    `,"code":"` + code + `"`,
			status:  http.StatusInternalServerError,
			message: "2FA configuration is invalid",
		},
		{
			name:    "the code is wrong",
			script:  func() *totpScript { return twoFactorAccount(t, 1, sealed) },
			body:    `,"code":"000000"`,
			status:  http.StatusUnauthorized,
			message: "invalid or reused 2FA code",
		},
		{
			name: "the accepted step cannot be persisted",
			script: func() *totpScript {
				script := twoFactorAccount(t, 1, sealed)
				script.fail = map[string]error{"totp_last_step=?": errors.New("disk full")}
				return script
			},
			body:    `,"code":"` + code + `"`,
			status:  http.StatusInternalServerError,
			message: "could not update 2FA state",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initSecret(t)
			script := tc.script()

			recorder := loginBody(t, script,
				`{"username":"operator","password":"correct-horse"`+tc.body+`}`)

			assertLogin(t, recorder, tc.status, tc.message)
			if managementSessionCookie(recorder) != nil {
				t.Error("a denied login was given a session cookie")
			}
		})
	}
}

// With 2FA on and no code, the answer is the prompt the sign-in form needs, not
// a refusal: the password was correct and only the second step is missing.
func TestAMissingCodeAsksForTheSecondFactor(t *testing.T) {
	initSecret(t)
	sealed, err := SealTOTPSecret("JBSWY3DPEHPK3PXP", 7)
	if err != nil {
		t.Fatalf("SealTOTPSecret: %v", err)
	}

	recorder := loginBody(t, twoFactorAccount(t, 1, sealed),
		`{"username":"operator","password":"correct-horse"}`)

	assertLogin(t, recorder, http.StatusOK, `"two_factor_required":true`)
	if managementSessionCookie(recorder) != nil {
		t.Error("a half-finished login was given a session cookie")
	}
}

// token_version is part of every token, so a read failure has to deny rather
// than issue a token that revocation could never invalidate.
func TestATokenVersionThatCannotBeReadDeniesTheLogin(t *testing.T) {
	rows := managementIdentity(t, "admin", "active")
	rows["totp_enabled, totp_secret"] = []driver.Value{int64(0), "", int64(0)}
	script := &totpScript{rows: rows}

	recorder := loginBody(t, script, `{"username":"operator","password":"correct-horse"}`)

	assertLogin(t, recorder, http.StatusInternalServerError, "token generation failed")
}

// last_login is display-only, so a write failure is logged and the session is
// still issued. Measured: the login answers 200 and sets the cookie.
func TestALastLoginWriteFailureStillSignsTheOperatorIn(t *testing.T) {
	t.Setenv("SERVIKA_VERSION_CHECK", "0")
	rows := managementIdentity(t, "admin", "active")
	rows["totp_enabled, totp_secret"] = []driver.Value{int64(0), "", int64(0)}
	rows["SELECT token_version"] = []driver.Value{int64(1)}
	script := &totpScript{rows: rows, fail: map[string]error{"last_login_at=NOW()": errors.New("disk full")}}

	recorder := loginBody(t, script, `{"username":"operator","password":"correct-horse"}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if managementSessionCookie(recorder) == nil {
		t.Error("no session cookie was set")
	}
}

// auditRecorded reports whether an audit row was written for an action.
func auditRecorded(script *totpScript, action string) bool {
	script.mu.Lock()
	defer script.mu.Unlock()
	for _, exec := range script.execs {
		if !strings.Contains(exec.query, "INSERT INTO audit_log") {
			continue
		}
		for _, arg := range exec.args {
			if text, ok := arg.(string); ok && text == action {
				return true
			}
		}
	}
	return false
}
