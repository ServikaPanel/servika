package auth

import (
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// loginRequest builds a panel login for a non-root account, which is the branch
// that reads the database.
func loginRequest(username, password string) *http.Request {
	body := `{"username":"` + username + `","password":"` + password + `"}`
	return httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
}

func runLogin(t *testing.T, script *totpScript, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handlers := &Handlers{
		DB:          totpDB(t, script),
		Secret:      []byte(strings.Repeat("k", 32)),
		LifetimeSec: 3600,
	}
	handlers.Login(recorder, loginRequest(username, password))
	return recorder
}

// The identity lookup and the password comparison shared one failure branch, so
// every driver error was reported as a wrong credential. During a database
// incident that told an operator typing the right password that their
// credentials were wrong, and every 401 records a failure against the per-account
// and per-IP lockout counters, so retrying through the outage locked a healthy
// account out for the quarter hour AFTER the database came back.
func TestADatabaseFailureIsAFaultNotAWrongPassword(t *testing.T) {
	// A script with no answer for the account lookup: the driver returns an
	// error, which is what an unreachable MariaDB produces.
	script := &totpScript{rows: map[string][]driver.Value{}}

	recorder := runLogin(t, script, "operator", "correct-horse")

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusInternalServerError, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "invalid username or password") {
		t.Fatalf("a database failure was reported as a wrong credential: %s", recorder.Body.String())
	}
}

// A 500 leaks nothing, because it is not conditioned on whether the account
// exists: an unknown username still folds into the shared 401 that keeps
// username existence secret.
func TestAnUnknownUsernameStillAnswersTheSharedRejection(t *testing.T) {
	// A lookup that returns no row rather than an error: six columns, zero rows.
	script := &totpScript{empty: map[string]int{
		"password_hash, role, status": 6,
	}}

	recorder := runLogin(t, script, "nobody", "correct-horse")

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "invalid username or password") {
		t.Fatalf("an unknown username was answered with %s", recorder.Body.String())
	}
}

// A known username with the wrong password gets the SAME answer as an unknown
// one, or the pair of responses tells an attacker which usernames exist.
func TestAWrongPasswordIsIndistinguishableFromAnUnknownUsername(t *testing.T) {
	hash, err := HashPassword("correct-horse")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	script := &totpScript{rows: map[string][]driver.Value{
		"password_hash, role, status": {int64(7), "operator", hash, "admin", "active", "Operator"},
	}}

	recorder := runLogin(t, script, "operator", "the-wrong-password")

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "invalid username or password") {
		t.Fatalf("a wrong password was answered with %s", recorder.Body.String())
	}
}

// The distinction has to be drawn on sql.ErrNoRows specifically, or it is the
// same merge under another name.
func TestTheFaultBranchTestsForNoRows(t *testing.T) {
	// The database identity branch is accountIdentity; Login dispatches to it.
	body := readAuthSource(t, "handlers.go")
	login := authFunction(t, body, "func (h *Handlers) accountIdentity(")

	if !strings.Contains(login, "errors.Is(err, sql.ErrNoRows)") {
		t.Fatal("the login path does not separate a missing row from a driver failure")
	}
	faultAt := strings.Index(login, "errors.Is(err, sql.ErrNoRows)")
	sharedAt := strings.Index(login, "if err != nil || !matches {")
	if faultAt < 0 || sharedAt < 0 {
		t.Fatalf("a branch is missing (fault=%d, shared=%d)", faultAt, sharedAt)
	}
	if faultAt > sharedAt {
		t.Fatal("the driver failure is judged after the shared rejection, so it never reaches its own branch")
	}
	// The timing defence stays: the comparison runs even on a miss.
	if !strings.Contains(login, "matches := PasswordMatches(hash, req.Password)") {
		t.Fatal("the unconditional password comparison was lost")
	}
}

func readAuthSource(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(name) // #nosec G304 -- a file of this package.
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}

// authFunction returns one function's body, from its signature to the closing
// brace in the first column.
func authFunction(t *testing.T, source, signature string) string {
	t.Helper()
	at := strings.Index(source, signature)
	if at < 0 {
		t.Fatalf("%q is not defined", signature)
	}
	body, _, found := strings.Cut(source[at:], "\n}\n")
	if !found {
		t.Fatalf("%q has no closing brace", signature)
	}
	return body
}
