package customer

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"servika/internal/auth"
	"servika/internal/httpx"
	mw "servika/internal/middleware"
)

// A scripted driver in the shape internal/auth uses for the other login
// handler: the repository carries no sqlmock dependency, and every rule under
// test is decided by the row the account lookup returns.
type loginScript struct {
	mu   sync.Mutex
	rows map[string][]driver.Value
	// empty maps a query fragment to the column count of an empty result set,
	// which is what makes Scan report sql.ErrNoRows rather than a column error.
	empty map[string]int
}

func (s *loginScript) answer(query string) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fragment, columns := range s.empty {
		if strings.Contains(query, fragment) {
			return &loginRows{values: make([]driver.Value, columns), done: true}, nil
		}
	}
	for fragment, values := range s.rows {
		if strings.Contains(query, fragment) {
			return &loginRows{values: values}, nil
		}
	}
	return nil, fmt.Errorf("the test script has no answer for: %s", query)
}

type loginRows struct {
	values []driver.Value
	done   bool
}

func (r *loginRows) Columns() []string { return make([]string, len(r.values)) }
func (r *loginRows) Close() error      { return nil }
func (r *loginRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

type loginConn struct{ script *loginScript }

func (c loginConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c loginConn) Driver() driver.Driver                        { return loginDriver{} }
func (c loginConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c loginConn) Close() error                                 { return nil }
func (c loginConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c loginConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.script.answer(query)
}

// The audit insert and the last-login update are accepted and ignored: neither
// decides whether a session is issued.
func (c loginConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

type loginDriver struct{}

func (loginDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

const (
	identityQuery = "password_hash, role, status, token_version"
	domainQuery   = "FROM domains d"
)

// account scripts a known account whose password is "correct-horse".
func account(t *testing.T, role, status string) []driver.Value {
	t.Helper()
	hash, err := auth.HashPassword("correct-horse")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// Order matches the SELECT in Login.
	return []driver.Value{int64(12), hash, role, status, int64(3)}
}

func login(t *testing.T, script *loginScript, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	return postLogin(t, script, `{"username":"`+username+`","password":"`+password+`"}`)
}

// postLogin sends one raw body, so a test can send what a client cannot.
func postLogin(t *testing.T, script *loginScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	return postLoginWith(t, &Handlers{Secret: testSecret}, script, body)
}

var testSecret = []byte(strings.Repeat("k", 32))

// postLoginWith runs the login against a caller-built Handlers, so a test can
// set the configured session lifetime. The DB is filled in from the script.
func postLoginWith(t *testing.T, handlers *Handlers, script *loginScript, body string) *httptest.ResponseRecorder {
	t.Helper()
	db := sql.OpenDB(loginConn{script: script})
	t.Cleanup(func() { _ = db.Close() })
	handlers.DB = db
	recorder := httptest.NewRecorder()
	handlers.Login(recorder, httptest.NewRequest(http.MethodPost, "/customer/login", strings.NewReader(body)))
	return recorder
}

func sessionCookie(recorder *httptest.ResponseRecorder) *http.Cookie {
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == httpx.SessionCookie {
			return cookie
		}
	}
	return nil
}

// An administrator or a reseller who
// reaches it with their correct password gets the answer a wrong password gets,
// or it becomes a second way into their accounts that skips the management
// panel's checks.
func TestOnlyACustomerAccountCanSignInHere(t *testing.T) {
	for _, role := range []string{mw.RoleAdmin, mw.RoleReseller} {
		t.Run(role, func(t *testing.T) {
			script := &loginScript{rows: map[string][]driver.Value{
				identityQuery: account(t, role, "active"),
				domainQuery:   {int64(42), "example.com"},
			}}

			recorder := login(t, script, "operator", "correct-horse")

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
			}
			if sessionCookie(recorder) != nil {
				t.Fatalf("a %s account was given a customer session cookie", role)
			}
		})
	}
}

// A request carrying no credential is refused before the account lookup: there
// is nothing to check, and the empty script would answer a lookup with a fault.
func TestARequestWithNoCredentialIsRefusedBeforeTheLookup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		message string
	}{
		{name: "not JSON", body: "{", message: "invalid request body"},
		{
			name:    "no username",
			body:    `{"password":"correct-horse"}`,
			message: "username and password are required",
		},
		{
			name:    "a username of spaces",
			body:    `{"username":"   ","password":"correct-horse"}`,
			message: "username and password are required",
		},
		{
			name:    "no password",
			body:    `{"username":"customer"}`,
			message: "username and password are required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := postLogin(t, &loginScript{}, tc.body)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), tc.message) {
				t.Errorf("answer = %s, want %q", recorder.Body.String(), tc.message)
			}
			if sessionCookie(recorder) != nil {
				t.Error("a request with no credential was given a session cookie")
			}
		})
	}
}

// Two different answers would tell an attacker which usernames exist.
func TestAnUnknownUsernameAndAWrongPasswordAnswerAlike(t *testing.T) {
	unknown := login(t, &loginScript{empty: map[string]int{identityQuery: 5}}, "nobody", "correct-horse")
	wrong := login(t, &loginScript{rows: map[string][]driver.Value{
		identityQuery: account(t, mw.RoleUser, "active"),
	}}, "customer", "the-wrong-password")

	if unknown.Code != http.StatusUnauthorized || wrong.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d and %d, want %d for both", unknown.Code, wrong.Code, http.StatusUnauthorized)
	}
	if unknown.Body.String() != wrong.Body.String() {
		t.Errorf("the two rejections differ:\n unknown: %s\n   wrong: %s", unknown.Body.String(), wrong.Body.String())
	}
}

// A driver failure is a fault, not a wrong credential, the same distinction the
// management login draws.
func TestADatabaseFailureIsNotReportedAsAWrongPassword(t *testing.T) {
	recorder := login(t, &loginScript{}, "customer", "correct-horse")

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusInternalServerError, recorder.Body.String())
	}
}

// A suspended customer gets no session, and neither does an account with no
// domain: the screen would land on /subscriptions/0, so the reason is stated
// instead.
func TestTheRightPasswordIsNotEnoughForACustomerSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script func(t *testing.T) *loginScript
		reason string
	}{
		{"a suspended customer", func(t *testing.T) *loginScript {
			return &loginScript{rows: map[string][]driver.Value{
				identityQuery: account(t, mw.RoleUser, "suspended"),
				domainQuery:   {int64(42), "example.com"},
			}}
		}, "account is suspended"},
		{"an account with no service", func(t *testing.T) *loginScript {
			return &loginScript{
				rows:  map[string][]driver.Value{identityQuery: account(t, mw.RoleUser, "active")},
				empty: map[string]int{domainQuery: 2},
			}
		}, "no service is linked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := login(t, tc.script(t), "customer", "correct-horse")

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusForbidden, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), tc.reason) {
				t.Fatalf("the refusal does not name the reason %q: %s", tc.reason, recorder.Body.String())
			}
			if sessionCookie(recorder) != nil {
				t.Fatal("the refused account was given a session cookie")
			}
		})
	}
}

// The token is kept out of the body so script on the page can never read it.
func TestTheCustomerTokenTravelsOnlyInTheHttpOnlyCookie(t *testing.T) {
	script := &loginScript{rows: map[string][]driver.Value{
		identityQuery: account(t, mw.RoleUser, "active"),
		domainQuery:   {int64(42), "example.com"},
	}}

	recorder := login(t, script, "customer", "correct-horse")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	cookie := sessionCookie(recorder)
	if cookie == nil || cookie.Value == "" {
		t.Fatal("no session cookie was set")
	}
	if !cookie.HttpOnly {
		t.Error("the session cookie is readable by JavaScript")
	}
	if strings.Contains(recorder.Body.String(), cookie.Value) {
		t.Error("the response body carries the session token")
	}
	if !strings.Contains(recorder.Body.String(), `"domain_id":42`) {
		t.Errorf("the response does not name the first domain: %s", recorder.Body.String())
	}
}
