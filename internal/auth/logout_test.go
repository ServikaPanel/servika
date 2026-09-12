package auth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"servika/internal/httpx"
)

// A recording driver: the question a logout test asks is what was WRITTEN, so
// the statement and its arguments are captured rather than answered.
type logoutRecorder struct {
	mu    sync.Mutex
	execs []recordedExec
}

type recordedExec struct {
	query string
	args  []driver.NamedValue
}

func (rec *logoutRecorder) record(query string, args []driver.NamedValue) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.execs = append(rec.execs, recordedExec{query: query, args: args})
}

// revocationOf returns the recorded INSERT into revoked_sessions, or nil.
func (rec *logoutRecorder) revocationOf() *recordedExec {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for i := range rec.execs {
		if strings.Contains(rec.execs[i].query, "revoked_sessions") {
			return &rec.execs[i]
		}
	}
	return nil
}

type logoutConn struct{ rec *logoutRecorder }

func (c logoutConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c logoutConn) Driver() driver.Driver                        { return logoutDriver{} }
func (c logoutConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c logoutConn) Close() error                                 { return nil }
func (c logoutConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c logoutConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.rec.record(query, args)
	return driver.RowsAffected(1), nil
}

type logoutDriver struct{}

func (logoutDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

var logoutSecret = []byte(strings.Repeat("L", 32))

// signOut posts a logout carrying the given cookie value, and reports what the
// handler wrote and answered. An empty value sends no cookie at all.
func signOut(t *testing.T, cookieValue string) (*logoutRecorder, *httptest.ResponseRecorder) {
	t.Helper()
	rec := &logoutRecorder{}
	db := sql.OpenDB(logoutConn{rec: rec})
	t.Cleanup(func() { _ = db.Close() })

	request := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	if cookieValue != "" {
		request.AddCookie(&http.Cookie{Name: httpx.SessionCookie, Value: cookieValue})
	}
	response := httptest.NewRecorder()
	(&Handlers{DB: db, Secret: logoutSecret}).Logout(response, request)
	return rec, response
}

// clearedCookie returns the session cookie the answer expires, or nil.
func clearedCookie(response *httptest.ResponseRecorder) *http.Cookie {
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == httpx.SessionCookie {
			return cookie
		}
	}
	return nil
}

// Signing out used to clear the cookie and nothing else, so the token the
// browser had just stopped sending stayed valid for the rest of its lifetime.
func TestSigningOutRecordsTheSurrenderedSession(t *testing.T) {
	token, err := Issue(logoutSecret, 3600, 7, "operator", "admin", 3)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := Parse(logoutSecret, token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	rec, response := signOut(t, token)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	revocation := rec.revocationOf()
	if revocation == nil {
		t.Fatal("the logout wrote nothing to revoked_sessions")
	}
	if len(revocation.args) == 0 || revocation.args[0].Value != claims.ID {
		t.Fatalf("the row does not name this session: args = %v, want jti %q", revocation.args, claims.ID)
	}
	if claims.ID == "" {
		t.Fatal("the issued token carries no session identifier")
	}
}

// A logout must not bump users.token_version: that ends every session the
// account holds, and signing out of one device must not sign out the others.
func TestSigningOutDoesNotEndTheAccountsOtherSessions(t *testing.T) {
	token, err := Issue(logoutSecret, 3600, 7, "operator", "admin", 3)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	rec, _ := signOut(t, token)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, exec := range rec.execs {
		if strings.Contains(exec.query, "token_version") {
			t.Fatalf("the logout bumped the account-wide counter: %s", exec.query)
		}
	}
}

// The endpoint is public and must still answer. A request with no cookie, or
// one carrying a value that is not a token this panel signed, has no session to
// record; the cookie is expired regardless.
func TestALogoutWithNothingToRecordStillClearsTheCookie(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cookie string
	}{
		{"no cookie at all", ""},
		{"a value that is not a token", "not-a-token"},
		{"a token signed with another key", otherKeyToken(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, response := signOut(t, tc.cookie)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
			}
			if revocation := rec.revocationOf(); revocation != nil {
				t.Errorf("a request with no valid session wrote a row anyway: %s", revocation.query)
			}
			cookie := clearedCookie(response)
			if cookie == nil || cookie.MaxAge >= 0 {
				t.Fatalf("the session cookie was not expired: %+v", cookie)
			}
		})
	}
}

// otherKeyToken signs a well-formed token this panel's key cannot verify.
func otherKeyToken(t *testing.T) string {
	t.Helper()
	token, err := Issue([]byte(strings.Repeat("X", 32)), 3600, 7, "operator", "admin", 3)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return token
}

// Two sessions must be distinguishable, or listing one would end the other.
func TestEverySessionGetsItsOwnIdentifier(t *testing.T) {
	seen := map[string]bool{}
	for range 64 {
		token, err := Issue(logoutSecret, 3600, 7, "operator", "admin", 3)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		claims, err := Parse(logoutSecret, token)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if claims.ID == "" {
			t.Fatal("a token was issued with no session identifier")
		}
		if seen[claims.ID] {
			t.Fatalf("two sessions share the identifier %q", claims.ID)
		}
		seen[claims.ID] = true
	}
}
