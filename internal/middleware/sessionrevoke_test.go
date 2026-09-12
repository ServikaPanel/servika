package middleware

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"servika/internal/auth"
	"servika/internal/httpx"

	"github.com/golang-jwt/jwt/v5"
)

// A scripted driver in the shape the other packages use: the two reads
// RequireAuth performs are answered by a query fragment each, so a test decides
// only the rule it is about.
type revokeScript struct {
	mu sync.Mutex
	// values maps a query fragment to the single column the read scans.
	values map[string]int64
	// fail maps a query fragment to the error the driver answers with.
	fail map[string]error
	// asked records every query the middleware sent, in order.
	asked []string
}

func (s *revokeScript) answer(query string) (driver.Rows, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, query)
	for fragment, err := range s.fail {
		if strings.Contains(query, fragment) {
			return nil, err
		}
	}
	for fragment, value := range s.values {
		if strings.Contains(query, fragment) {
			return &revokeRows{value: value}, nil
		}
	}
	return nil, fmt.Errorf("the test script has no answer for: %s", query)
}

func (s *revokeScript) queries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.asked...)
}

type revokeRows struct {
	value int64
	done  bool
}

func (r *revokeRows) Columns() []string { return []string{"v"} }
func (r *revokeRows) Close() error      { return nil }
func (r *revokeRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.value
	return nil
}

type revokeConn struct{ script *revokeScript }

func (c revokeConn) Connect(context.Context) (driver.Conn, error) { return c, nil }
func (c revokeConn) Driver() driver.Driver                        { return revokeDriver{} }
func (c revokeConn) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("unused") }
func (c revokeConn) Close() error                                 { return nil }
func (c revokeConn) Begin() (driver.Tx, error)                    { return nil, errors.New("unused") }

func (c revokeConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	return c.script.answer(query)
}

func (c revokeConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

type revokeDriver struct{}

func (revokeDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

const (
	versionRead = "SELECT token_version"
	revokedRead = "FROM revoked_sessions"
	// The idle timeout is the third read RequireAuth makes. Every script answers
	// 0 (feature off), so it decides nothing here.
	idleRead = "session_idle_minutes"
)

// script builds a scripted database that answers the reads a test does not care
// about, and the ones it does.
func script(values map[string]int64, fail map[string]error) *revokeScript {
	answers := map[string]int64{versionRead: 3, idleRead: 0}
	maps.Copy(answers, values)
	return &revokeScript{values: answers, fail: fail}
}

var authSecret = []byte(strings.Repeat("s", 32))

// guarded runs one request carrying the given token through RequireAuth against
// the scripted database, and reports the status plus whether the protected
// handler ran.
func guarded(t *testing.T, sc *revokeScript, token string) (int, bool) {
	t.Helper()
	db := sql.OpenDB(revokeConn{script: sc})
	t.Cleanup(func() { _ = db.Close() })
	original := scopeDB
	Init(db)
	resetStateCache()
	t.Cleanup(func() { scopeDB = original; resetStateCache() })

	reached := false
	handler := RequireAuth(authSecret)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: httpx.SessionCookie, Value: token})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code, reached
}

// liveToken issues a token whose account version is the one the script answers.
func liveToken(t *testing.T) string {
	t.Helper()
	token, err := auth.Issue(authSecret, 3600, 7, "operator", RoleAdmin, 3)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return token
}

// legacyToken signs a token with NO jti, the shape every session issued before
// the claim existed carries. auth.Issue can no longer produce one, so it is
// assembled here rather than faked at the check.
func legacyToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	claims := auth.Claims{
		UserID:       7,
		Username:     "operator",
		Role:         RoleAdmin,
		TokenVersion: 3,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			Issuer:    "servika",
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(authSecret)
	if err != nil {
		t.Fatalf("sign a token with no identifier: %v", err)
	}
	return token
}

// A logout lists the session it surrendered. Before this, signing out cleared
// only the cookie and the token stayed usable for the rest of its lifetime.
func TestASignedOutSessionIsRefusedEvenThoughItsTokenIsStillValid(t *testing.T) {
	code, reached := guarded(t, script(map[string]int64{revokedRead: 1}, nil), liveToken(t))

	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", code, http.StatusUnauthorized)
	}
	if reached {
		t.Fatal("the signed-out session reached the protected handler")
	}
}

// The account-wide check is not what refused it: token_version still matches,
// so a logout must not have bumped it. Otherwise one device signing out would
// take every other device down with it.
func TestALogoutIsCheckedPerSessionAndNotPerAccount(t *testing.T) {
	sc := script(map[string]int64{revokedRead: 0}, nil)

	code, reached := guarded(t, sc, liveToken(t))

	if code != http.StatusOK || !reached {
		t.Fatalf("a session that was not signed out was refused: status = %d, reached = %t", code, reached)
	}
	asked := sc.queries()
	if len(asked) < 2 || !strings.Contains(asked[0], versionRead) || !strings.Contains(asked[1], revokedRead) {
		t.Fatalf("the account read and then the session read did not both run: %v", asked)
	}
}

// Fail closed, exactly as the token_version check does: "I cannot check" must
// never become "it is fine", or a database outage hands every signed-out
// session back.
func TestASessionIsRefusedWhenTheRevocationListCannotBeRead(t *testing.T) {
	sc := script(nil, map[string]error{revokedRead: errors.New("the database is unreachable")})

	code, reached := guarded(t, sc, liveToken(t))

	if code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", code, http.StatusServiceUnavailable)
	}
	if reached {
		t.Fatal("the unverifiable session reached the protected handler")
	}
}

// A session opened before the jti claim existed carries none. Refusing those
// would sign every operator out the moment the panel restarted after the
// upgrade, and there is nothing to look up for them either way.
func TestATokenWithNoSessionIdentifierIsNotLookedUp(t *testing.T) {
	sc := script(nil, nil)

	code, reached := guarded(t, sc, legacyToken(t))

	if code != http.StatusOK || !reached {
		t.Fatalf("a token issued before the claim existed was refused: status = %d, reached = %t", code, reached)
	}
	for _, query := range sc.queries() {
		if strings.Contains(query, revokedRead) {
			t.Errorf("a token with no identifier was looked up anyway: %s", query)
		}
	}
}
