package auth

import (
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/httpx"
)

// The management panel and the customer panel are separated by one role
// comparison in each login handler. These tests pin the management side: a
// correct password is not enough when the account is a customer's or is
// suspended, and the session reaches the browser only as the HttpOnly cookie.

// managementIdentity scripts the account lookup for a known account whose
// password is "correct-horse".
func managementIdentity(t *testing.T, role, status string) map[string][]driver.Value {
	t.Helper()
	return map[string][]driver.Value{
		// Order matches the SELECT in Login.
		"password_hash, role, status": {int64(7), "operator", mustHash(t, "correct-horse"), role, status, "Operator"},
	}
}

func managementSessionCookie(recorder *httptest.ResponseRecorder) *http.Cookie {
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == httpx.SessionCookie {
			return cookie
		}
	}
	return nil
}

// A customer who types their correct password here must not come away with a
// management-panel session, since customers sign in at /customer/login, and a
// suspended account must not come away with any session at all.
func TestTheRightPasswordIsNotEnoughForAManagementSession(t *testing.T) {
	for _, tc := range []struct {
		name, role, status, reason string
	}{
		{"a customer account", "user", "active", "cannot sign in to the management panel"},
		{"a suspended account", "admin", "suspended", "account is suspended"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := &totpScript{rows: managementIdentity(t, tc.role, tc.status)}

			recorder := runLogin(t, script, "operator", "correct-horse")

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusForbidden, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), tc.reason) {
				t.Fatalf("the refusal does not name the reason %q: %s", tc.reason, recorder.Body.String())
			}
			if managementSessionCookie(recorder) != nil {
				t.Fatal("the refused account was given a session cookie")
			}
		})
	}
}

// The token is kept out of the body so script on the page can never read it.
func TestTheManagementTokenTravelsOnlyInTheHttpOnlyCookie(t *testing.T) {
	// A successful administrator login refreshes the update manifest, which is a
	// network request this test must not make.
	t.Setenv("SERVIKA_VERSION_CHECK", "0")
	rows := managementIdentity(t, "admin", "active")
	rows["totp_enabled, totp_secret"] = []driver.Value{int64(0), "", int64(0)}
	rows["SELECT token_version"] = []driver.Value{int64(1)}
	script := &totpScript{rows: rows}

	recorder := runLogin(t, script, "operator", "correct-horse")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	cookie := managementSessionCookie(recorder)
	if cookie == nil || cookie.Value == "" {
		t.Fatal("no session cookie was set")
	}
	if !cookie.HttpOnly {
		t.Error("the session cookie is readable by JavaScript")
	}
	if strings.Contains(recorder.Body.String(), cookie.Value) {
		t.Error("the response body carries the session token")
	}
}
