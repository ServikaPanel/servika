package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The panel is cookie-only. RequireAuth verifies the session cookie, enforces
// token_version and puts the verified claims in the request context, so a
// self-service handler must read the context and nothing else.
//
// These two are measured against a real handler rather than against `claims`
// directly, because the defect they guard reached production exactly through a
// test that supplied an Authorization header no client sends.

// A bearer token is not an identity here. Accepting one would take the acted-upon
// UserID from a credential nothing checked for revocation, because Parse does not
// look at token_version.
func TestABearerTokenIsNotAnIdentity(t *testing.T) {
	key := []byte("test-jwt-secret-0123456789-abcdef")
	h := &Handlers{Secret: key, LifetimeSec: 3600}

	token, err := Issue(key, 3600, 1, "root", "admin", 0)
	if err != nil {
		t.Fatalf("issue a token: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/me/2fa/setup", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()

	h.TwoFASetup(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; a header carried the identity: %s", recorder.Code, recorder.Body.String())
	}
}

// The context claims ARE the identity, and they arrive with no header at all,
// which is what every request from the panel looks like.
func TestTheContextClaimsAreTheIdentity(t *testing.T) {
	h := &Handlers{Secret: []byte("test-jwt-secret-0123456789-abcdef"), LifetimeSec: 3600}

	request := httptest.NewRequest(http.MethodGet, "/me/2fa/setup", nil)
	request = request.WithContext(WithClaims(request.Context(), &Claims{UserID: 1, Username: "root", Role: "admin"}))
	recorder := httptest.NewRecorder()

	h.TwoFASetup(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; the verified session was not read: %s", recorder.Code, recorder.Body.String())
	}
}
