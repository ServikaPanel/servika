package customer

import (
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"servika/internal/auth"
	mw "servika/internal/middleware"
)

// goodScript answers both queries a successful login makes.
func goodScript(t *testing.T) *loginScript {
	t.Helper()
	return &loginScript{rows: map[string][]driver.Value{
		identityQuery: account(t, mw.RoleUser, "active"),
		domainQuery:   {int64(42), "example.com"},
	}}
}

// issuedLifetime reports the three places a login states how long the session
// lasts: the cookie Max-Age, the token exp claim, and the expires_at the screen
// counts down from. They must agree, or the screen keeps a session it no longer
// holds, or drops one it still holds.
func issuedLifetime(t *testing.T, handlers *Handlers) (cookieMaxAge int, tokenSec int64, bodySec int64) {
	t.Helper()
	recorder := postLoginWith(t, handlers, goodScript(t), `{"username":"customer","password":"correct-horse"}`)
	if recorder.Code != 200 {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	cookie := sessionCookie(recorder)
	if cookie == nil {
		t.Fatal("no session cookie was set")
	}
	claims, err := auth.Parse(testSecret, cookie.Value)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var body struct {
		ExpiresAt int64 `json:"expires_at"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	now := time.Now()
	return cookie.MaxAge,
		int64(claims.ExpiresAt.Sub(now).Round(time.Second) / time.Second),
		body.ExpiresAt - now.Unix()
}

// The operator sets one session lifetime for the panel. Before this, the
// customer login ignored it and always issued 24 hours, so shortening the panel
// session shortened it for staff only.
func TestTheCustomerSessionUsesTheConfiguredLifetime(t *testing.T) {
	const configured = 900

	maxAge, tokenSec, bodySec := issuedLifetime(t, &Handlers{Secret: testSecret, LifetimeSec: configured})

	if maxAge != configured {
		t.Errorf("cookie Max-Age = %d, want %d", maxAge, configured)
	}
	if tokenSec < configured-5 || tokenSec > configured {
		t.Errorf("token expires in %ds, want about %d", tokenSec, configured)
	}
	if bodySec < configured-5 || bodySec > configured {
		t.Errorf("expires_at is %ds away, want about %d", bodySec, configured)
	}
}

// An unset lifetime must not issue a token that has already expired.
func TestAnUnsetLifetimeFallsBackToTheSameDefaultTheConfigUses(t *testing.T) {
	maxAge, tokenSec, _ := issuedLifetime(t, &Handlers{Secret: testSecret})

	if maxAge != defaultCustomerLifetimeSec {
		t.Errorf("cookie Max-Age = %d, want %d", maxAge, defaultCustomerLifetimeSec)
	}
	if tokenSec <= 0 {
		t.Errorf("the token expires in %ds; it was issued already expired", tokenSec)
	}
}
