package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// store returns a session store backed by a directory the test owns.
func store(t *testing.T) *sessionStore {
	t.Helper()
	dir := t.TempDir()
	return newSessionStore(filepath.Join(dir, "sessions.json"))
}

func TestASessionSurvivesTheAgentRestarting(t *testing.T) {
	// An in-memory table dropped every session on an update, a crash or a
	// reboot, and the operator had to log in again each time.
	first := store(t)
	token, err := newSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	first.add(token)

	second := newSessionStore(first.Path)
	second.load()
	if !second.valid(token) {
		t.Fatal("the session did not survive the restart")
	}
}

func TestAnExpiredSessionIsNotLoadedBackFromDisk(t *testing.T) {
	s := store(t)
	old := map[string]time.Time{"stale": time.Now().Add(-2 * sessionLife)}
	b, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s.load()
	if s.valid("stale") {
		t.Fatal("an expired session came back from disk")
	}
	if s.count() != 0 {
		t.Fatalf("the store holds %d sessions", s.count())
	}
}

func TestAnUnreadableSessionFileIsNotAFailure(t *testing.T) {
	// A first run has no file at all, and a corrupt one must not stop the panel
	// from starting; it only costs the sessions.
	s := store(t)
	s.load()
	if s.count() != 0 {
		t.Fatal("a missing file produced sessions")
	}
	if err := os.WriteFile(s.Path, []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.load()
	if s.count() != 0 {
		t.Fatal("a corrupt file produced sessions")
	}
}

func TestAWorkingOperatorIsNeverThrownOut(t *testing.T) {
	// The clock slides on every valid request, so only an IDLE session expires.
	s := store(t)
	s.add("live")
	// Push the stored time back to just inside the window, then use it: the
	// slide has to reset the clock rather than leave it where it was.
	s.mu.Lock()
	s.sessions["live"] = time.Now().Add(-sessionLife + time.Minute)
	s.mu.Unlock()
	if !s.valid("live") {
		t.Fatal("a session inside the window was refused")
	}
	s.mu.Lock()
	last := s.sessions["live"]
	s.mu.Unlock()
	if time.Since(last) > time.Second {
		t.Fatalf("the clock was not slid; it still reads %v ago", time.Since(last))
	}
}

func TestAnIdleSessionExpires(t *testing.T) {
	s := store(t)
	s.add("idle")
	s.mu.Lock()
	s.sessions["idle"] = time.Now().Add(-sessionLife - time.Minute)
	s.mu.Unlock()
	if s.valid("idle") {
		t.Fatal("an idle session past its life was accepted")
	}
	if s.count() != 0 {
		t.Fatal("the expired session was left in the table")
	}
}

func TestAnUnknownTokenIsRefused(t *testing.T) {
	s := store(t)
	if s.valid("") || s.valid("never-issued") {
		t.Fatal("an unknown token was accepted")
	}
}

func TestLoggingOutDropsTheSessionEverywhere(t *testing.T) {
	s := store(t)
	s.add("going")
	s.drop("going")
	if s.valid("going") {
		t.Fatal("the session survived the logout")
	}
	reloaded := newSessionStore(s.Path)
	reloaded.load()
	if reloaded.valid("going") {
		t.Fatal("the dropped session came back from disk")
	}
}

func TestExpiredSessionsAreSweptWhenANewOneIsAdded(t *testing.T) {
	// Nothing is added without a successful login, so this is where the table is
	// kept from growing without bound.
	s := store(t)
	s.add("old")
	s.mu.Lock()
	s.sessions["old"] = time.Now().Add(-sessionLife - time.Minute)
	s.mu.Unlock()
	s.add("new")
	if s.count() != 1 {
		t.Fatalf("the table holds %d sessions, expected 1", s.count())
	}
}

func TestASessionTokenIsLongAndUnique(t *testing.T) {
	first, err := newSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 64 {
		t.Fatalf("the token is %d characters, expected 64", len(first))
	}
	if first == second {
		t.Fatal("two session tokens are identical")
	}
}

func TestTheSessionFileIsNotWorldReadable(t *testing.T) {
	// It holds live session tokens.
	s := store(t)
	s.add("t")
	fi, err := os.Stat(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the session file is mode %v", fi.Mode().Perm())
	}
}

func TestTheSessionCookieCannotBeReadOrCarriedCrossSite(t *testing.T) {
	c := sessionCookieFor("abc")
	if !c.HttpOnly {
		t.Fatal("a cross-site script can read the session cookie")
	}
	if !c.Secure {
		t.Fatal("the session cookie would travel over plain HTTP")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatal("the session cookie is carried on a cross-origin request, which is the CSRF defence")
	}
	if c.MaxAge != int(sessionLife/time.Second) {
		t.Fatalf("the cookie lives %d seconds while the server honours %v", c.MaxAge, sessionLife)
	}
}

func TestLoggingOutTellsTheBrowserToDropTheCookieNow(t *testing.T) {
	c := expiredSessionCookie()
	if c.MaxAge >= 0 {
		t.Fatalf("the logout cookie has MaxAge %d, so the browser keeps it", c.MaxAge)
	}
	if c.Value != "" {
		t.Fatal("the logout cookie still carries a token")
	}
}

func TestOnlyTheRightUserAndPasswordLogIn(t *testing.T) {
	hash, err := hashPanelPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !checkPanelLogin(hash, "admin", "correct horse") {
		t.Fatal("the right credentials were refused")
	}
	for _, c := range []struct{ user, password string }{
		{"admin", "wrong"}, {"root", "correct horse"}, {"", "correct horse"},
		{"Admin", "correct horse"}, {"admin", ""},
	} {
		if checkPanelLogin(hash, c.user, c.password) {
			t.Errorf("the credentials %q/%q were accepted", c.user, c.password)
		}
	}
}

func TestAnAgentWithNoPasswordHashLetsNobodyIn(t *testing.T) {
	// A half-written settings file must not open the panel to anyone.
	if checkPanelLogin("", "admin", "") || checkPanelLogin("", "admin", "anything") {
		t.Fatal("an agent with no password hash accepted a login")
	}
}

func TestAFailedLoginCostsTheSameWhicheverPartWasWrong(t *testing.T) {
	// Returning early on a wrong user name, or when no hash is configured, would
	// leak from the response time which part was wrong and whether the agent is
	// even set up.
	hash, err := hashPanelPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	measure := func(h, user, password string) time.Duration {
		start := time.Now()
		checkPanelLogin(h, user, password)
		return time.Since(start)
	}
	wrongPassword := measure(hash, "admin", "wrong")
	wrongUser := measure(hash, "nobody", "wrong")
	noHash := measure("", "admin", "wrong")
	// bcrypt at the default cost takes tens of milliseconds. A branch that
	// skipped it would return in well under a millisecond.
	floor := wrongPassword / 4
	if wrongUser < floor {
		t.Fatalf("a wrong user name returned in %v against %v, so the comparison was skipped", wrongUser, wrongPassword)
	}
	if noHash < floor {
		t.Fatalf("an unconfigured agent returned in %v against %v, so its state is visible from outside", noHash, wrongPassword)
	}
}

func TestTheSessionTokenIsReadFromTheCookieAndNowhereElse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/local/summary", nil)
	if got := tokenFromRequest(req); got != "" {
		t.Fatalf("a request with no cookie produced the token %q", got)
	}
	// A token in a header or a query string must not be honoured: it would
	// travel in logs and in the Referer.
	req.Header.Set("Authorization", "Bearer abc")
	req.URL.RawQuery = "session=abc"
	if got := tokenFromRequest(req); got != "" {
		t.Fatalf("the token was taken from somewhere other than the cookie: %q", got)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "abc"})
	if got := tokenFromRequest(req); got != "abc" {
		t.Fatalf("the cookie token read as %q", got)
	}
}

// TestTheStoreFlushesTheSlidClocksOnItsOwn proves the background flush reaches
// disk. Without it a restart would undo every slide since the last login.
func TestTheStoreFlushesTheSlidClocksOnItsOwn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	store := newSessionStore(path)
	store.Every = 5 * time.Millisecond
	token, err := newSessionToken()
	if err != nil {
		t.Fatalf("the token could not be made: %v", err)
	}
	store.add(token)
	go store.flushPeriodically()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			var saved map[string]time.Time
			if json.Unmarshal(b, &saved) == nil {
				if _, found := saved[token]; found {
					return
				}
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the session never reached disk")
}
