package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// panelHash returns a hash source and the password that matches it.
func panelHash(t *testing.T) (func() string, string) {
	t.Helper()
	hash, err := hashPanelPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	return func() string { return hash }, "correct horse"
}

// loginRequest posts a login body.
func loginRequest(user, password string) *http.Request {
	body, _ := json.Marshal(map[string]string{"user": user, "password": password})
	return httptest.NewRequest(http.MethodPost, "/api/local/login", strings.NewReader(string(body)))
}

func TestALoginIssuesASessionCookie(t *testing.T) {
	sessions := store(t)
	hashOf, password := panelHash(t)
	rec := httptest.NewRecorder()
	loginHandler(sessions, hashOf)(rec, loginRequest("admin", password))
	if rec.Code != http.StatusOK {
		t.Fatalf("a correct login answered %d: %s", rec.Code, rec.Body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookie || cookies[0].Value == "" {
		t.Fatalf("the login set %v", cookies)
	}
	if !sessions.valid(cookies[0].Value) {
		t.Fatal("the issued token is not in the session store")
	}
}

func TestAFailedLoginSaysOnlyThatSomethingWasWrong(t *testing.T) {
	// Saying which of the two was wrong confirms that the user name exists.
	sessions := store(t)
	hashOf, _ := panelHash(t)
	for _, c := range []struct{ user, password string }{
		{"admin", "wrong"}, {"nobody", "correct horse"},
	} {
		rec := httptest.NewRecorder()
		loginHandler(sessions, hashOf)(rec, loginRequest(c.user, c.password))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%q/%q answered %d", c.user, c.password, rec.Code)
		}
		var body map[string]string
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["error"] != "the user name or the password is wrong" {
			t.Fatalf("the refusal said %q", body["error"])
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Fatal("a failed login set a cookie")
		}
	}
	if sessions.count() != 0 {
		t.Fatal("a failed login created a session")
	}
}

func TestThePasswordIsReadFreshOnEveryAttempt(t *testing.T) {
	// The panel-password command has to take effect without the service being
	// restarted.
	sessions := store(t)
	hash, err := hashPanelPassword("first")
	if err != nil {
		t.Fatal(err)
	}
	hashOf := func() string { return hash }

	rec := httptest.NewRecorder()
	loginHandler(sessions, hashOf)(rec, loginRequest("admin", "first"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the first password was refused: %d", rec.Code)
	}
	if hash, err = hashPanelPassword("second"); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	loginHandler(sessions, hashOf)(rec, loginRequest("admin", "first"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatal("the old password still works after a reset")
	}
	rec = httptest.NewRecorder()
	loginHandler(sessions, hashOf)(rec, loginRequest("admin", "second"))
	if rec.Code != http.StatusOK {
		t.Fatalf("the new password was refused without a restart: %d", rec.Code)
	}
}

func TestLoggingOutWorksWithAnExpiredCookieToo(t *testing.T) {
	// A stale tab has to be able to clear itself.
	sessions := store(t)
	req := httptest.NewRequest(http.MethodPost, "/api/local/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "long-gone"})
	rec := httptest.NewRecorder()
	logoutHandler(sessions)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("a logout with a dead cookie answered %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge >= 0 {
		t.Fatalf("the logout did not clear the cookie: %v", cookies)
	}
}

func TestAnEndpointBehindTheGuardNeedsALiveSession(t *testing.T) {
	sessions := store(t)
	var reached bool
	guarded := sessionGuard(sessions, func(http.ResponseWriter, *http.Request) { reached = true })

	rec := httptest.NewRecorder()
	guarded(rec, httptest.NewRequest(http.MethodGet, "/api/local/summary", nil))
	if reached || rec.Code != http.StatusUnauthorized {
		t.Fatalf("a request with no session reached the handler (code %d)", rec.Code)
	}

	token, err := newSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	sessions.add(token)
	req := httptest.NewRequest(http.MethodGet, "/api/local/summary", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	rec = httptest.NewRecorder()
	guarded(rec, req)
	if !reached {
		t.Fatal("a live session was refused")
	}
}

func TestTheWrongMethodOnLoginAndLogoutIsRefused(t *testing.T) {
	sessions := store(t)
	hashOf, _ := panelHash(t)
	rec := httptest.NewRecorder()
	loginHandler(sessions, hashOf)(rec, httptest.NewRequest(http.MethodGet, "/api/local/login", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("a GET login answered %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	logoutHandler(sessions)(rec, httptest.NewRequest(http.MethodGet, "/api/local/logout", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("a GET logout answered %d", rec.Code)
	}
}

// panelFiles is a small stand-in for the embedded interface.
var panelFiles = fstest.MapFS{
	"index.html":   {Data: []byte("<html>panel</html>")},
	"app.js":       {Data: []byte("console.log(1)")},
	"sub/page.txt": {Data: []byte("nested")},
}

func TestTheInterfaceIsNeverCached(t *testing.T) {
	// The files are served under fixed, unversioned names. Without this a
	// browser goes on running the OLD script after an update, which reads as
	// "the login worked but the panel never appears".
	// /app.js rather than /index.html: net/http redirects the index path to the
	// directory root, and the redirect is not what this is about.
	rec := httptest.NewRecorder()
	staticHandler(panelFiles).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("the interface answered %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Fatalf("the interface is cacheable: %q", got)
	}
}

func TestTheInterfaceCannotBeFramedOrSniffed(t *testing.T) {
	rec := httptest.NewRecorder()
	staticHandler(panelFiles).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("the panel can be framed, so a click can be hijacked")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("the browser may sniff a content type")
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "base-uri 'none'") {
		t.Fatalf("a <base> injection is not blocked: %q", csp)
	}
}

func TestAnUnknownPathIsNotTurnedIntoTheIndexPage(t *testing.T) {
	// Turning every path into index.html hides a mistyped /api path behind an
	// HTML page that looks like it worked.
	rec := httptest.NewRecorder()
	staticHandler(panelFiles).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/local/summry", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown path answered %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "panel") {
		t.Fatal("an unknown path was answered with the index page")
	}
}

func TestADirectoryIsNotListed(t *testing.T) {
	rec := httptest.NewRecorder()
	staticHandler(panelFiles).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("a directory answered %d: %s", rec.Code, rec.Body)
	}
}

func TestOnlyAReadMethodReachesTheInterface(t *testing.T) {
	rec := httptest.NewRecorder()
	staticHandler(panelFiles).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/index.html", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("a POST to the interface answered %d", rec.Code)
	}
}

func TestTheRootServesTheIndexPage(t *testing.T) {
	rec := httptest.NewRecorder()
	staticHandler(panelFiles).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("the root answered %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "panel") {
		t.Fatalf("the root served %q", rec.Body.String())
	}
}
