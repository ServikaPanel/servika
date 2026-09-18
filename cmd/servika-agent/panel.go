package main

// The local panel's own front door: the session guard, login and logout, and
// the static interface.
//
// TWO DOORS, ONE PROCESS. Port 8460 is the agent API the panel talks to with a
// shared token. Port 8443 is this: the browser interface for a Windows server
// that stands ALONE and is not registered with any panel. Both listen in the
// same process with the SAME certificate, so an operator sees one identity and
// approves one exception.
//
// No build tag. The guard, the login decision and the static rules are plain
// Go, so they are measured on every build.

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"servika/internal/logx"
)

// failedLoginDelay is a FIXED wait after every failed login.
//
// It slows a brute force down, and because it is the same for every failure the
// reason for one cannot be read off the timing either.
const failedLoginDelay = 500 * time.Millisecond

// panelJSON writes one JSON answer for the local panel.
func panelJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// sessionGuard refuses a request without a live session.
func sessionGuard(sessions *sessionStore, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sessions.valid(tokenFromRequest(r)) {
			panelJSON(w, http.StatusUnauthorized, map[string]string{"error": "a session is required"})
			return
		}
		next(w, r)
	}
}

// loginHandler answers POST /api/local/login.
//
// currentHash is read on EVERY attempt rather than captured once, so the
// panel-password command takes effect without the service being restarted.
func loginHandler(sessions *sessionStore, currentHash func() string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodFailure(w, r)
			return
		}
		var request struct {
			User     string `json:"user"`
			Password string `json:"password"`
		}
		if !readRequest(w, r, &request) {
			return
		}
		if !checkPanelLogin(currentHash(), request.User, request.Password) {
			time.Sleep(failedLoginDelay)
			logx.Warnf("local panel: a login attempt FAILED (%s)", r.RemoteAddr)
			// The message is deliberately ONE: which of the two was wrong is not
			// said, because saying it would confirm the user name exists.
			panelJSON(w, http.StatusUnauthorized, map[string]string{"error": "the user name or the password is wrong"})
			return
		}
		token, err := newSessionToken()
		if err != nil {
			panelJSON(w, http.StatusInternalServerError, map[string]string{"error": "the session token could not be generated"})
			return
		}
		sessions.add(token)
		http.SetCookie(w, sessionCookieFor(token))
		logx.Infof("local panel: admin logged in (%s)", r.RemoteAddr)
		panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// logoutHandler answers POST /api/local/logout.
//
// A live session is NOT required. Logging out is idempotent and has to work
// with an expired cookie too, or a stale tab can never clear itself.
func logoutHandler(sessions *sessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodFailure(w, r)
			return
		}
		if token := tokenFromRequest(r); token != "" {
			sessions.drop(token)
		}
		http.SetCookie(w, expiredSessionCookie())
		panelJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// staticHandler serves the interface from the root.
//
// No session is required here, because the login page itself is served from it.
// Every DATA endpoint is behind the session guard.
//
// THERE IS NO SINGLE-PAGE FALLBACK. An unknown path answers 404 rather than
// index.html: there is only one page, and turning every path into it would hide
// a mistyped /api path behind an HTML page that looks like it worked.
func staticHandler(files fs.FS) http.Handler {
	server := http.FileServer(http.FS(files))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodFailure(w, r)
			return
		}
		// A trailing slash below the root would list a directory.
		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		writeStaticHeaders(w)
		server.ServeHTTP(w, r)
	})
}

// writeStaticHeaders sets what every static response carries.
//
// NO-CACHE IS REQUIRED. The embedded files are served under fixed, unversioned
// names. With no cache header a browser keeps them on its own judgement and
// goes on running the OLD script after the agent is updated, which reads as
// "the login worked but the panel never appears".
//
// The security headers cover clickjacking, MIME sniffing and a <base>
// injection. There is deliberately no default-src or script-src: the interface
// may use an inline script, and a strict policy applied without checking would
// simply break the panel.
func writeStaticHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; object-src 'none'; base-uri 'none'")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
}
