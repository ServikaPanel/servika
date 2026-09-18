package main

// The local panel's browser sessions.
//
// PERSISTENT: a session survives the agent restarting. An in-memory table
// dropped every session on an update, a crash or a reboot, and the operator had
// to log in again each time. The file lives inside the data directory, which
// the installer locks to SYSTEM and Administrators.
//
// SLIDING: a session's clock is reset on every valid request, so somebody who
// is working is never thrown out; only an IDLE session expires. The disk write
// for a slide is periodic rather than per request, because writing a file on
// every page view is a cost with nothing to show for it.
//
// No build tag: none of this is Windows-specific and all of it is measured on
// every build.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	// sessionCookie is the browser cookie's name.
	sessionCookie = "servika_agent_session"

	// sessionLife is how long a session survives with no activity.
	sessionLife = 3 * time.Hour

	// flushEvery is how often the slid clocks reach disk.
	flushEvery = 2 * time.Minute
)

// sessionStore maps a token to the time it was last used.
type sessionStore struct {
	Path string

	// Every is the flush period. newSessionStore sets it to flushEvery; a test
	// shortens it so flushPeriodically can be observed.
	Every time.Duration

	mu       sync.Mutex
	sessions map[string]time.Time
}

// newSessionStore returns an empty store backed by path.
func newSessionStore(path string) *sessionStore {
	return &sessionStore{Path: path, Every: flushEvery, sessions: map[string]time.Time{}}
}

// load reads the file at startup, dropping whatever has already expired.
func (s *sessionStore) load() {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.Path)
	if err != nil {
		return
	}
	var saved map[string]time.Time
	if json.Unmarshal(b, &saved) != nil {
		return
	}
	for token, last := range saved {
		if time.Since(last) <= sessionLife {
			s.sessions[token] = last
		}
	}
}

// save writes the table atomically. The caller holds the lock.
//
// It is best effort: a failure costs persistence, and must NOT break the login
// or logout the caller is in the middle of.
func (s *sessionStore) save() {
	b, err := json.Marshal(s.sessions)
	if err != nil {
		return
	}
	temp := s.Path + ".new"
	if os.WriteFile(temp, b, 0o600) == nil {
		_ = os.Rename(temp, s.Path)
	}
}

// flushPeriodically writes the slid clocks to disk so a restart does not undo
// them. It runs as its own goroutine.
func (s *sessionStore) flushPeriodically() {
	ticker := time.NewTicker(s.Every)
	defer ticker.Stop()
	for range ticker.C {
		s.flushOnce()
	}
}

// flushOnce drops what has expired and writes the rest.
func (s *sessionStore) flushOnce() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	s.save()
}

// expire drops what has timed out. The caller holds the lock.
func (s *sessionStore) expire() {
	for token, last := range s.sessions {
		if time.Since(last) > sessionLife {
			delete(s.sessions, token)
		}
	}
}

// add records a new session. Expired ones are swept at the same time, so the
// table cannot grow without bound; nothing is added without a successful login.
func (s *sessionStore) add(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	s.sessions[token] = time.Now()
	s.save()
}

// valid reports whether a token is live, and slides its clock when it is.
func (s *sessionStore) valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	last, found := s.sessions[token]
	if !found {
		return false
	}
	if time.Since(last) > sessionLife {
		delete(s.sessions, token)
		s.save()
		return false
	}
	s.sessions[token] = time.Now()
	return true
}

// drop removes a session.
func (s *sessionStore) drop(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
	s.save()
}

// count reports how many sessions are held.
func (s *sessionStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// newSessionToken returns 32 random bytes as hex.
func newSessionToken() (string, error) { return randomHex(32) }

// sessionCookieFor builds the cookie one session is carried in.
//
// HttpOnly keeps a cross-site script from reading it, Secure keeps it off plain
// HTTP (the port is TLS anyway), and SameSite=Strict is the first CSRF defence:
// a request from another origin does not carry it at all. MaxAge matches the
// server-side life, so the browser keeps it across a closed tab for as long as
// the server would have honoured it.
func sessionCookieFor(token string) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionLife / time.Second),
	}
}

// expiredSessionCookie tells the browser to drop the cookie now.
func expiredSessionCookie() *http.Cookie {
	c := sessionCookieFor("")
	c.MaxAge = -1
	return c
}

// dummyHash is a bcrypt hash generated once per process that matches NOTHING:
// its password is 32 random bytes, thrown away as soon as it is hashed.
//
// It exists so a login attempt costs the same whether or not a password hash is
// configured. Without it the "no hash" branch would return far faster than
// bcrypt, and whether the agent has been installed could be read off the
// response time from outside.
var dummyHash = func() []byte {
	password := make([]byte, 32)
	_, _ = rand.Read(password)
	h, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		// This should not happen. A malformed fallback still satisfies "never
		// matches", because the comparison fails to parse it.
		return []byte("the dummy hash could not be generated")
	}
	return h
}()

// checkPanelLogin decides one login attempt.
//
// The bcrypt comparison runs UNCONDITIONALLY, even when the user name is wrong
// and even when no hash is configured. Returning early would leak from the
// response time which of the two was wrong, and whether the agent is set up.
func checkPanelLogin(hash, user, password string) bool {
	stored := []byte(hash)
	configured := len(stored) > 0
	if !configured {
		stored = dummyHash
	}
	matched := bcrypt.CompareHashAndPassword(stored, []byte(password)) == nil
	rightUser := subtle.ConstantTimeCompare([]byte(user), []byte("admin")) == 1
	return configured && rightUser && matched
}

// tokenFromRequest reads the session cookie.
func tokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}
