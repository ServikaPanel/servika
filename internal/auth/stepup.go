package auth

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"servika/internal/httpx"
)

// Step-up re-authentication is the check that is supposed to survive a session
// somebody else is holding. A hijacked or left-open browser already carries a
// valid cookie, so the six-digit code is the only thing between that session and
// turning the second factor off.
//
// middleware.LoginRateLimit does not reach these routes, and it counts 401
// responses, which a step-up endpoint must not send: the panel's own client logs
// the user out on 401, so a wrong code would end the session instead of refusing
// the change. The counter therefore lives here and answers 429.
const (
	stepUpMaxFailures = 5
	stepUpLockFor     = 15 * time.Minute
)

type stepUpState struct {
	failures int
	until    time.Time
}

var (
	stepUpMu     sync.Mutex
	stepUpByUser = map[int64]*stepUpState{}
	// stepUpNow is the clock, so a test does not wait for the lock to expire.
	stepUpNow = time.Now
)

// stepUpLocked returns how long this account must wait before its next attempt,
// and zero when it may try now.
func stepUpLocked(userID int64) time.Duration {
	stepUpMu.Lock()
	defer stepUpMu.Unlock()
	state, ok := stepUpByUser[userID]
	if !ok {
		return 0
	}
	if state.until.IsZero() {
		// Failures recorded, the limit not reached yet. The zero time is not an
		// expired lock: reading it as one would drop the counter on every attempt
		// and the limit would never be reached.
		return 0
	}
	remaining := state.until.Sub(stepUpNow())
	if remaining <= 0 {
		// The lock has run out. The counter goes with it, or the next single
		// failure would lock the account again immediately.
		delete(stepUpByUser, userID)
		return 0
	}
	return remaining
}

// stepUpFailed records one wrong code and locks the account at the limit.
func stepUpFailed(userID int64) {
	stepUpMu.Lock()
	defer stepUpMu.Unlock()
	state, ok := stepUpByUser[userID]
	if !ok {
		state = &stepUpState{}
		stepUpByUser[userID] = state
	}
	state.failures++
	if state.failures >= stepUpMaxFailures {
		state.until = stepUpNow().Add(stepUpLockFor)
	}
}

// stepUpPassed clears the counter after a correct code.
func stepUpPassed(userID int64) {
	stepUpMu.Lock()
	defer stepUpMu.Unlock()
	delete(stepUpByUser, userID)
}

// stepUpRefuse answers a locked account with the header that tells a client when
// to come back.
func stepUpRefuse(w http.ResponseWriter, remaining time.Duration) {
	seconds := int(remaining.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	httpx.WriteError(w, http.StatusTooManyRequests,
		fmt.Sprintf("too many failed code attempts — try again in %d minute(s)", seconds/60+1))
}
