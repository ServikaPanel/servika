package middleware

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func captureLockoutLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previousOutput, previousFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	resetLockoutLog()
	resetLoginState(t)
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
		resetLockoutLog()
	})
	return &buf
}

// resetLoginState clears both limiter maps so one case cannot decide the next.
func resetLoginState(t *testing.T) {
	t.Helper()
	clearLimiterState()
	t.Cleanup(clearLimiterState)
}

func clearLimiterState() {
	loginMu.Lock()
	loginMap = map[string]*loginRecord{}
	loginMu.Unlock()
	accountMu.Lock()
	accountMap = map[string]*loginRecord{}
	accountMu.Unlock()
}

// rejecting is a handler that answers 401, which is what the limiter counts.
func rejecting() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
}

func loginAttempt(handler http.Handler, address, username string) *httptest.ResponseRecorder {
	body := `{"username":"` + username + `","password":"wrong"}`
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	request.RemoteAddr = address + ":40000"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// The limiter returns 429 BEFORE next.ServeHTTP, so the login handler never
// runs and the audit rows it writes for a failed login stop with it. Without a
// record of the lock itself, an attack that ran for hours appears as exactly
// five failures and then nothing.
func TestTheAddressLockoutIsRecorded(t *testing.T) {
	logged := captureLockoutLog(t)
	handler := LoginRateLimit(rejecting())

	for range loginMaxFail {
		loginAttempt(handler, "203.0.113.7", "operator")
	}

	body := logged.String()
	if !strings.Contains(body, lockoutActionAddress) {
		t.Errorf("the address lockout was not recorded: %s", body)
	}
	if !strings.Contains(body, "203.0.113.7") {
		t.Errorf("the record does not name the address: %s", body)
	}
}

// The per-account lock is documented as a weapon anyone can fire. When it fires
// against a real operator, the record is the only thing that says which account
// was locked and from where.
func TestTheAccountLockoutIsRecordedWithItsSource(t *testing.T) {
	logged := captureLockoutLog(t)
	handler := LoginRateLimit(rejecting())

	// Spread across addresses, so the per-address lock does not engage first:
	// that is the distributed case the per-account counter exists for.
	for i := range accountMaxFail {
		loginAttempt(handler, addressFor(i), "operator")
	}

	body := logged.String()
	if !strings.Contains(body, lockoutActionAccount) {
		t.Errorf("the account lockout was not recorded: %s", body)
	}
	if !strings.Contains(body, `"operator"`) {
		t.Errorf("the record does not name the locked account: %s", body)
	}
}

// A locked address can be retried as fast as the attacker likes, so the refused
// attempts are logged on a throttle rather than one line per packet.
func TestBlockedAttemptsAreLoggedButThrottled(t *testing.T) {
	logged := captureLockoutLog(t)
	handler := LoginRateLimit(rejecting())
	for range loginMaxFail {
		loginAttempt(handler, "203.0.113.7", "operator")
	}
	logged.Reset()

	for range 25 {
		if got := loginAttempt(handler, "203.0.113.7", "operator").Code; got != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want %d; the lock did not engage", got, http.StatusTooManyRequests)
		}
	}

	body := strings.TrimSpace(logged.String())
	if !strings.Contains(body, "still refusing") {
		t.Errorf("a blocked attempt left no trace, so an attack that is still running looks like one that stopped: %s", body)
	}
	if lines := strings.Count(body, "\n") + 1; lines > 1 {
		t.Errorf("25 blocked attempts produced %d lines; the throttle is not holding:\n%s", lines, body)
	}
}

// The attempted account name is attacker-controlled and bounded only by the
// login body limit, so it is cut and stripped before it reaches the audit
// column or the log.
func TestTheRecordedAccountNameIsBoundedAndStripped(t *testing.T) {
	forged := "victim\nlogin lockout: auth.lockout.account engaged for \"root\""
	if got := safeName(forged); strings.ContainsAny(got, "\r\n") {
		t.Errorf("safeName(%q) = %q, which can forge a log line", forged, got)
	}
	long := strings.Repeat("a", 500)
	if got := safeName(long); len(got) > auditNameLimit {
		t.Errorf("safeName truncates to %d bytes, want at most %d", len(got), auditNameLimit)
	}
}

// addressFor gives each attempt its OWN address, so no per-address counter
// reaches its limit and none of them pays the graduated slowdown.
func addressFor(i int) string {
	return "198.51.100." + strconv.Itoa(i+1)
}
