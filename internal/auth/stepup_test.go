package auth

import (
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// resetStepUp empties the counter and restores the clock, so one test cannot
// lock an account for the next.
func resetStepUp(t *testing.T) {
	t.Helper()
	stepUpMu.Lock()
	stepUpByUser = map[int64]*stepUpState{}
	stepUpMu.Unlock()
	previous := stepUpNow
	t.Cleanup(func() {
		stepUpNow = previous
		stepUpMu.Lock()
		stepUpByUser = map[int64]*stepUpState{}
		stepUpMu.Unlock()
	})
}

// disableRequest asks to turn the second factor off with the given code.
func disableRequest(userID int64, code string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/me/2fa/disable",
		strings.NewReader(`{"code":"`+code+`"}`))
	return request.WithContext(WithClaims(request.Context(),
		&Claims{UserID: userID, Username: "operator", Role: "admin"}))
}

// sealedSeedScript answers the disable path's read with a sealed seed.
func sealedSeedScript(t *testing.T, userID int64, seed string) *totpScript {
	t.Helper()
	sealed, err := SealTOTPSecret(seed, userID)
	if err != nil {
		t.Fatalf("SealTOTPSecret: %v", err)
	}
	return &totpScript{rows: map[string][]driver.Value{
		"SELECT totp_secret, totp_last_step FROM users": {sealed, int64(-1)},
	}}
}

// The session cookie is what a hijacked browser already carries, so the code is
// the only thing left between that session and turning the second factor off.
// Six digits fall in minutes at an unthrottled request rate.
func TestTheDisableCodeCheckLocksAfterRepeatedFailures(t *testing.T) {
	initSecret(t)
	resetStepUp(t)
	handlers := &Handlers{DB: totpDB(t, sealedSeedScript(t, 7, "JBSWY3DPEHPK3PXP"))}

	for attempt := 1; attempt <= stepUpMaxFailures; attempt++ {
		recorder := httptest.NewRecorder()
		handlers.TwoFADisable(recorder, disableRequest(7, "000000"))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d answered %d, want %d (%s)",
				attempt, recorder.Code, http.StatusBadRequest, recorder.Body)
		}
	}

	recorder := httptest.NewRecorder()
	handlers.TwoFADisable(recorder, disableRequest(7, "000000"))
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("the account was not locked: status = %d (%s)", recorder.Code, recorder.Body)
	}
	if recorder.Header().Get("Retry-After") == "" {
		t.Error("the refusal does not say when to come back")
	}
}

// The lock is per account. One operator guessing must not lock another out of
// their own settings.
func TestALockedAccountDoesNotLockAnother(t *testing.T) {
	initSecret(t)
	resetStepUp(t)
	const seed = "JBSWY3DPEHPK3PXP"
	code, err := totpCodeFor(seed)
	if err != nil {
		t.Fatalf("build a valid code: %v", err)
	}
	guessed := &Handlers{DB: totpDB(t, sealedSeedScript(t, 7, seed))}
	for range stepUpMaxFailures {
		guessed.TwoFADisable(httptest.NewRecorder(), disableRequest(7, "000000"))
	}

	other := &Handlers{DB: totpDB(t, sealedSeedScript(t, 8, seed))}
	recorder := httptest.NewRecorder()
	other.TwoFADisable(recorder, disableRequest(8, code))

	if recorder.Code != http.StatusOK {
		t.Fatalf("the second account was refused: status = %d (%s)", recorder.Code, recorder.Body)
	}
}

// The lock expires, and the counter goes with it: otherwise the next single
// wrong code would lock the account again at once.
func TestTheLockExpiresWithItsCounter(t *testing.T) {
	initSecret(t)
	resetStepUp(t)
	const seed = "JBSWY3DPEHPK3PXP"
	handlers := &Handlers{DB: totpDB(t, sealedSeedScript(t, 7, seed))}
	for range stepUpMaxFailures {
		handlers.TwoFADisable(httptest.NewRecorder(), disableRequest(7, "000000"))
	}

	base := time.Now()
	stepUpNow = func() time.Time { return base.Add(stepUpLockFor + time.Minute) }

	recorder := httptest.NewRecorder()
	handlers.TwoFADisable(recorder, disableRequest(7, "000000"))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("after the lock expired the attempt answered %d, want %d (%s)",
			recorder.Code, http.StatusBadRequest, recorder.Body)
	}
}

// A correct code clears the counter, so a legitimate operator who mistyped a few
// times is not one failure away from a lock afterwards.
func TestACorrectCodeClearsTheCounter(t *testing.T) {
	initSecret(t)
	resetStepUp(t)
	const seed = "JBSWY3DPEHPK3PXP"
	code, err := totpCodeFor(seed)
	if err != nil {
		t.Fatalf("build a valid code: %v", err)
	}
	handlers := &Handlers{DB: totpDB(t, sealedSeedScript(t, 7, seed))}
	for range stepUpMaxFailures - 1 {
		handlers.TwoFADisable(httptest.NewRecorder(), disableRequest(7, "000000"))
	}

	recorder := httptest.NewRecorder()
	handlers.TwoFADisable(recorder, disableRequest(7, code))
	if recorder.Code != http.StatusOK {
		t.Fatalf("the correct code was refused: status = %d (%s)", recorder.Code, recorder.Body)
	}

	stepUpMu.Lock()
	_, still := stepUpByUser[7]
	stepUpMu.Unlock()
	if still {
		t.Error("the counter survived a correct code")
	}
}

// A code already accepted once must not turn the second factor off a second
// time inside its validity window. The login flow has used the replay-protected
// form since the replay migration; this path used the other one.
func TestADisableCodeIsNotReplayable(t *testing.T) {
	initSecret(t)
	resetStepUp(t)
	const seed = "JBSWY3DPEHPK3PXP"
	code, err := totpCodeFor(seed)
	if err != nil {
		t.Fatalf("build a valid code: %v", err)
	}
	step, ok := TOTPVerifyStep(seed, code, -1)
	if !ok {
		t.Fatal("the freshly built code does not verify")
	}
	sealed, err := SealTOTPSecret(seed, 7)
	if err != nil {
		t.Fatalf("SealTOTPSecret: %v", err)
	}
	// The row already records this step as accepted.
	script := &totpScript{rows: map[string][]driver.Value{
		"SELECT totp_secret, totp_last_step FROM users": {sealed, step},
	}}

	recorder := httptest.NewRecorder()
	(&Handlers{DB: totpDB(t, script)}).TwoFADisable(recorder, disableRequest(7, code))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("a reused code was accepted: status = %d (%s)", recorder.Code, recorder.Body)
	}
}
