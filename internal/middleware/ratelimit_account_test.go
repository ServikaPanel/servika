package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// resetLoginCounters clears both maps so one test cannot lock another out.
func resetLoginCounters(t *testing.T) {
	t.Helper()
	clear := func() {
		loginMu.Lock()
		loginMap = map[string]*loginRecord{}
		loginMu.Unlock()
		accountMu.Lock()
		accountMap = map[string]*loginRecord{}
		accountMu.Unlock()
	}
	clear()
	t.Cleanup(clear)
}

// The handler must still be able to read the body: the middleware consumes it to
// find the account, so it has to put it back or every login would fail on an
// empty request.
func TestLoginAccountRestoresTheBody(t *testing.T) {
	const body = `{"username":"Admin","password":"secret"}`
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))

	name, oversize := loginAccount(request)
	if oversize {
		t.Fatal("a short body was reported as oversize")
	}
	if name != "admin" {
		t.Errorf("account = %q, want the lowercased username", name)
	}
	rest, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatalf("read the restored body: %v", err)
	}
	if string(rest) != body {
		t.Errorf("the handler would read %q, want the original body", rest)
	}
}

// A body past the bound is refused rather than truncated: a cut JSON would fail
// in the handler with a 400, and the attempt would reach no counter at all.
func TestLoginAccountRefusesAnOversizeBody(t *testing.T) {
	huge := `{"username":"` + strings.Repeat("a", maxLoginBody) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(huge))

	if name, oversize := loginAccount(request); !oversize || name != "" {
		t.Errorf("loginAccount = (%q, %v), want the request refused", name, oversize)
	}
}

// A body that is not the expected shape leaves the per-IP counter as the only
// protection instead of failing the request.
func TestLoginAccountIgnoresAnUnreadableBody(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("not json"))
	if name, oversize := loginAccount(request); name != "" || oversize {
		t.Errorf("loginAccount = (%q, %v), want no account and no refusal", name, oversize)
	}
}

// The account counter key is a constant cost. The body bound alone let one
// failed attempt commit about 8 KB of the map for accountWindow+accountLock,
// and the counted address is the IPv6 /64, so a routed /48 could hold gigabytes
// against an endpoint that authenticates nobody.
func TestTheAccountKeyIsBoundedWhateverTheCallerSends(t *testing.T) {
	resetLoginCounters(t)
	long := strings.Repeat("a", maxLoginBody-40)
	request := httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(`{"username":"`+long+`","password":"x"}`))

	name, oversize := loginAccount(request)
	if oversize {
		t.Fatal("a body inside the bound was reported as oversize")
	}
	if len(name) > maxAccountKey {
		t.Errorf("the stored key is %d bytes, want at most %d", len(name), maxAccountKey)
	}
	if name != strings.Repeat("a", maxAccountKey) {
		t.Errorf("the key is not the first %d characters: %q", maxAccountKey, name)
	}
	// A name that can really exist is stored whole, or the limiter would merge
	// two accounts that both fit the column.
	full := strings.Repeat("b", maxAccountKey)
	whole := httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(`{"username":"`+full+`","password":"x"}`))
	if got, _ := loginAccount(whole); got != full {
		t.Errorf("a %d character name was cut to %q", maxAccountKey, got)
	}
}

// The cut is by rune, so a multi-byte name never leaves a broken one behind.
func TestTheAccountKeyIsNeverCutInsideARune(t *testing.T) {
	name := accountKey(strings.Repeat("ş", maxAccountKey+20))
	if !utf8.ValidString(name) {
		t.Errorf("the key is not valid UTF-8: %q", name)
	}
	if got := utf8.RuneCountInString(name); got != maxAccountKey {
		t.Errorf("the key holds %d runes, want %d", got, maxAccountKey)
	}
}

// The point of the second counter: an attacker rotating source addresses never
// fills the per-IP one, so the account itself has to be counted.
func TestAccountLocksAfterEnoughFailuresFromDifferentAddresses(t *testing.T) {
	resetLoginCounters(t)
	handler := LoginRateLimit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	attempt := func(address string) int {
		request := httptest.NewRequest(http.MethodPost, "/auth/login",
			strings.NewReader(`{"username":"root","password":"x"}`))
		request.RemoteAddr = address
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}

	// Every attempt comes from its own address, which is the case the per-IP
	// counter cannot see: none of them ever reaches a second failure.
	for i := range accountMaxFail {
		if code := attempt("10.0.1." + strconv.Itoa(i+1) + ":1"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d answered %d, want 401 while the account is still open", i+1, code)
		}
	}
	if code := attempt("10.0.0.200:1"); code != http.StatusTooManyRequests {
		t.Errorf("the attempt after the threshold answered %d, want 429", code)
	}
	// A different account is unaffected; the lock is not server-wide.
	other := httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(`{"username":"someone-else","password":"x"}`))
	other.RemoteAddr = "10.0.0.201:1"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, other)
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("another account answered %d, want 401", recorder.Code)
	}
}

// The threshold sits well above the per-IP one on purpose: the lock is also a
// way to keep the operator out, so ordinary mistyping must not reach it.
func TestAccountThresholdStaysAboveThePerAddressOne(t *testing.T) {
	if accountMaxFail <= loginMaxFail {
		t.Errorf("accountMaxFail = %d, must stay above loginMaxFail = %d", accountMaxFail, loginMaxFail)
	}
	if accountLock > loginLock {
		t.Errorf("accountLock = %v, must not exceed the per-address lock %v", accountLock, loginLock)
	}
}
