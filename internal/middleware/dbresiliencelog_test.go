package middleware

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

// captureStateLog redirects the standard logger for one test and clears the
// throttle, so one case cannot decide the outcome of the next.
func captureStateLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := captureLog(t)
	resetStateCache()
	resetStateComplaints()
	t.Cleanup(func() {
		resetStateCache()
		resetStateComplaints()
	})
	return buf
}

// Serving a request from the stale cache is the degraded mode whose documented
// consequence is that a revocation written during the window is not visible
// until the entry expires. It used to answer 200 and be indistinguishable in
// every log from a healthy request.
func TestTheStaleFallbackIsRecorded(t *testing.T) {
	logged := captureStateLog(t)
	const key = "token_version:users:7"
	// One good read, so there is something to fall back to.
	if _, err := readState(context.Background(), key, answer(3, nil)); err != nil {
		t.Fatalf("the first read failed: %v", err)
	}
	if logged.Len() != 0 {
		t.Fatalf("a healthy read logged something: %s", logged.String())
	}

	value, err := readState(context.Background(), key, answer(0, errors.New("connection refused")))
	if err != nil || value != 3 {
		t.Fatalf("readState() = %d, %v; want the cached 3", value, err)
	}
	line := logged.String()
	if !strings.Contains(line, key) {
		t.Errorf("the line does not name what could not be read: %s", line)
	}
	if !strings.Contains(line, "connection refused") {
		t.Errorf("the line does not carry the reason: %s", line)
	}
	if !strings.Contains(line, "revocation written now is not visible") {
		t.Errorf("the line does not state the consequence: %s", line)
	}
}

// A read with nothing fresh to fall back on becomes a 503 that never reaches a
// handler, so this is the only place the reason can be recorded.
func TestTheDenialIsRecorded(t *testing.T) {
	logged := captureStateLog(t)

	if _, err := readState(context.Background(), "suspended:9", answer(0, errors.New("too many connections"))); err == nil {
		t.Fatal("readState() = nil error, want the read failure")
	}
	line := logged.String()
	if !strings.Contains(line, "suspended:9") || !strings.Contains(line, "too many connections") {
		t.Errorf("the denial is not explained: %s", line)
	}
	if !strings.Contains(line, "being refused") {
		t.Errorf("the line does not say what the consequence is: %s", line)
	}
}

// These checks run on EVERY authenticated request, so one line per failure
// would turn a database outage into a full disk.
func TestTheComplaintIsThrottled(t *testing.T) {
	logged := captureStateLog(t)
	failing := answer(0, errors.New("connection refused"))

	// Each read costs two retry delays, so this is kept to the smallest count
	// that still proves the throttle rather than the largest that would.
	const reads = 20
	for range reads {
		_, _ = readState(context.Background(), "suspended:9", failing)
	}

	if lines := strings.Count(strings.TrimSpace(logged.String()), "\n") + 1; lines > 1 {
		t.Errorf("%d failed reads produced %d lines; the throttle is not holding:\n%s",
			reads, lines, logged.String())
	}
}

// The two kinds are throttled apart, or a sustained fallback would hide the
// moment the panel stopped being able to answer at all.
func TestAFallbackDoesNotSilenceTheDenial(t *testing.T) {
	logged := captureStateLog(t)
	failing := answer(0, errors.New("connection refused"))

	// A cached entry for one key, none for the other.
	if _, err := readState(context.Background(), "token_version:users:7", answer(3, nil)); err != nil {
		t.Fatalf("the seeding read failed: %v", err)
	}
	_, _ = readState(context.Background(), "token_version:users:7", failing) // fallback
	_, _ = readState(context.Background(), "suspended:9", failing)           // denial

	body := logged.String()
	if !strings.Contains(body, "serving the value last read") {
		t.Errorf("the fallback was not recorded: %s", body)
	}
	if !strings.Contains(body, "being refused") {
		t.Errorf("the denial was silenced by the fallback's throttle: %s", body)
	}
}

// The journal needs both ends of the window: an operator deciding whether a
// revocation could have been missed needs to know when the degraded period
// stopped, and how long it lasted.
func TestRecoveryIsRecordedOnce(t *testing.T) {
	logged := captureStateLog(t)
	const key = "token_version:users:7"

	if _, err := readState(context.Background(), key, answer(3, nil)); err != nil {
		t.Fatalf("the seeding read failed: %v", err)
	}
	_, _ = readState(context.Background(), key, answer(0, errors.New("connection refused")))
	logged.Reset()

	for range 5 {
		if _, err := readState(context.Background(), key, answer(3, nil)); err != nil {
			t.Fatalf("the recovery read failed: %v", err)
		}
	}

	body := logged.String()
	if !strings.Contains(body, "answered again after") {
		t.Errorf("the recovery was not recorded: %s", body)
	}
	if got := strings.Count(body, "answered again after"); got != 1 {
		t.Errorf("the recovery was recorded %d times, want once", got)
	}
}

// A missing row is an answer, not a failure, and must not look like an outage.
func TestAnAbsentRowIsNotReportedAsDegraded(t *testing.T) {
	logged := captureStateLog(t)

	if _, err := readState(context.Background(), "token_version:users:7", answer(0, sql.ErrNoRows)); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("readState() = %v, want sql.ErrNoRows", err)
	}
	if logged.Len() != 0 {
		t.Errorf("an absent row was reported as a degraded read: %s", logged.String())
	}
}

func answer(value int64, err error) func(context.Context) (int64, error) {
	return func(context.Context) (int64, error) { return value, err }
}

// The throttle window has to be bounded by the cache TTL, or a sustained outage
// logs less often than the window it is describing.
func TestTheThrottleWindowDoesNotOutlastTheCache(t *testing.T) {
	if stateComplainInterval > stateCacheTTL {
		t.Errorf("stateComplainInterval is %s but the cache holds an entry for %s",
			stateComplainInterval, stateCacheTTL)
	}
	if stateComplainInterval < time.Second {
		t.Errorf("stateComplainInterval is %s, which is not a throttle", stateComplainInterval)
	}
}
