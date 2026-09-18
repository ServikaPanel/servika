package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"servika/internal/platform"
)

// decodeFailure reads the envelope out of a recorded response.
func decodeFailure(t *testing.T, rec *httptest.ResponseRecorder) Failure {
	t.Helper()
	var got Failure
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("the error answer is not the envelope: %v", err)
	}
	return got
}

func TestEveryFailureCarriesTheSameEnvelope(t *testing.T) {
	// With each endpoint inventing its own shape, a client had to string-match
	// free text to find out what went wrong.
	rec := httptest.NewRecorder()
	writeEnvelope(rec, nil, http.StatusBadRequest, CodeInvalidRequest, "count must be a number", false)
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("the error answer is %q", got)
	}
	got := decodeFailure(t, rec)
	if got.Code != CodeInvalidRequest || got.Message != "count must be a number" {
		t.Fatalf("the envelope read %+v", got)
	}
	// The local panel's own interface reads the text under `error`.
	if got.Error != got.Message {
		t.Fatalf("the compatibility field reads %q while the message reads %q", got.Error, got.Message)
	}
	if got.RequestID == "" {
		t.Fatal("the envelope carries no correlation id")
	}
}

func TestTheCorrelationIdIsInTheHeaderAndTheBody(t *testing.T) {
	// One id has to tie the client's report, the response and the log line.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	writeEnvelope(rec, req, http.StatusInternalServerError, CodeInternal, "wevtutil failed", true)
	got := decodeFailure(t, rec)
	if header := rec.Header().Get(requestIDHeader); header != got.RequestID {
		t.Fatalf("the header says %q and the body says %q", header, got.RequestID)
	}
}

func TestAClientSuppliedCorrelationIdIsKept(t *testing.T) {
	// The panel already has an id for the request; inventing a second one would
	// break the trail across the two sides.
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set(requestIDHeader, "panel-side-id")
	if got := requestID(req); got != "panel-side-id" {
		t.Fatalf("the id read %q", got)
	}
}

func TestTheCorrelationIdHeaderMatchesThePanels(t *testing.T) {
	if requestIDHeader != "X-Request-Id" {
		t.Fatalf("the agent uses %q while the panel uses X-Request-Id", requestIDHeader)
	}
}

func TestEachPlatformFailureGetsItsOwnCodeAndStatus(t *testing.T) {
	// Sending the panel a 500 for a bad domain makes it look in the wrong place.
	cases := []struct {
		err    error
		code   Code
		status int
	}{
		{platform.ErrInvalidRequest, CodeInvalidRequest, http.StatusBadRequest},
		{platform.ErrUnsupported, CodeUnsupported, http.StatusUnprocessableEntity},
		{platform.ErrPasswordRequired, CodePasswordRequired, http.StatusUnprocessableEntity},
		{platform.ErrProtected, CodeProtected, http.StatusUnprocessableEntity},
		{platform.ErrInstallRunning, CodeInstallRunning, http.StatusConflict},
		{platform.ErrInstallPending, CodeInstallPending, http.StatusConflict},
		{platform.ErrNotInstallable, CodeNotInstallable, http.StatusUnprocessableEntity},
		{fmt.Errorf("wrapped: %w", platform.ErrInvalidRequest), CodeInvalidRequest, http.StatusBadRequest},
	}
	for _, c := range cases {
		code, status, _ := codeFor(c.err, http.StatusInternalServerError)
		if code != c.code || status != c.status {
			t.Errorf("%v mapped to %s/%d, expected %s/%d", c.err, code, status, c.code, c.status)
		}
	}
}

func TestAnUnrecognisedFailureTakesTheEndpointsOwnDefault(t *testing.T) {
	// A read endpoint's unknown failure is the host's problem; a mutation's is
	// more often the request's.
	code, status, retryable := codeFor(errors.New("appcmd exited 1"), http.StatusInternalServerError)
	if code != CodeInternal || status != http.StatusInternalServerError || !retryable {
		t.Fatalf("a read failure mapped to %s/%d retryable=%v", code, status, retryable)
	}
	code, status, retryable = codeFor(errors.New("appcmd exited 1"), http.StatusUnprocessableEntity)
	if code != CodeInternal || status != http.StatusUnprocessableEntity || retryable {
		t.Fatalf("a mutation failure mapped to %s/%d retryable=%v", code, status, retryable)
	}
}

func TestOnlyTheFailuresThatGetBetterAreMarkedRetryable(t *testing.T) {
	// A pending installation is a 409 too, but it needs an OPERATOR. A client
	// that retried it blindly would hammer a lock nobody is going to open.
	if _, _, retryable := codeFor(platform.ErrInstallRunning, http.StatusInternalServerError); !retryable {
		t.Fatal("a running installation was not marked retryable, so the client gives up on a wait")
	}
	for _, err := range []error{
		platform.ErrInstallPending, platform.ErrInvalidRequest, platform.ErrUnsupported,
		platform.ErrProtected, platform.ErrNotInstallable, platform.ErrPasswordRequired,
	} {
		if _, _, retryable := codeFor(err, http.StatusInternalServerError); retryable {
			t.Errorf("%v was marked retryable", err)
		}
	}
}

func TestACrossOriginMutationIsRefusedBeforeTheHandlerRuns(t *testing.T) {
	// SameSite=Strict alone is one layer: on a 0.0.0.0 bind a page on the SAME
	// host at a DIFFERENT port counts as same-site and carries the cookie.
	var reached bool
	handler := audited("site", func(http.ResponseWriter, *http.Request) { reached = true })
	req := httptest.NewRequest(http.MethodPost, "/site", nil)
	req.Host = "10.0.0.5:8443"
	req.Header.Set("Origin", "https://attacker.example.com")
	rec := httptest.NewRecorder()
	handler(rec, req)
	if reached {
		t.Fatal("a cross-origin mutation reached the handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a cross-origin mutation answered %d", rec.Code)
	}
	if got := decodeFailure(t, rec); got.Code != CodeCSRF {
		t.Fatalf("the refusal carried the code %s", got.Code)
	}
}

func TestASameHostDifferentPortOriginIsRefused(t *testing.T) {
	// This is the exact case SameSite does not catch.
	req := httptest.NewRequest(http.MethodPost, "/site", nil)
	req.Host = "10.0.0.5:8443"
	req.Header.Set("Origin", "https://10.0.0.5:9999")
	if err := checkCSRF(req); err == nil {
		t.Fatal("a same-host different-port origin was accepted")
	}
}

func TestASameOriginMutationIsAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/site", nil)
	req.Host = "10.0.0.5:8443"
	req.Header.Set("Origin", "https://10.0.0.5:8443")
	if err := checkCSRF(req); err != nil {
		t.Fatalf("a same-origin mutation was refused: %v", err)
	}
	// The Referer is the fallback a browser sends when Origin is absent.
	req = httptest.NewRequest(http.MethodPost, "/site", nil)
	req.Host = "10.0.0.5:8443"
	req.Header.Set("Referer", "https://10.0.0.5:8443/sites")
	if err := checkCSRF(req); err != nil {
		t.Fatalf("a same-origin Referer was refused: %v", err)
	}
}

func TestARequestFromOutsideABrowserIsNotBlocked(t *testing.T) {
	// A tool sends neither header. The session and SameSite are enough there,
	// and refusing it would break every command-line client.
	req := httptest.NewRequest(http.MethodPost, "/site", nil)
	req.Host = "10.0.0.5:8443"
	if err := checkCSRF(req); err != nil {
		t.Fatalf("a request with no Origin was refused: %v", err)
	}
}

func TestAMalformedOriginIsRefusedRatherThanIgnored(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/site", nil)
	req.Host = "10.0.0.5:8443"
	req.Header.Set("Origin", "null")
	if err := checkCSRF(req); err == nil {
		t.Fatal("an Origin with no host was accepted")
	}
}

func TestTheAuditWrapperGivesTheHandlerTheSameCorrelationId(t *testing.T) {
	// The failure envelope the handler writes has to carry the id the audit
	// line logged, or the two cannot be matched afterwards.
	var seen string
	handler := audited("site", func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get(requestIDHeader)
		writeEnvelope(w, r, http.StatusConflict, CodeInstallRunning, "busy", true)
	})
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, "/site", nil))
	if seen == "" {
		t.Fatal("the handler got no correlation id")
	}
	if got := decodeFailure(t, rec); got.RequestID != seen {
		t.Fatalf("the envelope says %q and the handler saw %q", got.RequestID, seen)
	}
}

func TestTheAuditWrapperRecordsTheStatusTheHandlerAnswered(t *testing.T) {
	// A handler that never calls WriteHeader answered 200, which is what
	// net/http sends.
	recorder := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
	if recorder.status != http.StatusOK {
		t.Fatal("the recorder does not start at 200")
	}
	recorder.WriteHeader(http.StatusTeapot)
	if recorder.status != http.StatusTeapot {
		t.Fatalf("the recorder holds %d", recorder.status)
	}
}

func TestAMethodFailureAndABodyFailureUseTheEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	methodFailure(rec, httptest.NewRequest(http.MethodPut, "/events", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("a wrong method answered %d", rec.Code)
	}
	if got := decodeFailure(t, rec); got.Code != CodeMethod {
		t.Fatalf("a wrong method carried the code %s", got.Code)
	}

	rec = httptest.NewRecorder()
	bodyFailure(rec, httptest.NewRequest(http.MethodPost, "/site", strings.NewReader("{")))
	if got := decodeFailure(t, rec); got.Code != CodeBadBody || got.Retryable {
		t.Fatalf("a bad body read as %+v", got)
	}
}

func TestTheSharedErrorPathDerivesEverythingFromTheFailure(t *testing.T) {
	// Every endpoint goes through this one function, so the code, the status and
	// the retryable flag cannot drift apart per call site.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/install", nil)
	writeError(rec, req, http.StatusInternalServerError,
		fmt.Errorf("the job %q is running: %w", "abc", platform.ErrInstallRunning))
	if rec.Code != http.StatusConflict {
		t.Fatalf("a running installation answered %d", rec.Code)
	}
	got := decodeFailure(t, rec)
	if got.Code != CodeInstallRunning || !got.Retryable {
		t.Fatalf("the envelope read %+v", got)
	}
	if !strings.Contains(got.Message, "abc") {
		t.Fatalf("the wrapping context was lost: %q", got.Message)
	}
}
