package main

// One error envelope for every endpoint.
//
// WHY: with each endpoint inventing its own error shape and its own status
// mapping, a client had to string-match free text and could not tell whether
// retrying would help. This file gives one envelope, a machine-readable code, a
// correlation id that appears in the response header AND the log, and an honest
// retryable flag.
//
// The envelope keeps an `error` field alongside `message`, because the local
// panel's own interface reads that name. A new field is only ever ADDED here.
//
// No build tag: the mapping and the CSRF check are the same everywhere and are
// measured on every build.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"servika/internal/logx"
	"servika/internal/platform"
)

// Code is the machine-readable failure code. Its status and its retryable flag
// are fixed in codeFor, not chosen per call site.
type Code string

const (
	CodeInvalidRequest   Code = "INVALID_REQUEST"    // 400, the caller's mistake
	CodeUnsupported      Code = "UNSUPPORTED"        // 422, the platform cannot do it
	CodePasswordRequired Code = "PASSWORD_REQUIRED"  // 422, the engine needs a password
	CodeProtected        Code = "PROTECTED"          // 422, a system resource
	CodeInstallRunning   Code = "INSTALL_RUNNING"    // 409, single flight; retrying WILL help
	CodeInstallPending   Code = "INSTALL_PENDING"    // 409, an operator has to clear it first
	CodeNotInstallable   Code = "NOT_INSTALLABLE"    // 422, unknown or already installed
	CodeMethod           Code = "METHOD_NOT_ALLOWED" // 405
	CodeBadBody          Code = "BAD_BODY"           // 400
	CodeCSRF             Code = "CSRF_REFUSED"       // 403, a cross-origin request
	CodeInternal         Code = "INTERNAL"           // 500
)

// Failure is the one shape every error answer takes.
type Failure struct {
	Code      Code   `json:"code"`
	Message   string `json:"message"`
	Error     string `json:"error"` // the same text, under the name the panel's interface reads
	RequestID string `json:"request_id"`
	Retryable bool   `json:"retryable"`
}

// requestIDHeader matches the panel's own header, so one correlation id follows
// a request across both sides.
const requestIDHeader = "X-Request-Id"

// requestID returns the request's correlation id, keeping one the client sent.
func requestID(r *http.Request) string {
	if r != nil {
		if v := r.Header.Get(requestIDHeader); v != "" {
			return v
		}
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}

// codeFor turns a platform sentinel into a code, a status and a retryable flag.
//
// Only INSTALL_RUNNING and a 500 are retryable. A pending installation is a 409
// as well but is NOT retryable: it needs an operator, and a client that retried
// it blindly would hammer a lock nobody is going to open.
func codeFor(err error, defaultStatus int) (Code, int, bool) {
	if code, status, found := sentinelCode(err); found {
		return code, status, code == CodeInstallRunning
	}
	return CodeInternal, defaultStatus, defaultStatus >= 500
}

// sentinelCode maps the platform's own errors.
func sentinelCode(err error) (Code, int, bool) {
	switch {
	case errors.Is(err, platform.ErrInvalidRequest):
		return CodeInvalidRequest, http.StatusBadRequest, true
	case errors.Is(err, platform.ErrPasswordRequired):
		return CodePasswordRequired, http.StatusUnprocessableEntity, true
	case errors.Is(err, platform.ErrProtected):
		return CodeProtected, http.StatusUnprocessableEntity, true
	case errors.Is(err, platform.ErrInstallRunning):
		return CodeInstallRunning, http.StatusConflict, true
	case errors.Is(err, platform.ErrInstallPending):
		return CodeInstallPending, http.StatusConflict, true
	case errors.Is(err, platform.ErrNotInstallable):
		return CodeNotInstallable, http.StatusUnprocessableEntity, true
	case errors.Is(err, platform.ErrUnsupported):
		return CodeUnsupported, http.StatusUnprocessableEntity, true
	}
	return "", 0, false
}

// writeEnvelope writes the failure and logs it under the same correlation id.
// r may be nil.
func writeEnvelope(w http.ResponseWriter, r *http.Request, status int, code Code, message string, retryable bool) {
	id := requestID(r)
	method, path := "-", "-"
	if r != nil {
		method, path = r.Method, r.URL.Path
	}
	// A 5xx is the agent failing; a 4xx is a request the agent refused and
	// continued past, which is what warning means here.
	if status >= http.StatusInternalServerError {
		logx.Errorf("[%s] %s %s -> %d %s: %s", id, method, path, status, code, message)
	} else {
		logx.Warnf("[%s] %s %s -> %d %s: %s", id, method, path, status, code, message)
	}
	w.Header().Set(requestIDHeader, id)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Failure{
		Code: code, Message: message, Error: message, RequestID: id, Retryable: retryable,
	})
}

// writeError is the one error path every endpoint takes. A sentinel decides the
// code, the status and the retryable flag; anything else takes defaultStatus.
func writeError(w http.ResponseWriter, r *http.Request, defaultStatus int, err error) {
	code, status, retryable := codeFor(err, defaultStatus)
	writeEnvelope(w, r, status, code, err.Error(), retryable)
}

// methodFailure answers a wrong HTTP method.
func methodFailure(w http.ResponseWriter, r *http.Request) {
	writeEnvelope(w, r, http.StatusMethodNotAllowed, CodeMethod, "that method is not supported", false)
}

// bodyFailure answers a body that could not be decoded.
func bodyFailure(w http.ResponseWriter, r *http.Request) {
	writeEnvelope(w, r, http.StatusBadRequest, CodeBadBody, "the request body could not be read", false)
}

// checkCSRF is defence in depth on top of the session cookie's SameSite=Strict.
//
// SameSite alone was one layer, and on a 0.0.0.0 bind a page on the SAME host
// at a DIFFERENT port counts as same-site and carries the cookie. So a request
// that CARRIES an Origin or Referer must have a host matching the request's own
// Host. A request with NEITHER is not from a browser, and the session plus
// SameSite are accepted as enough. A browser sends Origin on a same-origin POST
// or DELETE, and an attacker's page sends a different one, which is caught.
func checkCSRF(r *http.Request) error {
	source := r.Header.Get("Origin")
	if source == "" {
		source = r.Header.Get("Referer")
	}
	if source == "" {
		return nil
	}
	u, err := url.Parse(source)
	if err != nil || u.Host == "" {
		return fmt.Errorf("the Origin or Referer header is not a valid URL")
	}
	if !strings.EqualFold(u.Host, r.Host) {
		return fmt.Errorf("the cross-origin request was refused (origin %q is not host %q)", u.Host, r.Host)
	}
	return nil
}

// statusRecorder remembers the status an endpoint answered, for the audit line.
// net/http's default is 200 when WriteHeader is never called, so it starts there.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// audited wraps a privileged endpoint: it assigns the correlation id, refuses a
// cross-origin request BEFORE the handler sees it, and logs who did what and
// how it ended. The id is written back into the request headers so the failure
// envelope carries the SAME one.
//
// Only state-changing endpoints are wrapped. A read endpoint would only add
// noise.
func audited(name string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := requestID(r)
		r.Header.Set(requestIDHeader, id)
		w.Header().Set(requestIDHeader, id)
		if err := checkCSRF(r); err != nil {
			logx.Warnf("[%s] AUDIT %s CSRF-REFUSED actor=%s: %v", id, name, r.RemoteAddr, err)
			writeEnvelope(w, r, http.StatusForbidden, CodeCSRF, err.Error(), false)
			return
		}
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		started := time.Now()
		logx.Infof("[%s] AUDIT %s STARTED actor=%s %s %s", id, name, r.RemoteAddr, r.Method, r.URL.Path)
		next(recorder, r)
		logx.Infof("[%s] AUDIT %s ENDED status=%d took=%v", id, name, recorder.status, time.Since(started).Round(time.Millisecond))
	}
}
