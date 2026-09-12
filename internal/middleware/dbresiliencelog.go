package middleware

import (
	"sync"
	"time"

	"servika/internal/logx"
)

// The resilience layer beside this was a pure control-flow change: retry, then
// serve a cached answer, then deny. None of the three left a trace, which put
// the panel into two invisible states during a MariaDB restart or an exhausted
// connection pool.
//
// A request served from the stale cache answers 200 and is indistinguishable in
// every log from a healthy one, INCLUDING a request from a session revoked
// during the window; the package's own documentation calls that an explicit
// trade-off with a security consequence. A request with nothing fresh to fall
// back on answers 503 and never reaches a handler that could say why, so the
// operator sees a wall of 503s with no cause. Both are the 3 AM case
// instrumentation exists for.
//
// The lines are throttled the same way sessionidle.Complain throttles its own:
// these checks run on EVERY authenticated request, so one line per failure
// would turn a database outage into a full disk.

// stateComplainInterval bounds one kind of line. It matches the cache TTL, so a
// sustained outage produces roughly one line per window rather than one per
// request.
const stateComplainInterval = stateCacheTTL

type complaintKind string

const (
	complaintFallback complaintKind = "fallback"
	complaintDenied   complaintKind = "denied"
)

var (
	complaintMu   sync.Mutex
	lastComplaint = map[complaintKind]time.Time{}
	// degradedSince is when the first fallback or denial of the current episode
	// happened. It is what lets the recovery line state how long the panel was
	// answering from stale state, which is the number an operator needs to decide
	// whether a revocation could have been missed.
	degradedSince time.Time
)

// complainState logs one throttled line for a degraded authorization read.
func complainState(kind complaintKind, format string, args ...any) {
	complaintMu.Lock()
	defer complaintMu.Unlock()
	now := stateNow()
	if degradedSince.IsZero() {
		degradedSince = now
	}
	if previous, seen := lastComplaint[kind]; seen && now.Sub(previous) < stateComplainInterval {
		return
	}
	lastComplaint[kind] = now
	// #nosec G706 -- the arguments are a fixed cache key built from integer ids and a database driver error; no tenant string reaches the log.
	logx.Warnf("auth state: "+format, args...)
}

// noteStateHealthy closes an episode. It logs once, on the first successful read
// after a degraded period, so the journal carries both ends of the window.
func noteStateHealthy() {
	complaintMu.Lock()
	defer complaintMu.Unlock()
	if degradedSince.IsZero() {
		return
	}
	since := degradedSince
	degradedSince = time.Time{}
	clear(lastComplaint)
	logx.Infof("auth state: the database answered again after %s of degraded reads; "+
		"a revocation written during that window may have been served from the cache",
		stateNow().Sub(since).Round(time.Second))
}

// resetStateComplaints drops the throttle and the episode. Tests call it so one
// case cannot decide the outcome of the next.
func resetStateComplaints() {
	complaintMu.Lock()
	lastComplaint = map[complaintKind]time.Time{}
	degradedSince = time.Time{}
	complaintMu.Unlock()
}
