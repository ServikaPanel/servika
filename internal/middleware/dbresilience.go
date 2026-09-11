package middleware

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"
)

// Every authenticated request reads two rows before it reaches a handler: the
// identity's token_version and, for a scoped route, the domain's suspended flag.
// Both fail closed, which is right, but it also means a single unreachable
// moment on the database, a MariaDB restart or an exhausted connection pool,
// answers every request in flight with an error until it comes back.
//
// This softens that without opening the gate:
//
//  1. A failed read is retried a couple of times. Most blips are shorter than
//     the retries take.
//  2. If it still fails, the value the database last RETURNED for that key is
//     reused while it is fresh. The cache stores an answer that was read, it
//     never invents one: a bumped token_version and a suspended domain are both
//     refused from the cache exactly as they are from the database.
//  3. With nothing fresh to fall back on, the read fails and the caller denies
//     the request. "I cannot check" never becomes "it is fine".
//
// The trade-off is explicit: a revocation written WHILE the database is
// unreachable is not visible until the cached entry expires, so a session
// revoked during an outage can survive for up to stateCacheTTL. That window is
// bounded, it only exists while the database is down, and nearly every handler
// behind it needs the same database to do anything.
const (
	dbRetryAttempts = 2
	dbRetryDelay    = 40 * time.Millisecond
	stateCacheTTL   = 30 * time.Second

	// Above this many entries a store prunes what has expired. The map holds one
	// entry per recently seen identity or domain, so this only matters on a busy
	// panel, and pruning stale rows there costs less than keeping them.
	stateCacheMaxEntries = 1024
)

// stateNow is a seam so a test can age an entry without sleeping.
var stateNow = time.Now

type cachedState struct {
	value int64
	at    time.Time
}

var (
	stateMu    sync.Mutex
	stateCache = map[string]cachedState{}
)

func stateStore(key string, value int64, at time.Time) {
	stateMu.Lock()
	defer stateMu.Unlock()
	if len(stateCache) >= stateCacheMaxEntries {
		for k, v := range stateCache {
			if at.Sub(v.at) > stateCacheTTL {
				delete(stateCache, k)
			}
		}
	}
	stateCache[key] = cachedState{value: value, at: at}
}

func stateLoad(key string, at time.Time) (int64, bool) {
	stateMu.Lock()
	defer stateMu.Unlock()
	v, ok := stateCache[key]
	if !ok || at.Sub(v.at) > stateCacheTTL {
		return 0, false
	}
	return v.value, true
}

// resetStateCache drops everything the cache holds. Tests call it so one case
// cannot decide the outcome of the next.
func resetStateCache() {
	stateMu.Lock()
	stateCache = map[string]cachedState{}
	stateMu.Unlock()
}

// readState runs query, retrying a transient failure, and falls back to the
// value last read for key while that value is still fresh.
//
// sql.ErrNoRows is returned immediately: an absent row is an answer, not a
// failure, so retrying it only delays the response and caching it would be
// caching a fact the caller already has.
func readState(ctx context.Context, key string, query func(context.Context) (int64, error)) (int64, error) {
	var lastErr error
	for attempt := 0; attempt <= dbRetryAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(dbRetryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				lastErr = ctx.Err()
				return fallbackState(key, lastErr)
			case <-timer.C:
			}
		}
		value, err := query(ctx)
		if err == nil {
			stateStore(key, value, stateNow())
			noteStateHealthy()
			return value, nil
		}
		if errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}
		lastErr = err
	}
	return fallbackState(key, lastErr)
}

// fallbackState serves the last value read for key, or gives up.
//
// Both outcomes are LOGGED, throttled. Serving from the cache is the degraded
// mode whose documented consequence is that a revocation written right now is
// not visible until the entry expires; giving up is the 503 the caller answers
// with, which never reaches a handler that could record a reason. Without these
// lines an operator asking "why did a revoked session still work at 03:12" or
// "why was everything 503 at 03:12" has nothing to read.
func fallbackState(key string, readErr error) (int64, error) {
	if value, ok := stateLoad(key, stateNow()); ok {
		complainState(complaintFallback,
			"%s could not be read (%v); serving the value last read for it, so a revocation written now is not visible for up to %s",
			key, readErr, stateCacheTTL)
		return value, nil
	}
	complainState(complaintDenied,
		"%s could not be read (%v) and nothing fresh is cached; requests needing it are being refused",
		key, readErr)
	return 0, readErr
}
