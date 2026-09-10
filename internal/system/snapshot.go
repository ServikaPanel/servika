package system

import (
	"sync"
	"time"
)

// A short-lived cache in front of the expensive readers behind GET
// /system/usage.
//
// That endpoint is the most frequently polled route in the panel: the home
// screen and the monitoring screen each poll it every 5 seconds, so one
// administrator with both open drove the work below permanently. Per request it
// forked one `systemctl show` per unit in serviceList, asked xfs_quota whether a
// reboot is pending, and slept 150 ms between two /proc/stat samples on the
// request goroutine, which made 150 ms the latency floor of the busiest route in
// the panel by construction.
//
// Parallelism was already there and does not help: a WaitGroup reduces the
// latency of ONE request and not the cost, and nothing deduplicated the work
// across the repeated polls the frontend performs by design. This does both. It
// is the same shape internal/diskusage uses, and internal/phpversion documents a
// TTL for the same reason.
//
// The values are chosen against the 5-second poll: an operator installing or
// removing software is what changes the service list and the quota state, so
// those are held far longer than one poll, while the CPU sample is held for
// about one poll so the graph still moves.
const (
	cpuTTL     = 5 * time.Second
	serviceTTL = 20 * time.Second
	quotaTTL   = 30 * time.Second
)

// snapshot holds one cached reading and coalesces concurrent readers.
//
// A caller that arrives while a reading is in flight waits for that one instead
// of starting a second. Without this, two panel tabs polling together each took
// their own 150 ms CPU sample and forked their own fifteen probes.
type snapshot[T any] struct {
	ttl  time.Duration
	load func() T

	mu       sync.Mutex
	value    T
	at       time.Time
	fresh    bool
	inflight chan struct{}

	// now is a test seam: it lets a test age the cache without sleeping.
	now func() time.Time
}

func newSnapshot[T any](ttl time.Duration, load func() T) *snapshot[T] {
	return &snapshot[T]{ttl: ttl, load: load, now: time.Now}
}

// get returns the cached reading, taking a new one when it has expired.
func (s *snapshot[T]) get() T {
	s.mu.Lock()
	if s.fresh && s.now().Sub(s.at) < s.ttl {
		value := s.value
		s.mu.Unlock()
		return value
	}
	if done := s.inflight; done != nil {
		// Another caller is already reading. Wait for it rather than starting a
		// second reading of the same thing.
		s.mu.Unlock()
		<-done
		s.mu.Lock()
		value := s.value
		s.mu.Unlock()
		return value
	}
	done := make(chan struct{})
	s.inflight = done
	s.mu.Unlock()

	value := s.load()

	s.mu.Lock()
	s.value = value
	s.at = s.now()
	s.fresh = true
	s.inflight = nil
	s.mu.Unlock()
	close(done)
	return value
}

// invalidate drops the cached reading, so the next caller takes a fresh one. A
// panel action that changes what the reading reports calls it rather than
// waiting out the TTL, because a stale window right after an operation reads as
// the operation having done nothing.
func (s *snapshot[T]) invalidate() {
	s.mu.Lock()
	s.fresh = false
	s.mu.Unlock()
}
