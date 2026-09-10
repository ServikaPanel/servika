package system

import (
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errNoCPUForTest = errors.New("CPU line not found")

// GET /system/usage is polled every 5 seconds by two frontend screens. Per
// request it forked one `systemctl show` per unit and asked xfs_quota whether a
// reboot is pending, so one administrator with both screens open drove that work
// permanently on a host whose CPU is meant to be running customer sites.
func TestASecondCallInsideTheTTLDoesNotReadAgain(t *testing.T) {
	var reads atomic.Int64
	cache := newSnapshot(time.Minute, func() int64 { return reads.Add(1) })

	for range 10 {
		if got := cache.get(); got != 1 {
			t.Fatalf("get() = %d, want the first reading served from the cache", got)
		}
	}
	if reads.Load() != 1 {
		t.Errorf("%d readings were taken, want 1", reads.Load())
	}
}

// The cache is a cache, not a one-shot: once the TTL passes the next caller
// takes a fresh reading, or the panel would report the state at process start
// for ever.
func TestTheReadingIsTakenAgainOnceTheTTLPasses(t *testing.T) {
	var reads atomic.Int64
	cache := newSnapshot(time.Minute, func() int64 { return reads.Add(1) })
	clock := time.Now()
	cache.now = func() time.Time { return clock }

	cache.get()
	clock = clock.Add(2 * time.Minute)
	if got := cache.get(); got != 2 {
		t.Fatalf("get() = %d after the TTL passed, want a fresh reading", got)
	}
}

// Two panel tabs polling together each took their own 150 ms CPU sample and
// forked their own fifteen probes. A caller that arrives while a reading is in
// flight waits for that one.
func TestConcurrentCallersShareOneReading(t *testing.T) {
	var reads atomic.Int64
	release := make(chan struct{})
	cache := newSnapshot(time.Minute, func() int64 {
		<-release // hold the reading open so every caller arrives during it
		return reads.Add(1)
	})

	const callers = 32
	var wg sync.WaitGroup
	results := make([]int64, callers)
	wg.Add(callers)
	for i := range callers {
		go func() {
			defer wg.Done()
			results[i] = cache.get()
		}()
	}
	// Let the callers pile up on the in-flight reading before it returns.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if reads.Load() != 1 {
		t.Errorf("%d readings were taken for %d concurrent callers, want 1", reads.Load(), callers)
	}
	for i, got := range results {
		if got != 1 {
			t.Errorf("caller %d saw %d, want the shared reading", i, got)
		}
	}
}

// A panel action that changes what the reading reports drops the cache rather
// than waiting out the TTL, because a stale window right after an operation
// reads as the operation having done nothing.
func TestInvalidateForcesTheNextCallerToReadAgain(t *testing.T) {
	var reads atomic.Int64
	cache := newSnapshot(time.Minute, func() int64 { return reads.Add(1) })

	cache.get()
	cache.invalidate()
	if got := cache.get(); got != 2 {
		t.Fatalf("get() = %d after invalidate, want a fresh reading", got)
	}
}

// The three readers behind the endpoint are the expensive ones, and each has to
// sit behind the cache rather than being called straight from the handler.
func TestTheExpensiveReadersAreCached(t *testing.T) {
	previous := systemctlProbe
	var probes atomic.Int64
	systemctlProbe = func(string) (bool, bool) { probes.Add(1); return true, true }
	t.Cleanup(func() { systemctlProbe = previous })
	serviceSnapshot.invalidate()

	ReadServices()
	ReadServices()

	if got, want := probes.Load(), int64(len(serviceList)); got != want {
		t.Errorf("%d unit probes for two calls, want %d (one pass)", got, want)
	}
}

// The CPU reading is the one that costs a 150 ms sleep between two /proc/stat
// samples, which made 150 ms the latency floor of the panel's busiest route.
func TestTheCPUReadingIsServedFromTheCache(t *testing.T) {
	previous := cpuSampler
	var samples atomic.Int64
	cpuSampler = func() (CPUUsage, error) {
		return CPUUsage{Percent: float64(samples.Add(1))}, nil
	}
	t.Cleanup(func() { cpuSampler = previous; cpuSnapshot.invalidate() })
	cpuSnapshot.invalidate()

	first, err := ReadCPU()
	if err != nil {
		t.Fatalf("ReadCPU() = %v", err)
	}
	second, err := ReadCPU()
	if err != nil {
		t.Fatalf("ReadCPU() = %v", err)
	}
	if samples.Load() != 1 {
		t.Errorf("%d samples were taken for two calls, want 1", samples.Load())
	}
	if first.Percent != second.Percent {
		t.Errorf("the two calls saw %v and %v, want the same cached reading", first.Percent, second.Percent)
	}
}

// The error is cached with the reading, so a host whose /proc/stat cannot be
// read does not sample again on every poll either.
func TestAFailedCPUReadingIsAlsoCached(t *testing.T) {
	previous := cpuSampler
	var samples atomic.Int64
	cpuSampler = func() (CPUUsage, error) {
		samples.Add(1)
		return CPUUsage{}, errNoCPUForTest
	}
	t.Cleanup(func() { cpuSampler = previous; cpuSnapshot.invalidate() })
	cpuSnapshot.invalidate()

	if _, err := ReadCPU(); err == nil {
		t.Fatal("ReadCPU() reported success for a sampler that failed")
	}
	if _, err := ReadCPU(); err == nil {
		t.Fatal("the cached failure was reported as success")
	}
	if samples.Load() != 1 {
		t.Errorf("%d samples were taken for two calls, want 1", samples.Load())
	}
}

// The handler must not call an expensive reader directly, or the cache in front
// of it is bypassed.
func TestTheHandlerReadsThroughTheCaches(t *testing.T) {
	body, err := os.ReadFile("usage.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	start := strings.Index(source, "func Handler(")
	if start < 0 {
		t.Fatal("Handler was renamed; these assertions have to follow it")
	}
	end := strings.Index(source[start:], "\nfunc ")
	if end < 0 {
		end = len(source) - start
	}
	handler := source[start : start+end]

	if strings.Contains(handler, "probeServices(") {
		t.Error("the handler probes the units directly instead of reading through the cache")
	}
	if strings.Contains(handler, "sampleCPU(") {
		t.Error("the handler samples the CPU directly instead of reading through the cache")
	}
	if strings.Contains(handler, "resourcelimit.QuotaRebootRequired()") {
		t.Error("the handler asks xfs_quota directly instead of reading through the cache")
	}
}
