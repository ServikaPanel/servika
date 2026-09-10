package composer

import (
	"sync"
	"testing"
)

// One hosting account may hold concurrentRunsPerUser composer processes and no
// more. Without the gate a customer held hundreds of ten-minute resolvers inside
// the panel's own cgroup, which is a CPU and RAM exhaustion vector against every
// other tenant on the host.
func TestOneAccountCannotExceedItsRunSlots(t *testing.T) {
	const user = "c_gate"
	releases := make([]func(), 0, concurrentRunsPerUser)
	for slot := range concurrentRunsPerUser {
		release, ok := acquireRunSlot(user)
		if !ok {
			t.Fatalf("slot %d was refused although the account holds only %d", slot, slot)
		}
		releases = append(releases, release)
	}
	if _, ok := acquireRunSlot(user); ok {
		t.Fatalf("a %dth concurrent run was admitted", concurrentRunsPerUser+1)
	}
	// A finished run hands its slot back.
	releases[0]()
	release, ok := acquireRunSlot(user)
	if !ok {
		t.Fatal("a released slot was not reusable")
	}
	releases[0] = release
	for _, release := range releases {
		release()
	}
}

// The gate is per account, so one busy tenant must not refuse another's run.
func TestTheGateIsPerSystemUser(t *testing.T) {
	const busy, other = "c_busy", "c_other"
	releases := make([]func(), 0, concurrentRunsPerUser)
	for range concurrentRunsPerUser {
		release, ok := acquireRunSlot(busy)
		if !ok {
			t.Fatal("the busy account could not fill its own slots")
		}
		releases = append(releases, release)
	}
	release, ok := acquireRunSlot(other)
	if !ok {
		t.Fatal("a second account was refused because the first one was busy")
	}
	release()
	for _, release := range releases {
		release()
	}
}

// The gate is reached from concurrent requests, so its map and its channel must
// admit exactly the cap under a race.
func TestTheGateAdmitsExactlyTheCapUnderConcurrency(t *testing.T) {
	const user = "c_race"
	const attempts = 64
	var (
		mu       sync.Mutex
		granted  []func()
		waitAll  sync.WaitGroup
		starting = make(chan struct{})
	)
	waitAll.Add(attempts)
	for range attempts {
		go func() {
			defer waitAll.Done()
			<-starting
			if release, ok := acquireRunSlot(user); ok {
				mu.Lock()
				granted = append(granted, release)
				mu.Unlock()
			}
		}()
	}
	close(starting)
	waitAll.Wait()
	if len(granted) != concurrentRunsPerUser {
		t.Fatalf("%d of %d concurrent attempts were admitted, want %d", len(granted), attempts, concurrentRunsPerUser)
	}
	for _, release := range granted {
		release()
	}
}
