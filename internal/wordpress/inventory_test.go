package wordpress

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// resetInventory puts the package cache back to empty and restores the seams.
func resetInventory(t *testing.T) {
	t.Helper()
	restore := func() {
		inventoryMu.Lock()
		inventoryCached, inventoryAt, inventoryRunning = nil, time.Time{}, nil
		inventoryMu.Unlock()
		inventoryNow = time.Now
		collectInventoryFn = collectInventory
	}
	restore()
	t.Cleanup(restore)
}

// The pass costs two PHP processes and one wordpress.org call per installation,
// and the dashboard fetches this on mount. A second reader inside the TTL must be
// served the collected result rather than starting the fan-out again.
func TestASecondReaderInsideTheTTLStartsNoSecondPass(t *testing.T) {
	resetInventory(t)
	var passes atomic.Int32
	collectInventoryFn = func(context.Context, *sql.DB) ([]AllInstallation, error) {
		passes.Add(1)
		return []AllInstallation{{DomainID: 1}}, nil
	}

	for range 3 {
		if _, err := Inventory(context.Background(), nil); err != nil {
			t.Fatalf("inventory: %v", err)
		}
	}
	if got := passes.Load(); got != 1 {
		t.Fatalf("%d passes ran, want 1", got)
	}
}

// Readers arriving while a pass runs wait for it. Without that, every dashboard
// reload starts another full fan-out while the first is still spawning PHP.
func TestConcurrentReadersShareOnePass(t *testing.T) {
	resetInventory(t)
	var passes atomic.Int32
	release := make(chan struct{})
	collectInventoryFn = func(context.Context, *sql.DB) ([]AllInstallation, error) {
		passes.Add(1)
		<-release
		return []AllInstallation{{DomainID: 1}}, nil
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_, _ = Inventory(context.Background(), nil)
		})
	}
	// Let every caller reach the guard before the pass is allowed to finish.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := passes.Load(); got != 1 {
		t.Fatalf("%d passes ran, want 1", got)
	}
}

// A caller that gives up must not take the shared pass down with it, and must
// not leave the cache unfilled for everybody else.
func TestACallerGivingUpDoesNotAbandonThePass(t *testing.T) {
	resetInventory(t)
	finished := make(chan struct{})
	release := make(chan struct{})
	collectInventoryFn = func(passCtx context.Context, _ *sql.DB) ([]AllInstallation, error) {
		<-release
		if passCtx.Err() != nil {
			return nil, passCtx.Err()
		}
		close(finished)
		return []AllInstallation{{DomainID: 1}}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Inventory(ctx, nil)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("the abandoning caller got %v, want context.Canceled", err)
	}

	close(release)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("the pass was cancelled with its first caller")
	}
}

// A failed pass keeps whatever was already collected. Replacing it with a short
// list would report a site the pass could not read as having no WordPress, which
// is the one answer this must not invent.
func TestAFailedPassKeepsThePreviousInventory(t *testing.T) {
	resetInventory(t)
	collectInventoryFn = func(context.Context, *sql.DB) ([]AllInstallation, error) {
		return []AllInstallation{{DomainID: 1}, {DomainID: 2}}, nil
	}
	if _, err := Inventory(context.Background(), nil); err != nil {
		t.Fatalf("first pass: %v", err)
	}

	// Age the cache past its TTL so the next call runs a pass, and make it fail.
	inventoryNow = func() time.Time { return time.Now().Add(2 * inventoryTTL) }
	collectInventoryFn = func(context.Context, *sql.DB) ([]AllInstallation, error) {
		return nil, errors.New("the pass could not read the domains")
	}
	if _, err := Inventory(context.Background(), nil); err == nil {
		t.Fatal("the failed pass was reported as success")
	}

	inventoryMu.Lock()
	kept := len(inventoryCached)
	inventoryMu.Unlock()
	if kept != 2 {
		t.Fatalf("the cache holds %d installations after a failed pass, want the previous 2", kept)
	}
}
