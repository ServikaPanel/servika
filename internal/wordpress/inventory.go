package wordpress

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"servika/internal/logx"
)

// The server-wide WordPress inventory costs two wp-cli invocations per
// installation, each one a runuser plus a full PHP process that bootstraps
// WordPress, and the update check reaches the wordpress.org API. Run per request
// that was linear in the number of sites on the server against a fixed request
// budget: a host with a few hundred WordPress installations spawned hundreds of
// PHP processes as tenant users and still timed out. The dashboard fetches this
// on mount, so every page load started another full fan-out.
//
// The pass now runs at most once per TTL for the whole server and every request
// is served from its result, narrowed to the caller's own scope. This is the
// shape internal/diskusage already uses: one cache, one in-flight call, and the
// measurement on its OWN context so a client that gives up neither kills the run
// others are waiting on nor leaves the cache unfilled.

const (
	// inventoryTTL is how long a completed pass is served for.
	inventoryTTL = 15 * time.Minute
	// inventoryBudget bounds one pass. It is far above a request's budget on
	// purpose: the pass is not on the request path.
	inventoryBudget = 30 * time.Minute
)

// inventoryCall is one in-flight pass. Callers arriving while it runs wait on
// done rather than starting a second fan-out over the same server.
type inventoryCall struct {
	done     chan struct{}
	installs []AllInstallation
	err      error
}

var (
	inventoryMu      sync.Mutex
	inventoryCached  []AllInstallation
	inventoryAt      time.Time
	inventoryRunning *inventoryCall

	// Test seams. inventoryNow lets a test age the cache without sleeping, and
	// collectInventoryFn lets it count how many real passes a set of calls made.
	inventoryNow       = time.Now
	collectInventoryFn = collectInventory
)

// Inventory returns every WordPress installation on the server.
//
// ctx bounds only how long THIS caller waits. The pass itself runs under
// inventoryBudget, because it is shared: a dashboard tab closing mid-request
// must not abandon the work every other reader is waiting for.
func Inventory(ctx context.Context, db *sql.DB) ([]AllInstallation, error) {
	inventoryMu.Lock()
	if inventoryCached != nil && inventoryNow().Sub(inventoryAt) < inventoryTTL {
		installs := inventoryCached
		inventoryMu.Unlock()
		return installs, nil
	}
	if call := inventoryRunning; call != nil {
		inventoryMu.Unlock()
		return call.wait(ctx)
	}
	call := &inventoryCall{done: make(chan struct{})}
	inventoryRunning = call
	inventoryMu.Unlock()

	// #nosec G118 -- deliberate: the pass is SHARED, so it must outlive the caller that started it. Inheriting ctx would let one dashboard tab closing abandon the work every other reader is waiting for and leave the cache unfilled. internal/diskusage detaches the same way for the same reason.
	go func() {
		passCtx, cancel := context.WithTimeout(context.Background(), inventoryBudget)
		defer cancel()
		call.installs, call.err = collectInventoryFn(passCtx, db)

		inventoryMu.Lock()
		// A failed pass keeps whatever was already collected. Replacing it with a
		// short list would report sites the pass could not read as absent, and
		// "no WordPress here" is the one answer this must not invent.
		if call.err == nil {
			inventoryCached = call.installs
			inventoryAt = inventoryNow()
		}
		inventoryRunning = nil
		inventoryMu.Unlock()
		close(call.done)
	}()
	return call.wait(ctx)
}

// wait blocks until the shared pass finishes or this caller's context ends.
func (c *inventoryCall) wait(ctx context.Context) ([]AllInstallation, error) {
	select {
	case <-c.done:
		return c.installs, c.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// StartInventoryRefresher fills the inventory at startup and keeps it warm, so
// the first operator to open the dashboard is served a cached answer rather than
// paying for the whole fan-out inside their request.
func StartInventoryRefresher(ctx context.Context, db *sql.DB) {
	go func() {
		for {
			if _, err := Inventory(ctx, db); err != nil && ctx.Err() == nil {
				logx.Errorf("wordpress inventory: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(inventoryTTL):
			}
		}
	}()
}

// collectInventory discovers and inspects every WordPress installation on the
// server. It is unscoped on purpose: one shared pass serves every reader, and
// the handler narrows its result.
func collectInventory(ctx context.Context, db *sql.DB) ([]AllInstallation, error) {
	candidates, err := inventoryCandidates(ctx, db)
	if err != nil {
		return nil, err
	}
	installs := make([]AllInstallation, len(candidates))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, candidate wpCandidate) {
			defer wg.Done()
			defer func() { <-sem }()
			installs[i] = inspectInstallation(ctx, candidate)
		}(i, candidates[i])
	}
	wg.Wait()
	return installs, nil
}

// inventoryCandidates lists every discovered installation on the server.
//
// A read that broke half way is an ERROR, never a short list: the caller keeps
// the previous inventory instead, because a missing installation reads as a site
// that has no WordPress on it.
func inventoryCandidates(ctx context.Context, db *sql.DB) ([]wpCandidate, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT d.id, d.system_user, d.domain_name, COALESCE(d.cert_path,'') FROM domains d ORDER BY d.domain_name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var candidates []wpCandidate
	for rows.Next() {
		var id int64
		var systemUser, domainName, cert string
		if err := rows.Scan(&id, &systemUser, &domainName, &cert); err != nil {
			return nil, err
		}
		root := "/home/" + systemUser + "/public_html"
		for _, install := range Discover(systemUser) {
			candidates = append(candidates, wpCandidate{id, systemUser, domainName, cert != "", install.Dir, root})
		}
	}
	return candidates, rows.Err()
}
