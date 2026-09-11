package sitecopy

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Creating a staging copy runs a root rsync over the whole document root, up to
// 3 GB, for up to five minutes, outside the tenant's cgroup. Nothing serialised
// it, so a customer could fire any number at once and saturate the host's disk
// for every site and for the panel database.
func TestOnlyOneCopyRunsPerDomain(t *testing.T) {
	release, claimed := lockDomain(7)
	if !claimed {
		t.Fatal("the first copy could not claim the domain")
	}
	if _, second := lockDomain(7); second {
		t.Error("a second copy started for the same domain")
	}
	if other, ok := lockDomain(8); !ok {
		t.Error("a different domain was refused a copy")
	} else {
		other()
	}
	release()
	again, ok := lockDomain(7)
	if !ok {
		t.Fatal("the domain could not be copied again after the first finished")
	}
	again()
}

// The claim has to be atomic, or two requests arriving together both find it
// free and both start an rsync.
func TestOnlyOneOfManyConcurrentClaimsWins(t *testing.T) {
	const racers = 32
	var won int32
	var wg sync.WaitGroup
	var releases sync.Map
	wg.Add(racers)
	for i := range racers {
		go func() {
			defer wg.Done()
			if release, ok := lockDomain(99); ok {
				atomic.AddInt32(&won, 1)
				releases.Store(i, release)
			}
		}()
	}
	wg.Wait()
	releases.Range(func(_, value any) bool {
		value.(func())()
		return true
	})
	if won != 1 {
		t.Errorf("%d copies claimed one domain, want 1", won)
	}
}

// And the handler actually takes it, before doing any work.
func TestTheCreateHandlerClaimsTheDomainFirst(t *testing.T) {
	body, err := os.ReadFile("sitecopy.go") // #nosec G304 -- a file of this package.
	if err != nil {
		t.Fatalf("read sitecopy.go: %v", err)
	}
	create, _, found := strings.Cut(string(body)[strings.Index(string(body), "func (h *Handlers) Create("):], "\n}\n")
	if !found {
		t.Fatal("Create has no closing brace")
	}
	claim := strings.Index(create, "lockDomain(domainID)")
	work := strings.Index(create, "dirSizeBytes(")
	if claim < 0 {
		t.Fatal("Create does not claim the domain")
	}
	if work >= 0 && claim > work {
		t.Error("Create walks the document root before claiming the domain")
	}
	if !strings.Contains(create, "http.StatusConflict") {
		t.Error("a second concurrent copy is not refused with 409")
	}
	if !strings.Contains(create, "defer release()") {
		t.Error("the claim is never released, so one copy blocks the domain for ever")
	}
}

// The per-domain lock bounds concurrency; the route limiter bounds the RATE at
// which a customer can start copies across their domains. The expensive
// file-manager routes were throttled when they were recognised as this class of
// work and the staging copy, which does the same thing through another package,
// was not included.
func TestTheCopyRouteIsThrottled(t *testing.T) {
	body, err := os.ReadFile("../../cmd/server/main.go")
	if err != nil {
		t.Fatalf("read the router: %v", err)
	}
	const route = `Post("/domains/{id}/copy", copyH.Create)`
	line := routeLine(t, string(body), route)
	if !strings.Contains(line, "fileHeavy") {
		t.Errorf("the staging-copy route carries no rate limit: %s", strings.TrimSpace(line))
	}
}

// routeLine returns the whole source line that mounts a route.
func routeLine(t *testing.T, source, route string) string {
	t.Helper()
	at := strings.Index(source, route)
	if at < 0 {
		t.Fatalf("%q is not mounted; this test is out of date", route)
	}
	start := strings.LastIndex(source[:at], "\n") + 1
	return source[start : at+len(route)]
}
