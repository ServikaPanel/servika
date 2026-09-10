package redis

import (
	"os"
	"strings"
	"testing"
)

// Open and Close create and remove a real Valkey ACL account and rewrite
// WordPress drop-ins on the host, so neither can be executed here. What this
// pins is that the read-only policy is applied before any of that.
func handlerBody(t *testing.T, header string) string {
	t.Helper()
	source, err := os.ReadFile("redis.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	start := strings.Index(body, header)
	if start < 0 {
		t.Fatalf("%q was renamed; these assertions have to follow it", header)
	}
	end := strings.Index(body[start+len(header):], "\nfunc ")
	if end < 0 {
		return body[start:]
	}
	return body[start : start+len(header)+end]
}

// Both write paths provision or revoke host state, so a demo subscription must
// be refused the way every other tenant management endpoint refuses it.
// CustomerScope, the only middleware on these routes, enforces ownership and
// suspension but says nothing about is_demo.
func TestTheCacheWritePathsRefuseADemoSubscription(t *testing.T) {
	for _, header := range []string{
		"func (h *Handlers) Open(w http.ResponseWriter, r *http.Request) {",
		"func (h *Handlers) Close(w http.ResponseWriter, r *http.Request) {",
	} {
		body := handlerBody(t, header)
		if !strings.Contains(body, "if demo {") {
			t.Errorf("%s does not refuse a demo subscription", header)
		}
	}
}

// The status endpoint is a READ. Refusing it would hide the cache's own state
// from the account the demo exists to show it to.
func TestTheCacheStatusIsStillReadableOnADemoSubscription(t *testing.T) {
	body := handlerBody(t, "func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {")
	if strings.Contains(body, "if demo {") {
		t.Error("Status refuses a demo subscription, but reading the cache state is not a mutation")
	}
}

// The flag is read in one place so a new write path inherits it instead of
// having to remember it.
func TestTheDomainLookupReportsTheDemoFlag(t *testing.T) {
	source, err := os.ReadFile("redis.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "SELECT system_user, is_demo FROM domains WHERE id=?") {
		t.Error("the domain lookup does not read is_demo, so no handler can refuse on it")
	}
}
