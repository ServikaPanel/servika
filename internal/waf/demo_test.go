package waf

import (
	"os"
	"strings"
	"testing"
)

// Save rewrites the domain row and re-renders the vhost, so it cannot be
// executed here without a host. What this pins is that the read-only policy is
// applied before either happens.
func saveBody(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("waf.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	start := strings.Index(body, "func (h *Handlers) Save(w http.ResponseWriter, r *http.Request) {")
	if start < 0 {
		t.Fatal("Save was renamed; these assertions have to follow it")
	}
	end := strings.Index(body[start:], "\nfunc ")
	if end < 0 {
		return body[start:]
	}
	return body[start : start+end]
}

// A demo subscription is read-only everywhere else in the panel, and this
// endpoint accepts mode=off: without the guard a demo tenant could turn a
// security control off on a live vhost. CustomerScope, which is the only
// middleware on the route, enforces ownership and suspension but says nothing
// about is_demo.
func TestSaveRefusesADemoSubscription(t *testing.T) {
	body := saveBody(t)
	if !strings.Contains(body, "is_demo") {
		t.Fatal("Save never reads is_demo, so a demo subscription can change the firewall")
	}
	guard := strings.Index(body, "isDemo == 1")
	update := strings.Index(body, "UPDATE domains SET waf_enabled")
	apply := strings.Index(body, "provisioner.WAFApply(")
	if guard < 0 {
		t.Fatal("Save reads is_demo but does not refuse on it")
	}
	if update < 0 || apply < 0 {
		t.Fatal("the update or the vhost render is missing from Save")
	}
	if guard > update || guard > apply {
		t.Error("the demo guard runs after the row is written or the vhost is rendered")
	}
}
