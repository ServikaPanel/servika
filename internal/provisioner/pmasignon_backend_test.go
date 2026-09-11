package provisioner

import (
	"strings"
	"testing"
)

// The signon page dialled 127.0.0.1:8080 as a literal. Moving the backend port
// is a shipped feature, and its rewrite reaches the two panel vhosts only: this
// page was never enumerated, and it goes DIRECT to the backend rather than
// through nginx, so after a port move every "Open phpMyAdmin" click failed with
// the token unredeemable. Nothing linked the failure to the port change, and
// ensurePMASignon rewrote any hand repair from this template on the next
// restart, so the outage was permanent until the port was moved back.
func TestTheSignonPageDialsTheConfiguredBackend(t *testing.T) {
	t.Setenv("SERVIKA_LISTEN", "127.0.0.1:9443")

	page := pmaSignonPHP()
	if !strings.Contains(page, "http://127.0.0.1:9443/api/v1/internal/pma-redeem") {
		t.Error("the signon page does not dial the configured backend port")
	}
	if strings.Contains(page, "127.0.0.1:8080") {
		t.Error("the signon page still carries the hardcoded default port")
	}
	if strings.Contains(page, "{{BACKEND}}") {
		t.Error("the backend placeholder was not substituted")
	}
}

// A wildcard listen is not an address a client can dial, so the loopback is used
// while the port is kept.
func TestAWildcardListenFallsBackToTheLoopback(t *testing.T) {
	t.Setenv("SERVIKA_LISTEN", "0.0.0.0:9443")
	if !strings.Contains(pmaSignonPHP(), "http://127.0.0.1:9443/") {
		t.Error("a wildcard listen did not fall back to the loopback address")
	}
}

// With nothing configured the page keeps the shipped default, so an
// installation that never moved its port is unaffected.
func TestTheDefaultBackendIsUnchanged(t *testing.T) {
	t.Setenv("SERVIKA_LISTEN", "")
	if !strings.Contains(pmaSignonPHP(), "http://127.0.0.1:8080/api/v1/internal/pma-redeem") {
		t.Error("the default backend address changed")
	}
}
