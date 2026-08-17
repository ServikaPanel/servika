package provisioner

import (
	"os"
	"strings"
	"testing"
)

// A fresh installation already carries the whole rate limit, so the heal must
// leave the shipped template byte-identical. Anything else reloads nginx on the
// first boot of every new host for nothing.
func TestTheShippedTemplateAlreadyCarriesTheLoginRateLimit(t *testing.T) {
	body, err := os.ReadFile("../../assets/nginx/_panel.conf")
	if err != nil {
		t.Fatalf("read the panel vhost: %v", err)
	}
	updated, ok := applyLoginRateLimit(string(body))
	if !ok {
		t.Fatal("the template has no canonical API location")
	}
	if updated != string(body) {
		t.Error("the heal would rewrite the shipped template")
	}
}

// The whole point of dropping the early return: a changed rate has to reach an
// installation that already carries the sentinel. Under the old heal the
// sentinel ended the function and the rate stayed whatever it was.
func TestAChangedRateReachesAnInstallationThatAlreadyHasTheSentinel(t *testing.T) {
	stale := strings.Replace(panelLoginRateLimitHTTPBlock, panelLoginZoneLine,
		"limit_req_zone $binary_remote_addr zone=servika_login:10m rate=999r/m;", 1) +
		"\nserver {\n" + panelLoginLocation(panelLoginPaths[0]) + "\n" +
		panelLoginLocation(panelLoginPaths[1]) + "\n    location /api/ {\n        proxy_pass http://127.0.0.1:8080;\n    }\n}\n"

	updated, ok := applyLoginRateLimit(stale)
	if !ok {
		t.Fatal("the fixture has no canonical API location")
	}
	if strings.Contains(updated, "rate=999r/m") {
		t.Error("the stale rate survived, so a rate change never reaches an installed panel")
	}
	if !strings.Contains(updated, panelLoginZoneLine) {
		t.Error("the current zone line was not applied")
	}
	if got := strings.Count(updated, "limit_req_zone"); got != 1 {
		t.Errorf("the vhost declares %d zones; a second one is a duplicate nginx refuses", got)
	}
}

// An installation made before the rate limit existed gets both locations and
// the zone, each exactly once.
func TestAnInstallationWithoutTheRateLimitGetsItOnce(t *testing.T) {
	const old = `server {
    listen 8443 ssl;

    location /api/ {
        proxy_pass http://127.0.0.1:8080;
    }
}
`
	updated, ok := applyLoginRateLimit(old)
	if !ok {
		t.Fatal("the fixture has no canonical API location")
	}
	for _, path := range panelLoginPaths {
		if got := strings.Count(updated, "location = "+path+" {"); got != 1 {
			t.Errorf("%s appears %d times, want 1", path, got)
		}
	}
	if got := strings.Count(updated, "limit_req_zone"); got != 1 {
		t.Errorf("the vhost declares %d zones, want 1", got)
	}
	if !strings.Contains(updated, panelLoginRateLimitSentinel) {
		t.Error("the sentinel was not written")
	}
	// A second run must change nothing, or the panel writes and reloads on
	// every boot.
	again, _ := applyLoginRateLimit(updated)
	if again != updated {
		t.Error("a second run changed the vhost again")
	}
}

// Only one of the two locations present is the state a half-finished edit
// leaves. The missing one is added and the present one is not duplicated.
func TestOnlyTheMissingLoginLocationIsAdded(t *testing.T) {
	partial := panelLoginRateLimitHTTPBlock + "\nserver {\n" +
		panelLoginLocation(panelLoginPaths[0]) + "\n" +
		"    location /api/ {\n        proxy_pass http://127.0.0.1:8080;\n    }\n}\n"

	updated, ok := applyLoginRateLimit(partial)
	if !ok {
		t.Fatal("the fixture has no canonical API location")
	}
	for _, path := range panelLoginPaths {
		if got := strings.Count(updated, "location = "+path+" {"); got != 1 {
			t.Errorf("%s appears %d times, want 1", path, got)
		}
	}
}
