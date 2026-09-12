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
	stale := strings.Replace(panelLoginRateLimitHTTPBlock(), panelLoginZoneLine,
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

// The panel's login zone counts what every other rate limit in this repository
// counts: the full address for IPv4 and the /64 for IPv6. With
// $binary_remote_addr every address inside an IPv6 client's own network had its
// own counter, so the nginx layer in front of the two login endpoints did not
// apply to an IPv6 client at all.
func TestThePanelLoginZoneCountsTheSameUnitAsEveryOtherRateLimit(t *testing.T) {
	body, err := os.ReadFile("../../assets/nginx/_panel.conf")
	if err != nil {
		t.Fatalf("read the panel vhost: %v", err)
	}
	template := string(body)

	if strings.Contains(template, "limit_req_zone $binary_remote_addr") {
		t.Error("the panel login zone still counts the whole IPv6 address")
	}
	if !strings.Contains(template, panelLoginZoneLine) {
		t.Errorf("the template does not declare %q", panelLoginZoneLine)
	}
	// The template's map and the heal's are the same text, or a host repaired at
	// startup would collapse addresses differently from a fresh one.
	if !strings.Contains(template, panelRateLimitMap()) {
		t.Errorf("the template's collapse map differs from the heal's:\n%s", panelRateLimitMap())
	}
	// And both are the ladder the tenant vhosts already use.
	if panelRateLimitMap() != rateLimitAddrMap(panelRateLimitVar) {
		t.Error("the panel map is not rendered from the shared ladder")
	}
}

// An installation that carries the sentinel never re-enters the add branch, so
// the map has to reach it through its own repair. Without it the updated zone
// line would name a variable nginx does not know and refuse the whole
// configuration.
func TestAnInstalledPanelGetsTheCollapseMapAddedAboveItsZone(t *testing.T) {
	stale := panelLoginRateLimitSentinel + `
limit_req_zone $binary_remote_addr zone=servika_login:10m rate=20r/m;

server {
` + panelLoginLocation(panelLoginPaths[0]) + "\n" +
		panelLoginLocation(panelLoginPaths[1]) + "\n" +
		"    location /api/ {\n        proxy_pass http://127.0.0.1:8080;\n    }\n}\n"

	updated, ok := applyLoginRateLimit(stale)
	if !ok {
		t.Fatal("the fixture has no canonical API location")
	}
	if !strings.Contains(updated, panelRateLimitMap()) {
		t.Errorf("the collapse map was not added:\n%s", updated)
	}
	if strings.Index(updated, panelRateLimitMapOpen) > strings.Index(updated, panelLoginZoneLine) {
		t.Error("the map was written below the zone that reads it")
	}
	if got := strings.Count(updated, panelRateLimitMapOpen); got != 1 {
		t.Errorf("the vhost declares %d maps; a second one is a duplicate nginx refuses", got)
	}
	// A second pass must change nothing, or every boot rewrites and reloads.
	if again, _ := applyLoginRateLimit(updated); again != updated {
		t.Error("a second run changed the vhost again")
	}
}

// Only one of the two locations present is the state a half-finished edit
// leaves. The missing one is added and the present one is not duplicated.
func TestOnlyTheMissingLoginLocationIsAdded(t *testing.T) {
	partial := panelLoginRateLimitHTTPBlock() + "\nserver {\n" +
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
