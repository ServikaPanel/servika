package panelsettings

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The custom panel domain is a SECOND entrance to the same handlers. It proxied
// /api/ as one location, and a longer prefix wins in nginx, so a login through
// that domain was matched there and never reached the port-8443 vhost where the
// servika_login zone is applied. Both login endpoints were fully reachable with
// no nginx-layer throttle.

// rateLimitedLocations returns the exact-match locations of an nginx file that
// carry the login rate limit, keyed by path.
func rateLimitedLocations(config string) map[string]string {
	found := map[string]string{}
	pattern := regexp.MustCompile(`(?s)location = (\S+) \{(.*?)\n    \}`)
	for _, match := range pattern.FindAllStringSubmatch(config, -1) {
		if strings.Contains(match[2], "limit_req zone=servika_login") {
			found[match[1]] = match[2]
		}
	}
	return found
}

// repositoryRoot walks up to the module root, so the test can read the shipped
// vhost the panel installs.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for range 8 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("go.mod is not above this package")
	return ""
}

// The two templates are measured against each other, which is what nothing did
// when the rate limit was added to one of them.
func TestTheCustomDomainRateLimitsEveryLoginTheShippedVhostDoes(t *testing.T) {
	shipped, err := os.ReadFile(filepath.Join(repositoryRoot(t), "assets", "nginx", "_panel.conf"))
	if err != nil {
		t.Fatalf("the shipped panel vhost could not be read: %v", err)
	}
	wanted := rateLimitedLocations(string(shipped))
	if len(wanted) == 0 {
		t.Fatal("the shipped panel vhost carries no rate-limited login location; this test measures nothing")
	}

	rendered := rateLimitedLocations(panelDomainVhost("panel.example.com"))

	for path := range wanted {
		if _, ok := rendered[path]; !ok {
			t.Errorf("%s is rate limited on port 8443 and not on the custom domain", path)
		}
	}
}

// The exact-match login locations must sit in the same server block as the
// /api/ prefix they are protecting, and the domain still reaches the template.
func TestTheRenderedVhostCarriesTheDomainAndTheLoginLocations(t *testing.T) {
	rendered := panelDomainVhost("panel.example.com")

	if strings.Count(rendered, "server_name panel.example.com;") != 2 {
		t.Errorf("the domain does not reach both server blocks:\n%s", rendered)
	}
	login := strings.Index(rendered, "location = /api/v1/auth/login {")
	api := strings.Index(rendered, "location /api/ {")
	if login < 0 || api < 0 {
		t.Fatalf("a location is missing (login=%d api=%d)", login, api)
	}
	// nginx matches an exact location before any prefix whatever the order, so
	// this only asserts that both live in the one server block that serves the
	// domain, which is what makes the zone apply to the login request.
	if strings.Count(rendered, "listen 443 ssl;") != 1 {
		t.Errorf("the render grew a second TLS server block:\n%s", rendered)
	}
}
