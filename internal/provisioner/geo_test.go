package provisioner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"servika/internal/geoip"
)

// THE trap this whole design is shaped around. nginx evaluates `if` in the
// rewrite phase, before it has matched a location, so a server-context
// `return 403` fires on the ACME challenge path as well. A domain that allowed
// only its own country would pass its first certificate check and then fail
// every renewal, ending as a certificate error nobody would connect to the
// country rule.
func TestAnAllowRuleDoesNotRefuseTheACMEChallenge(t *testing.T) {
	shared := buildSharedConf([]string{"TR"}, geoip.Ranges{V4: []geoip.Network{{CIDR: "2.16.0.0/19", Country: "TR"}}}, nil)
	if !strings.Contains(shared, `~^/\.well-known/  "_exempt";`) {
		t.Fatalf("the well-known path is not mapped to the exemption sentinel:\n%s", shared)
	}

	allow := buildGeoBlock("allow", []string{"TR"})
	if !strings.Contains(allow, "_exempt") {
		t.Fatalf("an allow rule omits the exemption sentinel, so certificate renewal would be refused:\n%s", allow)
	}
	if !strings.Contains(allow, `!~ "^(TR|_exempt)$"`) {
		t.Errorf("unexpected allow rule shape:\n%s", allow)
	}

	// A deny rule must NOT list the sentinel: it names what is refused, and a
	// value that matches nothing is already allowed through.
	deny := buildGeoBlock("deny", []string{"CN"})
	if strings.Contains(deny, "_exempt") {
		t.Errorf("a deny rule names the exemption sentinel, which would refuse it:\n%s", deny)
	}
	if !strings.Contains(deny, `~ "^(CN)$"`) {
		t.Errorf("unexpected deny rule shape:\n%s", deny)
	}
}

// The rate limit exempts static assets through an EMPTY map key, which nginx
// does not account. A location-based split would have to be repeated across the
// php-fpm, apache and static backends and would miss the app-owns-root shape.
func TestStaticAssetsFallToAnEmptyRateLimitKey(t *testing.T) {
	shared := buildSharedConf(nil, geoip.Ranges{}, []int{30})
	if !strings.Contains(shared, `default  "$binary_remote_addr$server_name";`) {
		t.Fatalf("a dynamic request is not keyed by address and host:\n%s", shared)
	}
	for _, extension := range []string{"jpg", "css", "js", "woff2", "mp4", "pdf"} {
		if !strings.Contains(staticExtensions, extension) {
			t.Errorf("%s is counted against the rate limit", extension)
		}
	}
	// The key carries $server_name, or two domains sharing a zone would share
	// one counter and one busy site would rate-limit its neighbours.
	if !strings.Contains(shared, "$server_name") {
		t.Error("the rate limit key does not separate domains")
	}
}

// One zone per distinct RATE, never per domain: limit_req_zone lives in http
// context, so per-domain zones would multiply shared memory by the number of
// domains.
func TestZoneCountFollowsTheRateLadderNotTheDomainCount(t *testing.T) {
	// Two hundred domains using three distinct rates.
	rates := make([]int, 0, 200)
	for index := range 200 {
		rates = append(rates, []int{5, 30, 120}[index%3])
	}
	shared := buildSharedConf(nil, geoip.Ranges{}, rates)
	if got := strings.Count(shared, "limit_req_zone"); got != 3 {
		t.Fatalf("the shared file declares %d zones for 200 domains, want 3:\n%s", got, shared)
	}
	for _, want := range []string{"zone=servika_rl_5:10m rate=5r/s", "zone=servika_rl_30:10m rate=30r/s", "zone=servika_rl_120:10m rate=120r/s"} {
		if !strings.Contains(shared, want) {
			t.Errorf("missing %q:\n%s", want, shared)
		}
	}
}

func TestOnlyLadderRatesAreRendered(t *testing.T) {
	for _, rps := range RateLadder() {
		if !ValidRate(rps) {
			t.Errorf("%d is on the ladder but was refused", rps)
		}
		if buildRateLimit(rps) == "" {
			t.Errorf("%d rendered nothing", rps)
		}
	}
	for _, rps := range []int{1, 7, 31, 1000, -5} {
		if ValidRate(rps) {
			t.Errorf("%d was accepted but is not on the ladder", rps)
		}
		if buildRateLimit(rps) != "" {
			t.Errorf("%d rendered a directive", rps)
		}
	}
	// Zero is the off switch, valid to store and rendering nothing.
	if !ValidRate(0) {
		t.Error("0 was refused, so a domain could not turn the limit off")
	}
	if buildRateLimit(0) != "" {
		t.Error("0 rendered a directive")
	}
}

// The burst is twice the rate so a page firing several dynamic requests at once
// is served rather than queued, and the status is 429 rather than nginx's
// default 503, which would tell the client the site is down.
func TestTheRateLimitAnswersTooManyRequests(t *testing.T) {
	body := buildRateLimit(30)
	for _, want := range []string{"zone=servika_rl_30", "burst=60", "nodelay", "limit_req_status 429"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q:\n%s", want, body)
		}
	}
}

// The geo block is rendered even with no countries in use. Dropping it would
// leave $servika_geo_country undefined, and nginx refuses the whole
// configuration for an unknown variable rather than the file that named it.
func TestTheGeoBlockSurvivesAnEmptyCountrySet(t *testing.T) {
	shared := buildSharedConf(nil, geoip.Ranges{}, nil)
	if !strings.Contains(shared, "geo $servika_geo_country {") {
		t.Fatalf("the geo block is missing:\n%s", shared)
	}
	if strings.Contains(shared, "include ") {
		t.Errorf("an include was rendered with no ranges to include:\n%s", shared)
	}
	if !strings.Contains(shared, "$servika_geo_country_eff") {
		t.Error("the effective-country map is missing")
	}
}

// An unknown mode or an empty list renders nothing rather than something that
// happens to refuse everybody.
func TestAnEmptyOrUnknownCountryRuleRendersNothing(t *testing.T) {
	if got := buildGeoBlock("deny", nil); got != "" {
		t.Errorf("an empty deny list rendered %q", got)
	}
	if got := buildGeoBlock("allow", nil); got != "" {
		t.Errorf("an empty allow list rendered %q", got)
	}
	if got := buildGeoBlock("off", []string{"CN"}); got != "" {
		t.Errorf("mode off rendered %q", got)
	}
	if got := buildGeoBlock("deny", []string{"", "??", "toolong"}); got != "" {
		t.Errorf("unusable codes rendered %q", got)
	}
}

// The rendered http-context file is loaded by nginx alongside every vhost, so a
// syntax error in it takes the whole server down at the next reload.
func TestTheSharedConfIsValidNginxSyntax(t *testing.T) {
	prefix := t.TempDir()
	include := filepath.Join(prefix, "nginx-geo.conf")
	if err := os.WriteFile(include, []byte("1.0.1.0/24 CN;\n2001:250::/32 CN;\n"), 0o600); err != nil {
		t.Fatalf("write the include: %v", err)
	}
	t.Setenv("SERVIKA_GEOIP_DIR", prefix)

	shared := buildSharedConf(
		[]string{"CN"},
		geoip.Ranges{
			V4: []geoip.Network{{CIDR: "1.0.1.0/24", Country: "CN"}},
			V6: []geoip.Network{{CIDR: "2001:250::/32", Country: "CN"}},
		},
		[]int{5, 30},
	)
	body := "events {}\nhttp {\n" + shared + `
server {
    listen 8480;
    server_name example.com;
` + buildGeoBlock("allow", []string{"TR"}) + buildRateLimit(30) + `    location / { return 200; }
}
}
`
	checkNginxSyntax(t, prefix, body, "the shared protection configuration is not valid nginx syntax")
}

// The generated include is what nginx parses, so its line shape is a contract.
func TestTheGeoIncludeIsOneNetworkPerLine(t *testing.T) {
	body := buildGeoInclude(geoip.Ranges{
		V4: []geoip.Network{{CIDR: "1.0.1.0/24", Country: "CN"}},
		V6: []geoip.Network{{CIDR: "2001:250::/32", Country: "CN"}},
	})
	want := "1.0.1.0/24 CN;\n2001:250::/32 CN;\n"
	if body != want {
		t.Errorf("include =\n%q\nwant\n%q", body, want)
	}
}

// A failed nginx test must put every shared file back. nginx keeps serving its
// loaded configuration after a failed reload, so a broken shared file would
// survive to take the server down on the next unrelated change.
func TestARestorerPutsASharedFileBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.conf")
	if err := os.WriteFile(path, []byte("original\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	saved, err := writeShared(path, "replacement\n")
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if body, _ := os.ReadFile(path); string(body) != "replacement\n" {
		t.Fatalf("the file was not replaced: %q", body)
	}
	saved.restore()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(body) != "original\n" {
		t.Errorf("after restore the file holds %q, want %q", body, "original\n")
	}
}

// A file that did not exist before is removed rather than left holding the
// replacement, or the next reload would load a file the rollback thought it had
// undone.
func TestARestorerRemovesAFileThatDidNotExist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.conf")
	saved, err := writeShared(path, "content\n")
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	saved.restore()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("a file created by this render survived the rollback (err=%v)", err)
	}
}

// The fragments must reach BOTH vhost shapes. The plain-HTTP vhost is what a
// domain without a certificate serves, and a country rule that only applied on
// TLS would leave exactly the sites least likely to have one unprotected.
func TestBothVhostShapesCarryTheProtectionFragments(t *testing.T) {
	base := VhostOpts{
		DomainName: "example.com",
		WebRoot:    "/home/c_x/public_html",
		PHPSocket:  "/run/php-fpm/c_x.sock",
		GeoBlock:   buildGeoBlock("deny", []string{"CN"}),
		RateLimit:  buildRateLimit(30),
	}
	secure := base
	secure.CertPath = "/etc/pki/servika/example.com/example.com.crt"
	secure.KeyPath = "/etc/pki/servika/example.com/example.com.key"

	for name, opts := range map[string]VhostOpts{"plain": base, "tls": secure} {
		var rendered strings.Builder
		if err := vhostTmpl.Execute(&rendered, opts); err != nil {
			t.Fatalf("%s render: %v", name, err)
		}
		body := rendered.String()
		if !strings.Contains(body, "$servika_geo_country_eff") {
			t.Errorf("the %s vhost carries no country rule:\n%s", name, body)
		}
		if !strings.Contains(body, "limit_req zone=servika_rl_30") {
			t.Errorf("the %s vhost carries no rate limit:\n%s", name, body)
		}
	}
}
