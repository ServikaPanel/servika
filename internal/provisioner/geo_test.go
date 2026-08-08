package provisioner

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"servika/internal/geoip"
	"servika/internal/httpx"
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
	if !strings.Contains(shared, `default  "$servika_rl_addr$server_name";`) {
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

// nginxRateLimitKey replays the map ladder the shared file installs, using the
// SAME rules the renderer writes, so the test cannot drift from the config.
//
// nginx evaluates map regexes in the order they appear and takes the first
// match; this reproduces that. Go's engine is RE2 and nginx's is PCRE, but these
// patterns use no backreference and no lookaround, where the two agree.
func nginxRateLimitKey(t *testing.T, addr string) string {
	t.Helper()
	for _, rule := range rateLimitAddrRules {
		expression, err := regexp.Compile("(?i)" + rule.pattern)
		if err != nil {
			t.Fatalf("the shipped pattern %q does not compile: %v", rule.pattern, err)
		}
		if match := expression.FindStringSubmatchIndex(addr); match != nil {
			return string(expression.ExpandString(nil, rule.value, addr, match))
		}
	}
	return addr
}

// THE property the change exists for: two addresses in one IPv6 allocation share
// one nginx counter.
//
// Keyed per address, anyone with a routed /64 sends every request from a new
// source and never reaches the limit, which is what $binary_remote_addr did.
func TestOneIPv6AllocationSharesOneNginxCounter(t *testing.T) {
	first := nginxRateLimitKey(t, "2001:db8:abcd:1234::1")
	second := nginxRateLimitKey(t, "2001:db8:abcd:1234:ffff:ffff:ffff:ffff")
	if first != second {
		t.Errorf("two addresses in the same /64 keyed apart: %q vs %q", first, second)
	}

	// nginx renders the canonical RFC 5952 form, so an address with a zero third
	// or fourth hextet arrives COMPRESSED and carries no four explicit hextets.
	compressed := nginxRateLimitKey(t, "2001:db8::1")
	if compressed != nginxRateLimitKey(t, "2001:db8::9999") {
		t.Errorf("a compressed address is still keyed per host: %q", compressed)
	}

	// The other direction, so none of this is satisfied by a constant.
	if a, b := nginxRateLimitKey(t, "2001:db8:abcd:1234::1"), nginxRateLimitKey(t, "2001:db8:abcd:1235::1"); a == b {
		t.Errorf("two different /64 networks share the key %q", a)
	}
	if a, b := nginxRateLimitKey(t, "2001:db8::1"), nginxRateLimitKey(t, "2001:dead::1"); a == b {
		t.Errorf("two different compressed networks share the key %q", a)
	}
}

// IPv4 keeps its full address: there the allocation IS the address, and widening
// the key would let one abuser lock out everyone sharing their network.
//
// The IPv4-MAPPED form is the trap. Its /64 is ::/64, which every IPv4 client on
// earth would share, so five failed logins from anywhere would lock out the
// whole internet. It is matched before the IPv6 rules for exactly that reason.
func TestNginxDoesNotMergeIPv4ClientsIntoOneCounter(t *testing.T) {
	if got := nginxRateLimitKey(t, "203.0.113.5"); got != "203.0.113.5" {
		t.Errorf("an IPv4 address keyed as %q, want it unchanged", got)
	}
	if a, b := nginxRateLimitKey(t, "203.0.113.5"), nginxRateLimitKey(t, "203.0.114.5"); a == b {
		t.Errorf("two IPv4 clients share the key %q", a)
	}

	mapped := nginxRateLimitKey(t, "::ffff:203.0.113.5")
	if mapped == "::/64" {
		t.Fatal("an IPv4-mapped address was masked as IPv6, merging every IPv4 client into one counter")
	}
	if mapped != nginxRateLimitKey(t, "203.0.113.5") {
		t.Errorf("the mapped form keyed as %q and the plain form as %q; one client would get two counters",
			mapped, nginxRateLimitKey(t, "203.0.113.5"))
	}
	if a, b := nginxRateLimitKey(t, "::ffff:203.0.113.5"), nginxRateLimitKey(t, "::ffff:198.51.100.5"); a == b {
		t.Errorf("two different IPv4-mapped clients share the key %q", a)
	}
}

// The two enforcement layers must count the SAME unit.
//
// nginx limits requests per site and the Go middleware limits logins, but an
// operator reads them as one policy. If they disagreed, an address would be
// limited by one layer and not the other with nothing on screen explaining it.
// nginx matches text because it cannot do address arithmetic; httpx masks
// properly. This is what proves the two arrive at the same answer.
func TestBothEnforcementLayersCountTheSameUnit(t *testing.T) {
	for _, addr := range []string{
		"2001:db8:abcd:1234::1",
		"2001:db8:abcd:1234:ffff:ffff:ffff:ffff",
		"2001:db8::1",
		"2001:db8:0:1::5",
		"fe80::1",
		"::ffff:203.0.113.5",
		"203.0.113.5",
	} {
		if nginx, go_ := nginxRateLimitKey(t, addr), httpx.RateLimitKey(addr); nginx != go_ {
			t.Errorf("%s: nginx counts it as %q but the panel as %q", addr, nginx, go_)
		}
	}
}

// The regression itself: the bare address must no longer be the zone key.
func TestTheZoneKeyIsNoLongerTheBareAddress(t *testing.T) {
	shared := buildSharedConf(nil, geoip.Ranges{}, []int{30})
	if strings.Contains(shared, "$binary_remote_addr") {
		t.Errorf("the zone is still keyed per address, so IPv6 defeats it:\n%s", shared)
	}
	if !strings.Contains(shared, "map $remote_addr $servika_rl_addr {") {
		t.Errorf("the address map is missing, so $servika_rl_addr is undefined and nginx refuses the whole configuration:\n%s", shared)
	}
	// A repetition count must reach nginx quoted; unquoted, its brace opens a
	// block and nginx refuses the configuration with "unexpected {".
	if strings.Contains(shared, `    ~*^(?<ph>`) {
		t.Errorf("a pattern was written unquoted:\n%s", shared)
	}
}
