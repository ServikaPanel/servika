package provisioner

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"servika/internal/config"
	"servika/internal/geoip"
)

// Country rules and request rate limiting, both of which need one shared
// http-context file plus a per-vhost fragment.
//
// The shared file is generated from what every domain and the firewall
// currently ask for, so it holds the UNION of the countries in use rather than
// the whole world: a database with a quarter of a million networks in it would
// otherwise be parsed by nginx on every reload to answer a question nobody
// asked.

// protectionConfPath is the http-context file. The 00- prefix makes nginx load
// it before any vhost that references the variables and zones it declares,
// matching panelSecLimitsPath.
var protectionConfPath = "/etc/nginx/conf.d/00-servika-geo.conf"

func sharedConfPath() string { return protectionConfPath }

// geoIncludePath is the generated list of `<cidr> <CC>;` lines. It lives beside
// the country database rather than in conf.d, because it is data the panel
// regenerates and not a file an operator would ever edit.
func geoIncludePath() string {
	return filepath.Join(config.GeoIPDir(), "nginx-geo.conf")
}

// rateLadder is the set of request rates a domain may choose.
//
// It is a fixed ladder rather than a free number because limit_req_zone lives
// in the http context: one zone per DOMAIN would multiply shared memory by the
// number of domains, and five hundred domains at 10m each is five gigabytes.
// One zone per distinct RATE keeps the ceiling at five zones however many
// domains use them, and the key carries $server_name so their counters still do
// not collide.
var rateLadder = []int{5, 10, 30, 60, 120}

// ValidRate reports whether a request rate may be stored.
func ValidRate(rps int) bool { return rps == 0 || slices.Contains(rateLadder, rps) }

// RateLadder returns the selectable rates.
func RateLadder() []int { return slices.Clone(rateLadder) }

func rateZoneName(rps int) string { return fmt.Sprintf("servika_rl_%d", rps) }

// staticExtensions are the requests a rate limit does not count.
//
// The exemption is a map producing an EMPTY key, not a separate location:
// nginx does not account a request whose limit_req key is empty, and that works
// identically across the php-fpm, apache and static backends and when an
// application owns the site root. A location-based split would have to be
// repeated in each of those shapes and would silently miss one.
const staticExtensions = `jpg|jpeg|png|gif|ico|css|js|woff2?|svg|webp|avif|mp4|webm|pdf|zip|gz`

// buildSharedConf renders the http-context file.
//
// It is a pure function of what the callers ask for so the whole shape can be
// asserted, including the two traps below.
func buildSharedConf(countries []string, ranges geoip.Ranges, rates []int) string {
	var body strings.Builder
	body.WriteString("# Servika country rules and request rate limits (managed)\n\n")

	// The geo block is rendered even with no countries in use. Removing it
	// would leave $servika_geo_country undefined for any vhost that still
	// references it, and nginx rejects the whole configuration for an unknown
	// variable rather than the one file that named it.
	body.WriteString("geo $servika_geo_country {\n    default \"\";\n")
	if len(countries) > 0 && (len(ranges.V4) > 0 || len(ranges.V6) > 0) {
		fmt.Fprintf(&body, "    include %s;\n", geoIncludePath())
	}
	body.WriteString("}\n\n")

	// THE trap. `if` runs in the rewrite phase, before nginx has matched a
	// location, so a `return 403` in server context fires on the ACME challenge
	// path too. A domain allowing only its own country would pass its first
	// certificate check and then fail every renewal, ending as a certificate
	// error nobody connected to the country rule.
	//
	// The sentinel is what both modes can be written against: "_exempt" matches
	// no country, so a deny list never contains it, and the renderer always
	// appends it to an allow list.
	body.WriteString("map $request_uri $servika_geo_country_eff {\n")
	body.WriteString("    ~^/\\.well-known/  \"_exempt\";\n")
	body.WriteString("    default           $servika_geo_country;\n}\n\n")

	body.WriteString("map $request_uri $servika_rl_key {\n")
	fmt.Fprintf(&body, "    ~*\\.(%s)$  \"\";\n", staticExtensions)
	body.WriteString("    ~^/\\.well-known/  \"\";\n")
	body.WriteString("    default  \"$binary_remote_addr$server_name\";\n}\n\n")

	// Deduplicated HERE rather than trusted from the caller. This function is
	// what bounds the zone count, so a caller passing one entry per domain must
	// still produce one zone per distinct rate; nginx rejects a repeated zone
	// name outright, which would take every vhost down at once.
	sorted := slices.Clone(rates)
	sort.Ints(sorted)
	sorted = slices.Compact(sorted)
	for _, rps := range sorted {
		if !ValidRate(rps) || rps == 0 {
			continue
		}
		fmt.Fprintf(&body, "limit_req_zone $servika_rl_key zone=%s:10m rate=%dr/s;\n",
			rateZoneName(rps), rps)
	}
	return body.String()
}

// buildGeoInclude renders the `<cidr> <CC>;` lines nginx's geo block reads.
func buildGeoInclude(ranges geoip.Ranges) string {
	var body strings.Builder
	for _, network := range ranges.V4 {
		fmt.Fprintf(&body, "%s %s;\n", network.CIDR, network.Country)
	}
	for _, network := range ranges.V6 {
		fmt.Fprintf(&body, "%s %s;\n", network.CIDR, network.Country)
	}
	return body.String()
}

// buildGeoBlock renders one vhost's country rule.
//
// An allow list always carries the exemption sentinel, so a request the map
// marked exempt is never refused by an allow rule that simply does not name it.
func buildGeoBlock(mode string, countries []string) string {
	clean := make([]string, 0, len(countries))
	for _, code := range countries {
		if normalized := geoip.NormalizeCountry(code); normalized != "" {
			clean = append(clean, normalized)
		}
	}
	sort.Strings(clean)
	clean = slices.Compact(clean)
	if len(clean) == 0 {
		return ""
	}
	switch mode {
	case "deny":
		return "    # ---- Country rules, managed by Servika ----\n" +
			"    if ($servika_geo_country_eff ~ \"^(" + strings.Join(clean, "|") + ")$\") { return 403; }\n"
	case "allow":
		return "    # ---- Country rules, managed by Servika ----\n" +
			"    if ($servika_geo_country_eff !~ \"^(" + strings.Join(clean, "|") + "|_exempt)$\") { return 403; }\n"
	}
	return ""
}

// buildRateLimit renders one vhost's rate limit.
//
// burst is twice the rate with nodelay, so a page that fires several dynamic
// requests at once is served rather than queued, while a client sustaining more
// than the rate is refused. 429 rather than nginx's default 503: the client is
// being rate limited, not told the site is down.
func buildRateLimit(rps int) string {
	if rps == 0 || !ValidRate(rps) {
		return ""
	}
	return fmt.Sprintf("    # ---- Request rate limit, managed by Servika ----\n"+
		"    limit_req zone=%s burst=%d nodelay;\n"+
		"    limit_req_status 429;\n"+
		"    limit_req_log_level warn;\n", rateZoneName(rps), rps*2)
}

// domainProtection reads one domain's country and rate settings.
func domainProtection(domainName string) (geoBlock, rateLimit string) {
	if packageDB == nil {
		return "", ""
	}
	var domainID int64
	var mode string
	var rps int
	if err := packageDB.QueryRow(
		`SELECT id, COALESCE(geo_mode,'off'), COALESCE(rate_limit_rps,0) FROM domains WHERE domain_name=? LIMIT 1`,
		domainName).Scan(&domainID, &mode, &rps); err != nil {
		return "", ""
	}
	rateLimit = buildRateLimit(rps)
	if mode == "off" {
		return "", rateLimit
	}
	// A country policy without ranges behind it refuses nobody in deny mode and
	// everybody in allow mode, so it is not rendered at all when the database is
	// missing. The screen reports the same state, so this is not silent.
	if !geoip.Available() {
		return "", rateLimit
	}
	rows, err := packageDB.Query(
		`SELECT country_code FROM domain_geo_rules WHERE domain_id=? ORDER BY country_code`, domainID)
	if err != nil {
		return "", rateLimit
	}
	defer func() { _ = rows.Close() }()
	var countries []string
	for rows.Next() {
		var code string
		if rows.Scan(&code) == nil {
			countries = append(countries, code)
		}
	}
	return buildGeoBlock(mode, countries), rateLimit
}

// usedCountriesAndRates collects what the whole server currently asks for.
func usedCountriesAndRates() (countries []string, rates []int) {
	if packageDB == nil {
		return nil, nil
	}
	seenCountry := map[string]bool{}
	// Only a domain whose mode is active contributes: a stored list belonging
	// to a domain that turned the feature off must not keep a country's ranges
	// in a file nginx parses on every reload.
	rows, err := packageDB.Query(
		`SELECT r.country_code FROM domain_geo_rules r
		   JOIN domains d ON d.id = r.domain_id
		  WHERE COALESCE(d.geo_mode,'off') <> 'off'`)
	if err == nil {
		for rows.Next() {
			var code string
			if rows.Scan(&code) == nil {
				if normalized := geoip.NormalizeCountry(code); normalized != "" {
					seenCountry[normalized] = true
				}
			}
		}
		_ = rows.Close()
	}
	// The firewall's own country blocks share the database but not the nginx
	// file; they are collected here only so one download serves both.
	if firewallRows, err := packageDB.Query(
		`SELECT country_code FROM firewall_geo_rules WHERE enabled=1`); err == nil {
		for firewallRows.Next() {
			var code string
			if firewallRows.Scan(&code) == nil {
				if normalized := geoip.NormalizeCountry(code); normalized != "" {
					seenCountry[normalized] = true
				}
			}
		}
		_ = firewallRows.Close()
	}
	for code := range seenCountry {
		countries = append(countries, code)
	}
	sort.Strings(countries)

	seenRate := map[int]bool{}
	if rateRows, err := packageDB.Query(
		`SELECT DISTINCT rate_limit_rps FROM domains WHERE COALESCE(rate_limit_rps,0) > 0`); err == nil {
		for rateRows.Next() {
			var rps int
			if rateRows.Scan(&rps) == nil && ValidRate(rps) && rps > 0 {
				seenRate[rps] = true
			}
		}
		_ = rateRows.Close()
	}
	for rps := range seenRate {
		rates = append(rates, rps)
	}
	sort.Ints(rates)
	return countries, rates
}

// restorer puts a shared file back the way it was.
type restorer struct {
	path     string
	previous []byte
	existed  bool
}

func (r restorer) restore() {
	if !r.existed {
		_ = os.Remove(r.path)
		return
	}
	// #nosec G306 G703 -- root-owned nginx configuration file its master process must read; it carries public address ranges, not secrets.
	_ = os.WriteFile(r.path, r.previous, 0o644)
}

// ensureProtectionConf writes the shared http-context file and the geo include.
//
// It returns restorers because renderAndReload's rollback only puts the VHOST
// back. A shared file left broken keeps nginx running on its loaded
// configuration and then takes the whole server down at the next unrelated
// reload, which is a failure nobody would connect to this change.
func ensureProtectionConf() ([]restorer, error) {
	countries, rates := usedCountriesAndRates()

	var ranges geoip.Ranges
	if len(countries) > 0 && geoip.Available() {
		if found, err := geoip.Lookup(countries); err == nil {
			ranges = found
		}
	}

	var restorers []restorer
	if len(ranges.V4) > 0 || len(ranges.V6) > 0 {
		// 0750 matches the data directory: only root reads it, and nginx parses
		// the include in its master process before dropping privileges.
		if err := os.MkdirAll(config.GeoIPDir(), 0o750); err != nil {
			return restorers, fmt.Errorf("create the country data directory: %w", err)
		}
		saved, err := writeShared(geoIncludePath(), buildGeoInclude(ranges))
		if err != nil {
			return restorers, err
		}
		restorers = append(restorers, saved)
	}

	saved, err := writeShared(sharedConfPath(), buildSharedConf(countries, ranges, rates))
	if err != nil {
		return restorers, err
	}
	return append(restorers, saved), nil
}

// writeShared replaces a shared file, returning what it held before.
func writeShared(path, body string) (restorer, error) {
	// #nosec G304 -- fixed system configuration path built from package constants, never from request input.
	previous, err := os.ReadFile(path)
	saved := restorer{path: path, previous: previous, existed: err == nil}
	if saved.existed && string(previous) == body {
		return saved, nil // unchanged; nothing to write and nothing to roll back
	}
	// #nosec G306 -- root-owned nginx configuration file its master process must read; it carries public address ranges, not secrets.
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return saved, fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return saved, nil
}
