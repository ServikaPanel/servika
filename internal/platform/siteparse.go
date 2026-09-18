package platform

// Reading and validating what IIS management deals in: the lines appcmd prints,
// and the arguments this package will hand back to it.
//
// APPCMD'S `list` OUTPUT IS SAFE TO PARSE, unlike Get-Service or wevtutil: it is
// one line per object in a fixed shape and it does NOT localise. A line that
// does not match the shape is skipped rather than guessed at. Nothing parses the
// output of a `set`, `start` or `stop`; those report their failure as-is.
//
// This file carries no build tag, so the shapes are measured on every build.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The shapes appcmd prints.
var (
	// SITE "shop.example.com" (id:2,bindings:http/*:80:shop.example.com,state:Started)
	siteLinePattern = regexp.MustCompile(`^SITE "(.+)" \(id:(\d+),bindings:(.*),state:(\w+)\)$`)
	// APPPOOL "sv_shop1a2b3c4d" (MgdVersion:v4.0,MgdMode:Integrated,state:Started)
	poolLinePattern = regexp.MustCompile(`^APPPOOL "(.+)" \(MgdVersion:(.*),MgdMode:(.*),state:(\w+)\)$`)
	// APP "shop.example.com/" (applicationPool:sv_shop1a2b3c4d)
	appLinePattern = regexp.MustCompile(`^APP "(.+)" \(applicationPool:(.*)\)$`)
	// VDIR "shop.example.com/" (physicalPath:C:\inetpub\servika\sv_x\httpdocs)
	vdirLinePattern = regexp.MustCompile(`^VDIR "(.+)" \(physicalPath:(.*)\)$`)
)

// poolNamePattern is the only kind of application pool this package will act on:
// one the provider itself created. It keeps operations off the system pools such
// as DefaultAppPool, and it keeps injection characters out of an appcmd
// argument in the same move.
var poolNamePattern = regexp.MustCompile(`^` + userPrefix + `[a-z0-9]{1,20}$`)

// managedRuntimes are the only .NET versions that may be set. An empty string is
// "No Managed Code" and is deliberately in the set. A free-form version string
// reaching appcmd would break the configuration quietly.
var managedRuntimes = map[string]bool{"v4.0": true, "v2.0": true, "": true}

// poolActions maps what the API accepts onto the appcmd verb. The map IS the
// allowlist: turning free text into a verb would be an arbitrary command surface.
var poolActions = map[string]string{"start": "start", "stop": "stop", "recycle": "recycle"}

// Binding is one IIS binding. SSL is not a separate flag from IIS; it is derived
// from the protocol.
type Binding struct {
	Protocol string
	Port     int
	Host     string
	SSL      bool
}

// Pool is the application pool a site's root application runs in.
type Pool struct {
	Name           string
	State          string
	RuntimeVersion string
}

// SiteSummary is one row of the site listing.
type SiteSummary struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Bindings string `json:"bindings"`
}

// SiteDetail is everything the agent reports about one site.
type SiteDetail struct {
	Name         string
	State        string
	PhysicalPath string
	Pool         Pool
	Bindings     []Binding
}

// eachLine walks the lines of a command's output with the carriage return
// stripped, because appcmd ends its lines the Windows way.
func eachLine(out string, fn func(line string) bool) {
	for line := range strings.SplitSeq(out, "\n") {
		if fn(strings.TrimRight(line, "\r")) {
			return
		}
	}
}

// firstMatch returns the submatches of the first line matching a pattern.
func firstMatch(out string, pattern *regexp.Regexp) []string {
	var found []string
	eachLine(out, func(line string) bool {
		if m := pattern.FindStringSubmatch(line); m != nil {
			found = m
			return true
		}
		return false
	})
	return found
}

// parseSiteList reads `appcmd list site` into rows.
func parseSiteList(out string) []SiteSummary {
	sites := make([]SiteSummary, 0, 8)
	eachLine(out, func(line string) bool {
		if m := siteLinePattern.FindStringSubmatch(line); m != nil {
			sites = append(sites, SiteSummary{Name: m[1], State: m[4], Bindings: m[3]})
		}
		return false
	})
	return sites
}

// parseBindings turns appcmd's bindings field into a structured list. Each part
// is "protocol/ip:port:host" and the host may be empty.
func parseBindings(raw string) []Binding {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var list []Binding
	for part := range strings.SplitSeq(raw, ",") {
		if b, ok := parseBinding(strings.TrimSpace(part)); ok {
			list = append(list, b)
		}
	}
	return list
}

// parseBinding reads one "protocol/ip:port:host" part.
func parseBinding(part string) (Binding, bool) {
	slash := strings.IndexByte(part, '/')
	if part == "" || slash < 0 {
		return Binding{}, false
	}
	b := Binding{
		Protocol: part[:slash],
		SSL:      strings.EqualFold(part[:slash], "https"),
	}
	fields := strings.SplitN(part[slash+1:], ":", 3)
	if len(fields) == 3 {
		b.Port, _ = strconv.Atoi(fields[1])
		b.Host = fields[2]
	}
	return b, true
}

// validatePoolName refuses a pool this package will not act on.
func validatePoolName(pool string) (string, error) {
	pool = strings.TrimSpace(pool)
	if !poolNamePattern.MatchString(pool) {
		return "", fmt.Errorf("%q is not a pool this panel manages: %w", pool, ErrInvalidRequest)
	}
	return pool, nil
}

// poolVerb maps an action onto its appcmd verb.
func poolVerb(action string) (string, error) {
	verb, ok := poolActions[action]
	if !ok {
		return "", fmt.Errorf("action %q is not start, stop or recycle: %w", action, ErrInvalidRequest)
	}
	return verb, nil
}

// validateRuntime refuses a .NET version that is not in the set.
func validateRuntime(version string) error {
	if !managedRuntimes[version] {
		return fmt.Errorf("%q is not v4.0, v2.0 or empty for no managed code: %w", version, ErrInvalidRequest)
	}
	return nil
}

// validateBinding checks and normalises a protocol, port and host. Adding and
// removing a binding share this, so the two can never disagree about what a
// binding is.
func validateBinding(protocol, port, host string) (Binding, error) {
	var b Binding
	if protocol != "http" && protocol != "https" {
		return b, fmt.Errorf("protocol %q is not http or https: %w", protocol, ErrInvalidRequest)
	}
	b.Protocol = protocol
	b.SSL = protocol == "https"
	number, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil || number < 1 || number > 65535 {
		return b, fmt.Errorf("port %q is not between 1 and 65535: %w", port, ErrInvalidRequest)
	}
	b.Port = number
	host = strings.ToLower(strings.TrimSpace(host))
	if host != "" && !domainPattern.MatchString(host) {
		return b, fmt.Errorf("host %q is not a valid name: %w", host, ErrInvalidRequest)
	}
	b.Host = host
	return b, nil
}
