package provisioner

import (
	"os"
	"strings"
	"testing"
)

// nginx keeps NONE of the inherited add_header directives in a location that
// declares one of its own, so the panel vhost repeats the set by hand in every
// such location. Two of the six were left out of the three static-asset
// locations when the set grew, and Permissions-Policy out of the three PHP ones,
// so a response from /assets/, /pma/ or /webmail/ carried a weaker policy than
// the same-origin page that loaded it.

// headerRuns returns every contiguous add_header run of an nginx file, keyed by
// the location line above it. The server-level run is keyed by "".
func headerRuns(config string) map[string][]string {
	runs := map[string][]string{}
	location := ""
	var current []string
	flush := func() {
		if len(current) > 0 {
			runs[location] = append(runs[location], current...)
			current = nil
		}
	}
	for line := range strings.SplitSeq(config, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "location "):
			flush()
			location = trimmed
		case strings.HasPrefix(trimmed, "add_header "):
			current = append(current, trimmed)
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
			// A blank line or a comment does not end the run.
		default:
			flush()
		}
	}
	flush()
	return runs
}

// The six headers every response of the panel carries. The CSP is checked by
// name rather than by value, because phpMyAdmin and Roundcube run inline
// scripts and are deliberately served under the relaxed policy.
var panelHeaderNames = []string{
	"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
	"Permissions-Policy", "Content-Security-Policy", "Strict-Transport-Security",
}

func TestEveryPanelLocationThatDeclaresAHeaderRepeatsTheWholeSet(t *testing.T) {
	body, err := os.ReadFile("../../assets/nginx/_panel.conf")
	if err != nil {
		t.Fatalf("read the panel vhost: %v", err)
	}
	runs := headerRuns(string(body))
	if len(runs) < 4 {
		t.Fatalf("only %d header runs were found; this test measures nothing", len(runs))
	}
	for location, run := range runs {
		if !runCarries(run, "X-Content-Type-Options") {
			continue // a cache-only run, which inherits nothing to repeat
		}
		for _, header := range panelHeaderNames {
			if !runCarries(run, header) {
				t.Errorf("%q emits add_header and drops %s, so its responses lose it",
					locationName(location), header)
			}
		}
	}
}

// locationName renders the server level readably.
func locationName(location string) string {
	if location == "" {
		return "the server block"
	}
	return location
}

// The installed vhost is repaired too: the template only reaches a new host.
func TestTheHealAddsTheMissingHeadersToAnInstalledVhost(t *testing.T) {
	installed := `server {
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "` + panelPermissionsPolicy + `" always;
    add_header Content-Security-Policy "` + panelStrictCSP + `" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location /assets/ {
        add_header Cache-Control "public, immutable";
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    }

    location ~ ^/pma/(.+\.(css|js))$ {
        add_header Cache-Control "public, immutable";
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    }
}
`

	repaired := repeatMissingPanelHeaders(installed)

	runs := headerRuns(repaired)
	for location, run := range runs {
		for _, header := range panelHeaderNames {
			if !runCarries(run, header) {
				t.Errorf("%q still drops %s after the repair", locationName(location), header)
			}
		}
	}
	// Each application keeps ONE policy: the panel's own assets take the strict
	// one, phpMyAdmin's take the relaxed one its PHP location already has.
	assets := strings.Index(repaired, "location /assets/ {")
	pma := strings.Index(repaired, "location ~ ^/pma/")
	if !strings.Contains(repaired[assets:pma], panelStrictCSP) {
		t.Errorf("the panel's own assets are not served under the strict policy:\n%s", repaired[assets:pma])
	}
	if !strings.Contains(repaired[pma:], panelRelaxedCSP) {
		t.Errorf("phpMyAdmin's assets are not served under its own policy:\n%s", repaired[pma:])
	}
}

// A second boot must change nothing, or every restart would rewrite the vhost
// and reload nginx.
func TestTheHeaderRepairIsIdempotent(t *testing.T) {
	body, err := os.ReadFile("../../assets/nginx/_panel.conf")
	if err != nil {
		t.Fatalf("read the panel vhost: %v", err)
	}
	if repaired := repeatMissingPanelHeaders(string(body)); repaired != string(body) {
		t.Error("the repair rewrites a vhost that already carries every header")
	}
}
