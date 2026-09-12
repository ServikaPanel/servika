package provisioner

import "strings"

// nginx discards every inherited add_header the moment a location declares one
// of its own, so each location that sets a cache header has to repeat the whole
// server-level set. The repeats were written by hand and drifted: the three
// static-asset locations of the panel vhost re-emitted four of the six headers
// and dropped Content-Security-Policy and Permissions-Policy, and the three PHP
// locations dropped Permissions-Policy while carrying their own relaxed CSP.
//
// This repairs an INSTALLED vhost, because the template only reaches a new
// installation.

// panelPermissionsPolicy is the server-level Permissions-Policy of the panel.
const panelPermissionsPolicy = "geolocation=(), microphone=(), camera=(), interest-cohort=()"

// panelRelaxedCSP is what phpMyAdmin and Roundcube are served under: both run
// inline scripts, so they cannot take the SPA's policy.
const panelRelaxedCSP = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
	"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
	"img-src 'self' data: blob:; font-src 'self' data: https://fonts.gstatic.com; " +
	"connect-src 'self'; frame-ancestors 'self'; object-src 'none'; " +
	"base-uri 'self'; form-action 'self'"

// referrerPolicyHeader is the line the repair anchors on. Every header run in
// the panel vhost carries it, and it sits where the missing headers belong.
const referrerPolicyHeader = `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`

// repeatMissingPanelHeaders adds the inherited headers an add_header run does
// not repeat.
//
// A run is the contiguous block of add_header lines a location declares. The
// server-level run already carries the whole set, so it is left as it is.
func repeatMissingPanelHeaders(content string) string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines)+8)
	location := ""
	for i, line := range lines {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "location ") {
			location = trimmed
		}
		out = append(out, line)
		if strings.TrimSpace(line) != referrerPolicyHeader {
			continue
		}
		out = append(out, missingHeadersFor(headerRun(lines, i), indentOf(line), location)...)
	}
	return strings.Join(out, "\n")
}

// missingHeadersFor renders the header lines a run does not already carry.
//
// A run that repeats one inherited header has to repeat them all, so every
// header of the set is checked rather than only the two that had drifted: a run
// missing a third one is the same defect.
func missingHeadersFor(run []string, indent, location string) []string {
	wanted := [][2]string{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "SAMEORIGIN"},
		{"Permissions-Policy", panelPermissionsPolicy},
		{"Content-Security-Policy", policyFor(location)},
		{"Strict-Transport-Security", "max-age=31536000; includeSubDomains"},
	}
	var added []string
	for _, header := range wanted {
		if runCarries(run, header[0]) {
			continue
		}
		added = append(added, indent+`add_header `+header[0]+` "`+header[1]+`" always;`)
	}
	return added
}

// policyFor picks the policy an application can actually run under. A location
// of phpMyAdmin or Roundcube takes the relaxed one its PHP sibling already has,
// so one application is never served under two policies.
func policyFor(location string) string {
	if strings.Contains(location, "/pma/") || strings.Contains(location, "/webmail/") {
		return panelRelaxedCSP
	}
	return panelStrictCSP
}

// headerRun returns the contiguous add_header lines around index, which is the
// set one location emits.
func headerRun(lines []string, index int) []string {
	first, last := index, index
	for first > 0 && isHeaderLine(lines[first-1]) {
		first--
	}
	for last+1 < len(lines) && isHeaderLine(lines[last+1]) {
		last++
	}
	return lines[first : last+1]
}

// isHeaderLine reports whether a line belongs to a header run. A comment between
// two add_header lines is part of the run: the template explains the repeat
// there, and treating the comment as a boundary would split the run in two.
func isHeaderLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "add_header ") || strings.HasPrefix(trimmed, "#")
}

// runCarries reports whether a run already emits a header.
func runCarries(run []string, header string) bool {
	for _, line := range run {
		if strings.HasPrefix(strings.TrimSpace(line), "add_header "+header+" ") {
			return true
		}
	}
	return false
}

// indentOf returns the leading whitespace of a line.
func indentOf(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}
